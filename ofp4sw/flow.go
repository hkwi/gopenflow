package ofp4sw

import (
	"encoding/binary"
	"errors"
	"github.com/hkwi/gopenflow"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/hkwi/gopenflow/oxm"
	"log"
	"sort"
	"sync"
	"time"
)

func (pipe Pipeline) addFlowEntry(req ofp4.FlowMod) error {
	tableId := req.TableId()
	if tableId > ofp4.OFPTT_MAX {
		return ofp4.MakeErrorMsg(
			ofp4.OFPET_FLOW_MOD_FAILED,
			ofp4.OFPFMFC_BAD_TABLE_ID,
		)
	}
	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	var table *flowTable
	if trial, ok := pipe.flows[tableId]; ok {
		table = trial
	} else {
		table = &flowTable{
			lock:    &sync.RWMutex{},
			feature: makeFlowTableFeature(),
		}
		pipe.flows[tableId] = table
	}
	return table.addFlowEntry(req, pipe)
}

func (self Pipeline) validate(now time.Time) {
	self.lock.Lock()
	defer self.lock.Unlock()

	for _, table := range self.flows {
		table := table
		go func() {
			table.lock.Lock()
			defer table.lock.Unlock()

			for _, prio := range table.priorities {
				prio := prio
				go func() {
					prio.lock.Lock()
					defer prio.lock.Unlock()

					do_rebuild := false
					var validFlows []*flowEntry
					for _, flows := range prio.flows {
						for _, flow := range flows {
							reason := flow.valid(now)
							if reason == -1 {
								validFlows = append(validFlows, flow)
							} else {
								do_rebuild = true
								if flow.flags&ofp4.OFPFF_SEND_FLOW_REM != 0 {
									//
								}
							}
						}
					}
					if do_rebuild {
						prio.rebuildIndex(validFlows)
					}
				}()
			}
		}()
	}
}

type flowTable struct {
	lock        *sync.RWMutex   // for counters and collections
	priorities  []*flowPriority // sorted list by priority
	activeCount uint32          // number of entries
	lookupCount uint64
	matchCount  uint64
	feature     flowTableFeature
}

func (self *flowTable) addFlowEntry(req ofp4.FlowMod, pipe Pipeline) error {
	flow, e1 := newFlowEntry(req)
	if e1 != nil {
		return e1
	}
	if err := self.feature.accepts(flow, req.Priority()); err != nil {
		return err
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	var priority *flowPriority
	i := sort.Search(len(self.priorities), func(k int) bool {
		return self.priorities[k].priority <= req.Priority() // descending order
	})
	if i == len(self.priorities) || self.priorities[i].priority != req.Priority() {
		priority = &flowPriority{
			lock:     &sync.RWMutex{},
			priority: req.Priority(),
			flows:    make(map[uint32][]*flowEntry),
		}
		self.priorities = append(self.priorities, nil)
		copy(self.priorities[i+1:], self.priorities[i:])
		self.priorities[i] = priority
	} else {
		priority = self.priorities[i]
	}

	priority.lock.Lock()
	defer priority.lock.Unlock()

	key := priority.hash.Key(matchHash(flow.fields))

	flows := []*flowEntry{flow} // prepare for rebuild
	for k, fs := range priority.flows {
		if k == key {
			for _, f := range fs {
				if conflict, err := flow.fields.Conflict(f.fields); err != nil {
					return err
				} else if req.Flags()&ofp4.OFPFF_CHECK_OVERLAP != 0 && !conflict {
					return ofp4.MakeErrorMsg(ofp4.OFPET_FLOW_MOD_FAILED, ofp4.OFPFMFC_OVERLAP)
				}

				if isEqual, err := flow.fields.Equal(f.fields); err != nil {
					return err
				} else if isEqual {
					// old entry will be cleared
					if req.Flags()&ofp4.OFPFF_RESET_COUNTS == 0 {
						// counters should be copied
						flow.packetCount = f.packetCount
						flow.byteCount = f.byteCount
					}
				} else {
					flows = append(flows, f)
				}
			}
		} else {
			flows = append(flows, fs...)
		}
	}

	if portNo, act := hookDot11Action(req.Match().OxmFields()); portNo != 0 && len(act) != 0 {
		if port := pipe.getPort(portNo); port != nil {
			if err := port.Vendor(gopenflow.MgmtFrameAdd(act)).(error); err != nil {
				return err
			}
		}
	}
	priority.rebuildIndex(flows)
	self.activeCount = uint32(len(flows))
	return nil
}

type flowPriority struct {
	lock     *sync.RWMutex // for collections
	priority uint16
	hash     matchHash               // mask common to all flows in this priority
	flows    map[uint32][]*flowEntry // entries in the same priority
}

/* invoke this method inside a mutex guard. */
func (self *flowPriority) rebuildIndex(flows []*flowEntry) {
	hash := matchHash(make(map[OxmKey]OxmPayload))
	for _, flow := range flows {
		hash.Merge(matchHash(flow.fields))
	}

	hashed := make(map[uint32][]*flowEntry)
	for _, flow := range flows {
		key := hash.Key(matchHash(flow.fields))
		if ent, ok := hashed[key]; ok {
			hashed[key] = append(ent, flow)
		} else {
			hashed[key] = []*flowEntry{flow}
		}
	}
	for key, flows := range hashed {
		sort.Sort(flowEntryList(flows))
		hashed[key] = flows
	}
	self.hash = hash
	self.flows = hashed
}

type flowEntry struct {
	lock        *sync.RWMutex // for counters
	fields      match
	cookie      uint64
	packetCount uint64
	byteCount   uint64
	touched     time.Time
	created     time.Time

	flags       uint16 // OFPFF_
	idleTimeout uint16
	hardTimeout uint16

	instMeter    uint32
	instApply    actionList
	instClear    bool
	instWrite    actionSet
	instMetadata *metadataInstruction
	instGoto     uint8
	instExp      map[int][]instExperimenter
}

func newFlowEntry(req ofp4.FlowMod) (*flowEntry, error) {
	reqMatch := match{}
	if err := reqMatch.UnmarshalBinary(req.Match().OxmFields()); err != nil {
		return nil, err
	}
	entry := &flowEntry{
		lock:        &sync.RWMutex{},
		fields:      reqMatch,
		cookie:      req.Cookie(),
		created:     time.Now(),
		idleTimeout: req.IdleTimeout(),
		hardTimeout: req.HardTimeout(),
		instWrite:   makeActionSet(),
		instExp:     make(map[int][]instExperimenter),
	}
	if err := entry.importInstructions(req.Instructions()); err != nil {
		return nil, err
	}
	return entry, nil
}

func (self flowEntry) valid(now time.Time) int {
	if self.idleTimeout != 0 && now.Sub(self.touched) > time.Duration(self.idleTimeout)*time.Second {
		return ofp4.OFPRR_IDLE_TIMEOUT
	}
	if self.hardTimeout != 0 && now.Sub(self.created) > time.Duration(self.hardTimeout)*time.Second {
		return ofp4.OFPRR_HARD_TIMEOUT
	}
	return -1
}

func (entry *flowEntry) importInstructions(instructions ofp4.Instruction) error {
	for _, inst := range instructions.Iter() {
		switch inst.Type() {
		default:
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_INSTRUCTION,
				ofp4.OFPBIC_UNKNOWN_INST,
			)
		case ofp4.OFPIT_GOTO_TABLE:
			entry.instGoto = ofp4.InstructionGotoTable(inst).TableId()
		case ofp4.OFPIT_WRITE_METADATA:
			i := ofp4.InstructionWriteMetadata(inst)
			if i.Metadata()&^i.MetadataMask() != 0 {
				return errors.New("invalid value/mask pair")
			}
			entry.instMetadata = &metadataInstruction{
				i.Metadata(),
				i.MetadataMask(),
			}
		case ofp4.OFPIT_WRITE_ACTIONS, ofp4.OFPIT_APPLY_ACTIONS, ofp4.OFPIT_CLEAR_ACTIONS:
			i := ofp4.InstructionActions(inst)
			switch inst.Type() {
			case ofp4.OFPIT_WRITE_ACTIONS:
				var aset actionSet
				if err := aset.UnmarshalBinary(i.Actions()); err != nil {
					return err
				}
				entry.instWrite = aset
			case ofp4.OFPIT_APPLY_ACTIONS:
				var alist actionList
				if err := alist.UnmarshalBinary(i.Actions()); err != nil {
					return err
				}
				entry.instApply = alist
			case ofp4.OFPIT_CLEAR_ACTIONS:
				entry.instClear = true
			}
		case ofp4.OFPIT_METER:
			entry.instMeter = ofp4.InstructionMeter(inst).MeterId()
		case ofp4.OFPIT_EXPERIMENTER:
			experimenter := ofp4.InstructionExperimenter(inst).Experimenter()
			data := inst[8:]
			if handler, ok := instructionHandlers[experimenter]; ok {
				pos := handler.Order(data)
				entry.instExp[pos] = append(entry.instExp[pos], instExperimenter{
					Experimenter: experimenter,
					Data:         data,
					Handler:      handler,
				})
			} else {
				return ofp4.MakeErrorMsg(ofp4.OFPET_BAD_INSTRUCTION, ofp4.OFPBIC_UNSUP_INST)
			}
		}
	}
	return nil
}

func (entry flowEntry) exportInstructions() ofp4.Instruction {
	var insts []byte

	if entry.instMeter != 0 {
		insts = append(insts, ofp4.MakeInstructionMeter(entry.instMeter)...)
	}
	if len([]action(entry.instApply)) > 0 {
		if actions, err := entry.instApply.MarshalBinary(); err != nil {
			panic(err)
		} else {
			insts = append(insts, ofp4.MakeInstructionActions(ofp4.OFPIT_APPLY_ACTIONS, actions)...)
		}
	}
	if entry.instClear {
		insts = append(insts, ofp4.MakeInstructionActions(ofp4.OFPIT_CLEAR_ACTIONS, nil)...)
	}
	if entry.instWrite.Len() > 0 {
		if actions, err := entry.instWrite.MarshalBinary(); err != nil {
			panic(err)
		} else {
			insts = append(insts, ofp4.MakeInstructionActions(ofp4.OFPIT_WRITE_ACTIONS, actions)...)
		}
	}
	if entry.instMetadata != nil {
		inst := ofp4.MakeInstructionWriteMetadata(
			entry.instMetadata.metadata,
			entry.instMetadata.mask,
		)
		insts = append(insts, inst...)
	}
	if entry.instGoto != 0 {
		insts = append(insts, ofp4.MakeInstructionGotoTable(entry.instGoto)...)
	}
	return insts
}

// sort.Interface for longest match
type flowEntryList []*flowEntry

func (self flowEntryList) Len() int {
	return len([]*flowEntry(self))
}

func (self flowEntryList) Less(i, j int) bool {
	l := []*flowEntry(self)

	a, aerr := l[i].fields.Expand()
	b, berr := l[j].fields.Expand()

	if aerr != nil && berr != nil {
		result, err := a.Fit(b)
		if err != nil {
			return result
		}
	}
	return len(l[i].fields) > len(l[j].fields)
}

func (self flowEntryList) Swap(i, j int) {
	l := []*flowEntry(self)
	l[i], l[j] = l[j], l[i]
}

type metadataInstruction struct {
	metadata uint64
	mask     uint64
}

func (m metadataInstruction) apply(value uint64) uint64 {
	return m.metadata&m.mask | value&^m.mask
}

/*
flowFilter will be used in querying and or deleting flows in flow tables.
*/
type flowFilter struct {
	opUnregister bool
	opStrict     bool
	cookie       uint64
	cookieMask   uint64
	tableId      uint8
	priority     uint16
	outPort      uint32
	outGroup     uint32
	meterId      uint32
	match        match
}

type flowStats struct {
	tableId  uint8
	priority uint16
	flow     *flowEntry
}

func (pipe Pipeline) filterFlows(req flowFilter) []flowStats {
	pipe.lock.RLock()
	defer pipe.lock.RUnlock()

	return pipe.filterFlowsInside(req)
}

/*
filterFlowsInside filters flow entries in the flow tables without a mutex guard.

Please make sure that you invoke this method inside a mutex guard.
This is because group, meter deletion will also remove associated flows, and the
mutex is aquired in that operation, outside of filterFlowsInside.
*/
func (pipe Pipeline) filterFlowsInside(req flowFilter) []flowStats {
	var stats []flowStats
	if req.tableId == ofp4.OFPTT_ALL {
		waits := 0
		reducer := make(chan []flowStats)
		for tableId, table := range pipe.flows {
			tableId := tableId
			table := table
			go func() {
				reducer <- table.filterFlows(req, tableId)
			}()
			waits++
		}
		for i := 0; i < waits; i++ {
			stats = append(stats, <-reducer...)
		}
	} else {
		if table, ok := pipe.flows[req.tableId]; ok {
			stats = table.filterFlows(req, req.tableId)
		}
	}
	return stats
}

func (table flowTable) filterFlows(req flowFilter, tableId uint8) []flowStats {
	if req.opUnregister {
		table.lock.Lock()
		defer table.lock.Unlock()
	} else {
		table.lock.RLock()
		defer table.lock.RUnlock()
	}

	waits := 0
	reducer := make(chan []flowStats)
	for _, prio := range table.priorities {
		if req.opStrict && prio.priority != req.priority {
			continue
		}
		prio := prio
		go func() {
			reducer <- prio.filterFlows(req, tableId)
		}()
		waits++
	}
	var stats []flowStats
	for i := 0; i < waits; i++ {
		stats = append(stats, <-reducer...)
	}
	if req.opUnregister {
		table.activeCount -= uint32(len(stats))
	}
	return stats
}

func (prio *flowPriority) filterFlows(req flowFilter, tableId uint8) []flowStats {
	if req.opUnregister {
		prio.lock.Lock()
		defer prio.lock.Unlock()
	} else {
		prio.lock.RLock()
		defer prio.lock.RUnlock()
	}

	reqMatch, err := req.match.Expand()
	if err != nil {
		log.Print(err)
		return nil
	}

	var hits []flowStats
	var miss []*flowEntry
	for _, flows := range prio.flows {
		for _, flow := range flows {
			hit := func() bool {
				if fields, err := flow.fields.Expand(); err != nil {
					log.Print(err)
					return false
				} else {
					if req.opStrict {
						if eq, err := fields.Equal(reqMatch); err != nil {
							log.Print(err)
							return false
						} else if !eq {
							return false
						}
					} else {
						if fit, err := fields.Fit(reqMatch); err != nil {
							log.Print(err)
							return false
						} else if !fit {
							return false
						}
					}
				}
				if req.opUnregister {
					if req.outPort != ofp4.OFPP_ANY {
						found := func() bool {
							for _, act := range flow.instApply {
								if cact, ok := act.(*actionOutput); ok {
									if cact.Port == req.outPort {
										return true
									}
								}
							}
							if act, ok := flow.instWrite.hash[uint16(ofp4.OFPAT_OUTPUT)]; ok {
								if act.(actionOutput).Port == req.outPort {
									return true
								}
							}
							return false
						}()
						if !found {
							return false
						}
					}
					if req.outGroup != ofp4.OFPG_ANY {
						found := func() bool {
							for _, act := range flow.instApply {
								if cact, ok := act.(*actionGroup); ok {
									if cact.GroupId == req.outGroup {
										return true
									}
								}
							}
							if act, ok := flow.instWrite.hash[uint16(ofp4.OFPAT_GROUP)]; ok {
								if act.(actionGroup).GroupId == req.outGroup {
									return true
								}
							}
							return false
						}()
						if !found {
							return false
						}
					}
				}
				if req.cookieMask != 0 && (flow.cookie&req.cookieMask) != (req.cookie&req.cookieMask) {
					return false
				}
				return true
			}()
			if hit {
				stat := flowStats{
					tableId:  tableId,
					priority: prio.priority,
					flow:     flow,
				}
				hits = append(hits, stat)
			} else {
				miss = append(miss, flow)
			}
		}
	}
	if req.opUnregister {
		prio.rebuildIndex(miss)
	}
	return hits
}

func hookDot11Action(hdr oxm.Oxm) (uint32, []byte) {
	var inPort uint32
	for _, o := range hdr.Iter() {
		if o.Header().Type() == oxm.OXM_OF_IN_PORT {
			inPort = binary.BigEndian.Uint32(o[4:])
		}
	}
	var action []byte
	for _, o := range hdr.Iter() {
		if o.Header().Class() != ofp4.OFPXMC_EXPERIMENTER {
			continue
		}
		if ofp4.OxmExperimenterHeader(o).Experimenter() != oxm.STRATOS_EXPERIMENTER_ID {
			continue
		}
		switch o.Header().Field() {
		case oxm.STROXM_BASIC_DOT11_ACTION_CATEGORY:
			buf := o[8:]
			if len(action) < len(buf) {
				action = buf
			}
		case oxm.STROXM_BASIC_DOT11_PUBLIC_ACTION:
			buf := append([]byte{4}, o[8:]...)
			if len(action) < len(buf) {
				action = buf
			}
		}
	}
	return inPort, action
}
