package ofp4sw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"hash/fnv"
	"time"
)

type flowTable struct {
	commands chan func()
	// list by priority
	priorities  []*flowPriority
	lookupCount uint64
	matchCount  uint64
}

type flowPriority struct {
	commands chan func()
	priority uint16
	caps     []match
	flows    map[uint32][]*flowEntry // entries in the same priority
}

type flowEntry struct {
	commands    chan func()
	fields      []match
	cookie      uint64
	packetCount uint64
	byteCount   uint64
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
}

type match struct {
	field uint64
	mask  []byte
	value []byte
}

func newFlowTable() *flowTable {
	table := &flowTable{commands: make(chan func(), 16)}
	go func() {
		for cmd := range table.commands {
			if cmd != nil {
				cmd()
			} else {
				break
			}
		}
	}()
	return table
}

func newFlowPriority(priority uint16) *flowPriority {
	prio := &flowPriority{
		commands: make(chan func(), 16),
		flows:    make(map[uint32][]*flowEntry),
		priority: priority,
	}
	go func() {
		for cmd := range prio.commands {
			if cmd != nil {
				cmd()
			} else {
				break
			}
		}
	}()
	return prio
}

type lookupResult struct {
	entry    *flowEntry
	priority uint16
}

func (table *flowTable) lookup(data frame) (*flowEntry, uint16) {
	ch := make(chan []*flowPriority)
	table.commands <- func() {
		table.lookupCount++
		ch <- table.priorities
		close(ch)
	}
	for _, prio := range <-ch {
		if en := prio.matchFrame(data); en != nil {
			table.commands <- func() {
				table.matchCount++
			}
			return en, prio.priority
		}
	}
	return nil, 0
}

func (priority flowPriority) matchFrame(data frame) *flowEntry {
	ret := make(chan *flowEntry)
	priority.commands <- func() {
		ret <- func() *flowEntry {
			hasher := fnv.New32()
			for _, p1 := range priority.caps {
				if buf, err := data.getValue(p1); err != nil {
					return nil
				} else {
					hasher.Write(buf)
				}
			}
			if entries, ok := priority.flows[hasher.Sum32()]; ok {
				for _, entry := range entries {
					hit := true
					for _, field := range entry.fields {
						if !field.match(data) {
							hit = false
							break
						}
					}
					if hit {
						return entry
					}
				}
			}
			return nil
		}()
		close(ret)
	}
	return <-ret
}

func (priority *flowPriority) rebuildIndex(flows []*flowEntry) {
	var cap []match
	for i, flow := range flows {
		if i == 0 {
			cap = flow.fields
		} else {
			cap = capMask(cap, flow.fields)
		}
	}

	for k, _ := range priority.flows {
		delete(priority.flows, k)
	}

	priority.caps = cap
	for _, flow := range flows {
		key := capKey(cap, flow.fields)
		if ent, ok := priority.flows[key]; ok {
			// XXX: reorder for longest match
			priority.flows[key] = append(ent, flow)
		} else {
			priority.flows[key] = []*flowEntry{flow}
		}
	}
}

type flowEntryResult struct {
	outputs []packetOut
	groups  []groupOut
	tableId uint8
}

func (rule *flowEntry) process(data *frame, pipe Pipeline) flowEntryResult {
	var result flowEntryResult
	if frameData, err := data.data(); err != nil {
		fmt.Println(err)
		return result
	} else {
		ch := make(chan error)
		rule.commands <- func() {
			rule.packetCount++
			rule.byteCount += uint64(len(frameData))
			ch <- nil
			close(ch)
		}
		_ = <-ch
	}
	if rule.instMeter != 0 {
		for _, meter := range pipe.getMeters(rule.instMeter) {
			if err := meter.process(data); err != nil {
				return result
			}
		}
	}
	for _, act := range rule.instApply {
		if aret, err := act.process(data, pipe); err != nil {
			data.errors = append(data.errors, err)
		} else {
			result.groups = append(result.groups, aret.groups...)
			result.outputs = append(result.outputs, aret.outputs...)
		}
	}
	if rule.instClear {
		data.actionSet = make(map[uint16]action)
	}
	if rule.instWrite != nil {
		for k, v := range rule.instWrite {
			data.actionSet[k] = v
		}
	}
	if rule.instMetadata != nil {
		data.metadata = rule.instMetadata.apply(data.metadata)
	}
	if rule.instGoto != 0 {
		result.tableId = rule.instGoto
	} else {
		tmp := data.clone()
		aret := actionSet(data.actionSet).process(tmp, pipe)
		result.groups = append(result.groups, aret.groups...)
		result.outputs = append(result.outputs, aret.outputs...)
	}
	return result
}

type metadataInstruction struct {
	metadata uint64
	mask     uint64
}

func (m metadataInstruction) apply(value uint64) uint64 {
	return m.metadata&m.mask | value&^m.mask
}

func (m match) match(data frame) bool {
	if value, err := data.getValue(m); err == nil {
		if bytes.Compare(maskBytes(value, m.mask), m.value) == 0 {
			return true
		}
	}
	return false
}

func maskBytes(value, mask []byte) []byte {
	ret := make([]byte, len(value))
	for i, _ := range ret {
		ret[i] = value[i] & mask[i]
	}
	return ret
}

func (m match) matchMatch(wide []match) bool {
	for _, w := range wide {
		if w.field == m.field {
			if bytes.Compare(maskBytes(m.value, w.mask), maskBytes(w.value, w.mask)) == 0 {
				return true
			} else {
				return false
			}
		}
	}
	return true
}

func overlap(f1, f2 []match) bool {
	mask := capMask(f1, f2)
	for _, m := range mask {
		for _, m1 := range f1 {
			if m1.field == m.field {
				for _, m2 := range f2 {
					if m2.field == m.field {
						if bytes.Compare(maskBytes(m1.value, m.mask), maskBytes(m2.value, m.mask)) != 0 {
							return false
						}
					}
				}
			}
		}
	}
	return true
}

func capMask(f1, f2 []match) []match {
	var ret []match
	for _, m1 := range f1 {
		for _, m2 := range f2 {
			if m1.field == m2.field {
				maskFull := true
				mask := make([]byte, len(m1.mask))
				for i, _ := range mask {
					mask[i] = m1.mask[i] & m2.mask[i]
					if mask[i] != 0 {
						maskFull = false
					}
				}
				if !maskFull {
					ret = append(ret, match{
						field: m1.field,
						mask:  mask,
					})
				}
			}
		}
	}
	return ret
}

func capKey(cap []match, f []match) uint32 {
	var buf []byte
	for _, m1 := range cap {
		for _, m2 := range f {
			if m1.field == m2.field {
				value := make([]byte, len(m2.value))
				for i, _ := range value {
					value[i] = m2.value[i] & (m1.mask[i] & m2.mask[i])
				}
				buf = append(buf, value...)
			}
		}
	}
	hasher := fnv.New32()
	if _, err := hasher.Write(buf); err != nil {
		return 0
	}
	return hasher.Sum32()
}

type matchList []match

func (ms matchList) MarshalBinary() ([]byte, error) {
	var ret []byte
	for _, m := range []match(ms) {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], 0x8000)
		if ofp4.OxmHaveMask(uint16(m.field)) {
			hdr[2] = uint8(m.field)<<1 | uint8(1)
			hdr[3] = uint8(len(m.value) + len(m.mask))
			ret = append(ret, hdr...)
			ret = append(ret, m.value...)
			ret = append(ret, m.mask...)
		} else {
			hdr[2] = uint8(m.field<<1) | uint8(0)
			hdr[3] = uint8(len(m.value))
			ret = append(ret, hdr...)
			ret = append(ret, m.value...)
		}
	}
	return ret, nil
}

func (ms *matchList) UnmarshalBinary(s []byte) error {
	var ret []match
	for cur := 0; cur+4 < len(s); cur += 4 + int(s[cur+3]) {
		if binary.BigEndian.Uint16(s[cur:cur+2]) == 0x8000 {
			m := match{}
			m.field = uint64(s[cur+2] >> 1)
			length := int(s[cur+3])
			if s[cur+2]&0x01 == 0 {
				m.value = s[cur+4 : cur+4+length]
				m.mask = make([]byte, length)
				for i, _ := range m.mask {
					m.mask[i] = 0xFF
				}
			} else {
				m.value = s[cur+4 : cur+4+length/2]
				m.mask = s[cur+4+length/2 : cur+4+length]
			}
			ret = append(ret, m)
		} else {
			// silently ignore
			fmt.Print("oxm_class", s[cur:cur+2])
		}
	}
	*ms = matchList(ret)
	return nil
}

//////////// ofp_flow_stats

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
	match        []match
}

type flowStats struct {
	tableId  uint8
	priority uint16
	entry    *flowEntry
}

func (p Pipeline) filterFlows(req flowFilter) []flowStats {
	ch := make(chan []flowStats)
	p.commands <- func() {
		ch <- p.filterFlowsInside(req)
		close(ch)
	}
	return <-ch
}

func (p Pipeline) filterFlowsInside(req flowFilter) []flowStats {
	var stats []flowStats
	waits := 0
	ch2 := make(chan []flowStats)
	for i, table := range p.flows {
		if req.tableId == ofp4.OFPTT_ALL || req.tableId == i {
			i2 := i
			table2 := table
			go func() {
				ch2 <- table2.filterFlows(req, i2)
			}()
			waits++
		}
	}
	for i := 0; i < waits; i++ {
		stats = append(stats, <-ch2...)
	}
	return stats
}

func (t flowTable) filterFlows(req flowFilter, tableId uint8) []flowStats {
	ch := make(chan []flowStats)
	t.commands <- func() {
		var stats []flowStats
		waits := 0
		ch2 := make(chan []flowStats)
		for _, prio := range t.priorities {
			if req.opStrict && prio.priority != req.priority {
				continue
			}
			prio2 := prio
			go func() {
				ch2 <- prio2.filterFlows(req, tableId)
			}()
			waits++
		}
		for i := 0; i < waits; i++ {
			stats = append(stats, <-ch2...)
		}
		ch <- stats
		close(ch)
	}
	return <-ch
}

func (p flowPriority) filterFlows(req flowFilter, tableId uint8) []flowStats {
	ch := make(chan []flowStats)
	p.commands <- func() {
		var hits []flowStats
		var miss []*flowEntry
		for _, flows := range p.flows {
			for _, flow := range flows {
				hit := func() bool {
					if (flow.cookie & req.cookieMask) != (req.cookie & req.cookieMask) {
						return false
					}
					for _, m := range flow.fields {
						if !m.matchMatch(req.match) {
							return false
						}
					}
					if req.outPort != ofp4.OFPP_ANY {
						for _, act := range flow.instApply {
							if cact, ok := act.(*actionOutput); ok {
								if cact.Port == req.outPort {
									return true
								}
							}
						}
						for _, act := range flow.instWrite {
							if cact, ok := act.(*actionOutput); ok {
								if cact.Port == req.outPort {
									return true
								}
							}
						}
						return false
					}
					if req.outGroup != ofp4.OFPG_ANY {
						for _, act := range flow.instApply {
							if cact, ok := act.(*actionGroup); ok {
								if cact.GroupId == req.outGroup {
									return true
								}
							}
						}
						for _, act := range flow.instWrite {
							if cact, ok := act.(*actionGroup); ok {
								if cact.GroupId == req.outGroup {
									return true
								}
							}
						}
						return false
					}
					if req.meterId != 0 {
						if flow.instMeter == req.meterId {
							return true
						}
						return false
					}
					return true
				}()
				if hit {
					stat := flowStats{
						tableId:  tableId,
						priority: p.priority,
						entry:    flow,
					}
					hits = append(hits, stat)
				} else {
					miss = append(miss, flow)
				}
			}
		}
		if req.opUnregister {
			p.rebuildIndex(miss)
			for _, hit := range hits {
				hit.entry.commands <- nil
			}
		}
		ch <- hits
		close(ch)
	}
	return <-ch
}

///// flow entry operation

func newFlowEntry(req ofp4.FlowMod) (*flowEntry, error) {
	var reqMatch matchList
	if err := reqMatch.UnmarshalBinary(req.Match.OxmFields); err != nil {
		return nil, err
	}
	entry := &flowEntry{
		commands:    make(chan func(), 16),
		fields:      []match(reqMatch),
		cookie:      req.Cookie,
		created:     time.Now(),
		idleTimeout: req.IdleTimeout,
		hardTimeout: req.HardTimeout,
	}
	for _, binst := range req.Instructions {
		switch inst := binst.(type) {
		default:
			return nil, ofp4.Error{Type: ofp4.OFPET_BAD_INSTRUCTION, Code: ofp4.OFPBIC_UNKNOWN_INST}
		case *ofp4.InstructionGotoTable:
			entry.instGoto = inst.TableId
		case *ofp4.InstructionWriteMetadata:
			entry.instMetadata = &metadataInstruction{inst.Metadata, inst.MetadataMask}
		case *ofp4.InstructionActions:
			switch inst.Type {
			case ofp4.OFPIT_WRITE_ACTIONS:
				var aset actionSet
				aset.fromMessage(inst.Actions)
				entry.instWrite = aset
			case ofp4.OFPIT_APPLY_ACTIONS:
				var alist actionList
				alist.fromMessage(inst.Actions)
				entry.instApply = alist
			case ofp4.OFPIT_CLEAR_ACTIONS:
				entry.instClear = true
			}
		case *ofp4.InstructionMeter:
			entry.instMeter = inst.MeterId
		case *ofp4.InstructionExperimenter:
			return nil, ofp4.Error{Type: ofp4.OFPET_BAD_INSTRUCTION, Code: ofp4.OFPBIC_UNSUP_INST}
		}
	}
	go func() {
		for cmd := range entry.commands {
			if cmd != nil {
				cmd()
			} else {
				break
			}
		}
	}()
	return entry, nil
}

func (pipe Pipeline) addFlowEntry(req ofp4.FlowMod) error {
	ch := make(chan error)
	pipe.commands <- func() {
		ch <- func() error {
			if req.TableId > ofp4.OFPTT_MAX {
				return ofp4.Error{
					Type: ofp4.OFPET_FLOW_MOD_FAILED,
					Code: ofp4.OFPFMFC_BAD_TABLE_ID,
				}
			}
			var table *flowTable
			if trial, ok := pipe.flows[req.TableId]; ok {
				table = trial
			} else {
				table = newFlowTable()
				pipe.flows[req.TableId] = table
			}

			ch2 := make(chan error)
			table.commands <- func() {
				ch2 <- func() error {
					var split int
					var priority *flowPriority
					for i, prio := range table.priorities { // descending order
						if prio.priority > req.Priority {
							split = i
						} else if prio.priority == req.Priority {
							priority = prio
						} else {
							break
						}
					}
					if priority == nil {
						priority = newFlowPriority(req.Priority)
						table.priorities = append(append(table.priorities[:split], priority), table.priorities[split:]...)
					}
					ch3 := make(chan error)
					priority.commands <- func() {
						ch3 <- func() error {
							var reqMatch matchList
							if err := reqMatch.UnmarshalBinary(req.Match.OxmFields); err != nil {
								return err
							}

							var flows []*flowEntry
							if flow, err := newFlowEntry(req); err != nil {
								return err
							} else {
								key := capKey(priority.caps, flow.fields)
								if ent, ok := priority.flows[key]; ok {
									overlaps := false
									for _, f := range ent {
										if overlap(f.fields, flow.fields) {
											overlaps = true
											break
										}
									}
									if overlaps && (req.Flags&ofp4.OFPFF_CHECK_OVERLAP) != uint16(0) {
										flow.commands <- nil
										return ofp4.Error{Type: ofp4.OFPET_FLOW_MOD_FAILED, Code: ofp4.OFPFMFC_OVERLAP}
									}
								}
								flows = append(flows, flow)
							}
							for _, fs := range priority.flows {
								flows = append(flows, fs...)
							}
							priority.rebuildIndex(flows)
							return nil
						}()
					}
					return <-ch3
				}()
				close(ch2)
			}
			return <-ch2
		}()
		close(ch)
	}
	ret := <-ch

	return ret
}
