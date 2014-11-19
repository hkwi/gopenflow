package ofp4sw

import (
	"encoding"
	"encoding/binary"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
)

// Experimenter instructions and actions are identified by (experimenter-id, experimenter-type) pair.
type experimenterKey struct {
	Id   uint32
	Type uint32
}

type experimenterProp struct {
	experimenterKey
	Data []byte
}

// Static types are
// 1) uint16 for OFPIT_*
// 2) experimenterKey
type instructionKey interface{}

type instructionKeyList []instructionKey

func (self instructionKeyList) Have(key instructionKey) bool {
	for _, k := range []instructionKey(self) {
		if k == key {
			return true
		}
	}
	return false
}

// Static types are
// 1) uint16 for OFPAT_*
// 2) experimenterKey
type actionKey interface{}

type actionKeyList []actionKey

func (self actionKeyList) Have(key actionKey) bool {
	for _, k := range []actionKey(self) {
		if k == key {
			return true
		}
	}
	return false
}

// Static types are
// 1) uint32 for OFPXMC_OPENFLOW_BASIC oxm field
// 2) uint64 for OFPXMC_EXPERIMENTER oxm field
type oxmKey interface{}

type oxmKeyList []oxmKey

func (self oxmKeyList) Have(key oxmKey) bool {
	for _, k := range []oxmKey(self) {
		if k == key {
			return true
		}
	}
	return false
}

type TableHandler interface {
	// XXX: TBD
}

var tableHandlers map[experimenterKey]TableHandler = make(map[experimenterKey]TableHandler)

func AddTableHandler(experimenter uint32, expType uint32, handler TableHandler) {
	key := experimenterKey{
		Id:   experimenter,
		Type: expType,
	}
	tableHandlers[key] = handler
}

// special rule here. nil means "NOT SET"
type flowTableFeatureProps struct {
	inst          []instructionKey
	next          []uint8
	writeActions  []actionKey
	applyActions  []actionKey
	writeSetfield []oxmKey
	applySetfield []oxmKey
	experimenter  []experimenterProp
}

type flowTableFeature struct {
	name          string
	metadataMatch uint64
	metadataWrite uint64
	config        uint32
	maxEntries    uint32
	// properties
	match     []oxmKey
	wildcards []oxmKey
	hit       flowTableFeatureProps
	miss      flowTableFeatureProps
}

func makeFlowTableFeature() flowTableFeature {
	return flowTableFeature{
		metadataMatch: 0xFFFFFFFFFFFFFFFF,
		metadataWrite: 0xFFFFFFFFFFFFFFFF,
		maxEntries:    0xFFFFFFFF,
	}
}

func (self flowTableFeature) exportProps() []encoding.BinaryMarshaler {
	var props []encoding.BinaryMarshaler

	instExport := func(pType uint16, keys []instructionKey) {
		if keys == nil {
			return
		}
		var ids []ofp4.Instruction
		for _, key := range keys {
			switch k := key.(type) {
			case uint16:
				ids = append(ids, ofp4.InstructionId{
					Type: k,
				})
			case experimenterKey:
				ids = append(ids, ofp4.InstructionExperimenter{
					Experimenter: k.Id,
					ExpType:      k.Type,
				})
			default:
				panic("unexpected instruction key type")
			}
		}
		props = append(props, ofp4.TableFeaturePropInstructions{
			Type:           pType,
			InstructionIds: ids,
		})
	}
	instExport(ofp4.OFPTFPT_INSTRUCTIONS, self.hit.inst)
	instExport(ofp4.OFPTFPT_INSTRUCTIONS_MISS, self.miss.inst)

	oxmExport := func(pType uint16, keys []oxmKey) {
		if keys == nil {
			return
		}
		var ids []uint32
		for _, key := range keys {
			switch k := key.(type) {
			case uint32:
				ids = append(ids, k)
			case uint64:
				if handler, ok := oxmHandlers[k]; ok {
					base := make([]byte, 8)
					binary.BigEndian.PutUint64(base, k)
					if oxmId, err := handler.OxmId(base); err != nil { // give handler a chance to modify the key
						log.Print(err)
					} else {
						ids = append(ids, binary.BigEndian.Uint32(oxmId))
						ids = append(ids, binary.BigEndian.Uint32(oxmId[4:]))
					}
				} else {
					log.Print("unknown oxm experimenter key")
				}
			}
		}
		props = append(props, ofp4.TableFeaturePropOxm{
			Type:   pType,
			OxmIds: ids,
		})
	}
	oxmExport(ofp4.OFPTFPT_MATCH, self.match)
	oxmExport(ofp4.OFPTFPT_WILDCARDS, self.wildcards)
	oxmExport(ofp4.OFPTFPT_WRITE_SETFIELD, self.hit.writeSetfield)
	oxmExport(ofp4.OFPTFPT_WRITE_SETFIELD_MISS, self.miss.writeSetfield)
	oxmExport(ofp4.OFPTFPT_APPLY_SETFIELD, self.hit.applySetfield)
	oxmExport(ofp4.OFPTFPT_APPLY_SETFIELD_MISS, self.miss.applySetfield)

	nextExport := func(pType uint16, keys []uint8) {
		if keys == nil {
			return
		}
		props = append(props, ofp4.TableFeaturePropNextTables{
			Type:         pType,
			NextTableIds: keys,
		})
	}
	nextExport(ofp4.OFPTFPT_NEXT_TABLES, self.hit.next)
	nextExport(ofp4.OFPTFPT_NEXT_TABLES_MISS, self.miss.next)

	actionExport := func(pType uint16, keys []actionKey) {
		if keys == nil {
			return
		}
		var ids []ofp4.Action
		for _, key := range keys {
			switch k := key.(type) {
			case uint16:
				ids = append(ids, ofp4.ActionGeneric{
					Type: k,
				})
			case experimenterKey:
				ids = append(ids, ofp4.ActionExperimenter{
					Experimenter: k.Id,
					ExpType:      k.Type,
				})
			default:
				panic("unexpected action key type")
			}
		}
		props = append(props, ofp4.TableFeaturePropActions{
			Type:      pType,
			ActionIds: ids,
		})
	}
	actionExport(ofp4.OFPTFPT_WRITE_ACTIONS, self.hit.writeActions)
	actionExport(ofp4.OFPTFPT_WRITE_ACTIONS_MISS, self.miss.writeActions)
	actionExport(ofp4.OFPTFPT_APPLY_ACTIONS, self.hit.applyActions)
	actionExport(ofp4.OFPTFPT_APPLY_ACTIONS_MISS, self.miss.applyActions)

	experimenterExport := func(pType uint16, exps []experimenterProp) {
		if exps == nil {
			return
		}
		for _, exp := range exps {
			props = append(props, ofp4.TableFeaturePropExperimenter{
				Type:         pType,
				Experimenter: exp.Id,
				ExpType:      exp.Type,
				Data:         exp.Data,
			})
		}
	}
	experimenterExport(ofp4.OFPTFPT_EXPERIMENTER, self.hit.experimenter)
	experimenterExport(ofp4.OFPTFPT_EXPERIMENTER_MISS, self.miss.experimenter)

	return props
}

func (self *flowTableFeature) importProps(props []encoding.BinaryMarshaler) error {
	for _, prop := range props {
		switch p := prop.(type) {
		case *ofp4.TableFeaturePropInstructions:
			ids := []instructionKey{}
			for _, instId := range p.InstructionIds {
				switch inst := instId.(type) {
				case *ofp4.InstructionId:
					ids = append(ids, inst.Type)
				case *ofp4.InstructionExperimenter:
					ids = append(ids, experimenterKey{
						Id:   inst.Experimenter,
						Type: inst.ExpType,
					})
				default:
					panic("unexpected")
				}
			}
			switch p.Type {
			case ofp4.OFPTFPT_INSTRUCTIONS:
				self.hit.inst = ids
			case ofp4.OFPTFPT_INSTRUCTIONS_MISS:
				self.miss.inst = ids
			default:
				panic("unexpected")
			}
		case *ofp4.TableFeaturePropNextTables:
			switch p.Type {
			case ofp4.OFPTFPT_NEXT_TABLES:
				self.hit.next = p.NextTableIds
			case ofp4.OFPTFPT_NEXT_TABLES_MISS:
				self.miss.next = p.NextTableIds
			default:
				panic("unexpected")
			}
		case *ofp4.TableFeaturePropActions:
			ids := []actionKey{}
			for _, act := range p.ActionIds {
				switch a := act.(type) {
				case *ofp4.ActionGeneric:
					ids = append(ids, a.Type)
				case *ofp4.ActionExperimenter:
					ids = append(ids, experimenterKey{
						Id:   a.Experimenter,
						Type: a.ExpType,
					})
				default:
					panic("unexpected")
				}
			}
			switch p.Type {
			case ofp4.OFPTFPT_WRITE_ACTIONS:
				self.hit.writeActions = ids
			case ofp4.OFPTFPT_WRITE_ACTIONS_MISS:
				self.miss.writeActions = ids
			case ofp4.OFPTFPT_APPLY_ACTIONS:
				self.hit.applyActions = ids
			case ofp4.OFPTFPT_APPLY_ACTIONS_MISS:
				self.miss.applyActions = ids
			default:
				panic("unexpected")
			}
		case *ofp4.TableFeaturePropOxm:
			ids := []oxmKey{}
			var exp *uint64
			for _, v := range p.OxmIds {
				if exp == nil {
					if ofp4.OxmHeader(v).Class() == ofp4.OFPXMC_EXPERIMENTER {
						capture := uint64(v) << 32
						exp = &capture
					} else {
						ids = append(ids, v)
					}
				} else {
					ids = append(ids, *exp|uint64(v))
					exp = nil
				}
			}
			switch p.Type {
			case ofp4.OFPTFPT_MATCH:
				self.match = ids
			case ofp4.OFPTFPT_WILDCARDS:
				self.wildcards = ids
			case ofp4.OFPTFPT_WRITE_SETFIELD:
				self.hit.writeSetfield = ids
			case ofp4.OFPTFPT_WRITE_SETFIELD_MISS:
				self.miss.writeSetfield = ids
			case ofp4.OFPTFPT_APPLY_SETFIELD:
				self.hit.applySetfield = ids
			case ofp4.OFPTFPT_APPLY_SETFIELD_MISS:
				self.miss.applySetfield = ids
			default:
				panic("unexpected")
			}
		case *ofp4.TableFeaturePropExperimenter:
			eKey := experimenterKey{
				Id:   p.Experimenter,
				Type: p.ExpType,
			}
			if _, ok := tableHandlers[eKey]; !ok {
				return ofp4.Error{
					Type: ofp4.OFPET_TABLE_FEATURES_FAILED,
					Code: ofp4.OFPTFFC_BAD_ARGUMENT,
				}
			}
			exp := experimenterProp{
				experimenterKey: eKey,
				Data:            p.Data,
			}
			switch p.Type {
			case ofp4.OFPTFPT_EXPERIMENTER:
				self.hit.experimenter = append(self.hit.experimenter, exp)
			case ofp4.OFPTFPT_EXPERIMENTER_MISS:
				self.miss.experimenter = append(self.hit.experimenter, exp)
			default:
				panic("unexpected")
			}
		}
	}
	return nil
}

// See openflow switch 1.3.4 spec "Flow Table Modification Messages" page 40
func (self flowTableFeature) accepts(entry *flowEntry, priority uint16) error {
	isTableMiss := false
	if entry.fields.isEmpty() && priority == 0 {
		isTableMiss = true
	}

	var instKeys instructionKeyList
	if isTableMiss && self.miss.inst != nil {
		instKeys = instructionKeyList(self.miss.inst)
	} else if self.hit.inst != nil {
		instKeys = instructionKeyList(self.hit.inst)
	}

	if entry.instGoto != 0 {
		if instKeys != nil && !instKeys.Have(uint16(ofp4.OFPIT_GOTO_TABLE)) {
			return ofp4.Error{
				Type: ofp4.OFPET_BAD_INSTRUCTION,
				Code: ofp4.OFPBIC_UNSUP_INST,
			}
		}

		var next []uint8
		if isTableMiss && self.miss.next != nil {
			next = self.miss.next
		} else if self.hit.next != nil {
			next = self.hit.next
		}
		if next != nil {
			supported := false
			for _, tableId := range next {
				if entry.instGoto == tableId {
					supported = true
				}
			}
			if !supported {
				return ofp4.Error{
					Type: ofp4.OFPET_BAD_INSTRUCTION,
					Code: ofp4.OFPBIC_BAD_TABLE_ID,
				}
			}
		}
	}

	if entry.instMetadata != nil {
		if instKeys != nil && !instKeys.Have(uint16(ofp4.OFPIT_WRITE_METADATA)) {
			return ofp4.Error{
				Type: ofp4.OFPET_BAD_INSTRUCTION,
				Code: ofp4.OFPBIC_UNSUP_INST,
			}
		}
		if entry.instMetadata.metadata&^self.metadataWrite != 0 {
			return ofp4.Error{
				Type: ofp4.OFPET_BAD_INSTRUCTION,
				Code: ofp4.OFPBIC_UNSUP_METADATA,
			}
		}
		if entry.instMetadata.mask&^self.metadataWrite != 0 {
			return ofp4.Error{
				Type: ofp4.OFPET_BAD_INSTRUCTION,
				Code: ofp4.OFPBIC_UNSUP_METADATA_MASK,
			}
		}
	}

	if !isTableMiss && self.match != nil {
		specified := make(map[oxmKey]bool)
		for _, k := range self.match {
			specified[k] = false
		}
		for _, m := range entry.fields.basic {
			if !oxmKeyList(self.match).Have(m.Type) {
				return ofp4.Error{
					Type: ofp4.OFPET_BAD_MATCH,
					Code: ofp4.OFPBMC_BAD_FIELD,
				}
			}
			if specified[m.Type] {
				return ofp4.Error{
					Type: ofp4.OFPET_BAD_MATCH,
					Code: ofp4.OFPBMC_DUP_FIELD,
				}
			} else {
				specified[m.Type] = true
			}
		}
		for key, _ := range entry.fields.exp {
			if !oxmKeyList(self.match).Have(key) {
				return ofp4.Error{
					Type: ofp4.OFPET_BAD_MATCH,
					Code: ofp4.OFPBMC_BAD_FIELD,
				}
			}
			specified[key] = true
		}
		for _, k := range self.wildcards {
			specified[k] = true
		}
		for _, v := range specified {
			if !v {
				return ofp4.Error{
					Type: ofp4.OFPET_BAD_MATCH,
					Code: ofp4.OFPBMC_BAD_WILDCARDS,
				}
			}
		}
	}

	if len([]action(entry.instApply)) > 0 {
		if instKeys != nil && !instKeys.Have(uint16(ofp4.OFPIT_APPLY_ACTIONS)) {
			return ofp4.Error{
				Type: ofp4.OFPET_BAD_INSTRUCTION,
				Code: ofp4.OFPBIC_UNSUP_INST,
			}
		}
		var keys []actionKey
		if isTableMiss && self.miss.applyActions != nil {
			keys = self.miss.applyActions
		} else if self.hit.applyActions != nil {
			keys = self.hit.applyActions
		}
		if keys != nil {
			for _, act := range []action(entry.instApply) {
				var aKey actionKey
				switch a := act.(type) {
				case *actionExperimenter:
					aKey = a.experimenterKey
				case *actionOutput:
					aKey = uint16(ofp4.OFPAT_OUTPUT)
				case *actionMplsTtl:
					aKey = uint16(ofp4.OFPAT_SET_MPLS_TTL)
				case *actionPush:
					aKey = a.Type
				case *actionPopMpls:
					aKey = uint16(ofp4.OFPAT_POP_MPLS)
				case *actionSetQueue:
					aKey = uint16(ofp4.OFPAT_SET_QUEUE)
				case *actionGroup:
					aKey = uint16(ofp4.OFPAT_GROUP)
				case *actionNwTtl:
					aKey = uint16(ofp4.OFPAT_SET_NW_TTL)
				case *actionSetField:
					aKey = uint16(ofp4.OFPAT_SET_FIELD)
				}
				if !actionKeyList(keys).Have(aKey) {
					return ofp4.Error{
						Type: ofp4.OFPET_BAD_ACTION,
						Code: ofp4.OFPBAC_BAD_TYPE,
					}
				}
			}
			// XXX: Experimenter
		}
	}

	if entry.instWrite.Len() > 0 {
		if instKeys != nil && !instKeys.Have(uint16(ofp4.OFPIT_WRITE_ACTIONS)) {
			return ofp4.Error{
				Type: ofp4.OFPET_BAD_INSTRUCTION,
				Code: ofp4.OFPBIC_UNSUP_INST,
			}
		}
		var keys []actionKey
		if isTableMiss && self.miss.writeActions != nil {
			keys = self.miss.writeActions
		} else if self.hit.writeActions != nil {
			keys = self.hit.writeActions
		}
		if keys != nil {
			for _, a := range entry.instWrite.hash {
				if !actionKeyList(keys).Have(a.Key()) {
					return ofp4.Error{
						Type: ofp4.OFPET_BAD_ACTION,
						Code: ofp4.OFPBAC_BAD_TYPE,
					}
				}
			}
			for k, _ := range entry.instWrite.exp {
				if !actionKeyList(keys).Have(k) {
					return ofp4.Error{
						Type: ofp4.OFPET_BAD_ACTION,
						Code: ofp4.OFPBAC_BAD_TYPE,
					}
				}
			}
		}
	}

	for _, insts := range entry.instExp {
		for _, inst := range insts {
			if instKeys != nil && !instKeys.Have(inst.experimenterKey) {
				return ofp4.Error{
					Type: ofp4.OFPET_BAD_INSTRUCTION,
					Code: ofp4.OFPBIC_UNSUP_INST,
				}
			}
		}
	}

	if entry.instMeter != 0 {
		if instKeys != nil && !instKeys.Have(uint16(ofp4.OFPIT_METER)) {
			return ofp4.Error{
				Type: ofp4.OFPET_BAD_INSTRUCTION,
				Code: ofp4.OFPBIC_UNSUP_INST,
			}
		}
	}

	return nil
}
