package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
)

// Experimenter instructions and actions are identified by (experimenter-id, experimenter-type) pair.
type experimenterKey struct {
	Experimenter uint32
	ExpType      uint32
}

type experimenterProp struct {
	experimenterKey
	Data []byte
}

// Static types are
// 1) uint16 for OFPIT_*
// 2) uint32 for OFPIT_EXPERIMENTER experimenter
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
// 2) uint32 for OFPAT_EXPERIMENTER experimenter
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

type oxmExperimenterKey [2]uint32

// Static types are
// 1) uint32 for OFPXMC_OPENFLOW_BASIC oxm field
// 2) oxmExperimenterKey for OFPXMC_EXPERIMENTER oxm field
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
		Experimenter: experimenter,
		ExpType:      expType,
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

func (self flowTableFeature) exportProps() []byte {
	var props []byte

	instExport := func(pType uint16, keys []instructionKey) {
		if keys == nil {
			return
		}
		var ids []byte
		for _, key := range keys {
			switch k := key.(type) {
			case uint16:
				ids = append(ids, ofp4.MakeInstruction(k)...)
			case uint32:
				ids = append(ids, ofp4.MakeInstructionExperimenter(k)...)
			default:
				panic("unexpected instruction key type")
			}
		}
		props = append(props, ofp4.MakeTableFeaturePropInstructions(pType, ids)...)
	}
	instExport(ofp4.OFPTFPT_INSTRUCTIONS, self.hit.inst)
	instExport(ofp4.OFPTFPT_INSTRUCTIONS_MISS, self.miss.inst)

	oxmExport := func(pType uint16, keys []oxmKey) {
		if keys == nil {
			return
		}
		var ids []byte
		for _, key := range keys {
			switch k := key.(type) {
			case uint32:
				ids = append(ids, ofp4.MakeOxm(k)...)
			case oxmExperimenterKey:
				ids = append(ids, ofp4.MakeOxmExperimenterHeader(k)...)
			default:
				panic("unknown oxm key")
			}
		}
		props = append(props, ofp4.MakeTableFeaturePropOxm(pType, ids)...)
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
		props = append(props, ofp4.MakeTableFeaturePropNextTables(pType, keys)...)
	}
	nextExport(ofp4.OFPTFPT_NEXT_TABLES, self.hit.next)
	nextExport(ofp4.OFPTFPT_NEXT_TABLES_MISS, self.miss.next)

	actionExport := func(pType uint16, keys []actionKey) {
		if keys == nil {
			return
		}
		var ids []byte
		for _, key := range keys {
			switch k := key.(type) {
			case uint16:
				ids = append(ids, ofp4.MakeActionHeader(k)...)
			case uint32:
				ids = append(ids, ofp4.MakeActionExperimenterHeader(k)...)
			default:
				panic("unexpected action key type")
			}
		}
		props = append(props, ofp4.MakeTableFeaturePropActions(pType, ids)...)
	}
	actionExport(ofp4.OFPTFPT_WRITE_ACTIONS, self.hit.writeActions)
	actionExport(ofp4.OFPTFPT_WRITE_ACTIONS_MISS, self.miss.writeActions)
	actionExport(ofp4.OFPTFPT_APPLY_ACTIONS, self.hit.applyActions)
	actionExport(ofp4.OFPTFPT_APPLY_ACTIONS_MISS, self.miss.applyActions)

	experimenterExport := func(pType uint16, exps []experimenterProp) {
		for _, exp := range exps {
			props = append(props, ofp4.MakeTableFeaturePropExperimenter(pType, exp.Experimenter, exp.ExpType, exp.Data)...)
		}
	}
	experimenterExport(ofp4.OFPTFPT_EXPERIMENTER, self.hit.experimenter)
	experimenterExport(ofp4.OFPTFPT_EXPERIMENTER_MISS, self.miss.experimenter)

	return props
}

func (self *flowTableFeature) importProps(props ofp4.TableFeaturePropHeader) error {
	for _, prop := range props.Iter() {
		switch prop.Type() {
		case ofp4.OFPTFPT_INSTRUCTIONS, ofp4.OFPTFPT_INSTRUCTIONS_MISS:
			var ids []instructionKey
			for _, inst := range ofp4.TableFeaturePropInstructions(prop).InstructionIds().Iter() {
				if inst.Type() == ofp4.OFPIT_EXPERIMENTER {
					ids = append(ids, ofp4.InstructionExperimenter(inst).Experimenter())
				} else {
					ids = append(ids, inst.Type())
				}
			}
			switch prop.Type() {
			case ofp4.OFPTFPT_INSTRUCTIONS:
				self.hit.inst = ids
			case ofp4.OFPTFPT_INSTRUCTIONS_MISS:
				self.miss.inst = ids
			}
		case ofp4.OFPTFPT_NEXT_TABLES:
			self.hit.next = ofp4.TableFeaturePropNextTables(prop).NextTableIds()
		case ofp4.OFPTFPT_NEXT_TABLES_MISS:
			self.miss.next = ofp4.TableFeaturePropNextTables(prop).NextTableIds()
		case ofp4.OFPTFPT_WRITE_ACTIONS, ofp4.OFPTFPT_WRITE_ACTIONS_MISS,
			ofp4.OFPTFPT_APPLY_ACTIONS, ofp4.OFPTFPT_APPLY_ACTIONS_MISS:
			var ids []actionKey
			for _, act := range ofp4.TableFeaturePropActions(prop).ActionIds().Iter() {
				if act.Type() == ofp4.OFPAT_EXPERIMENTER {
					ids = append(ids, ofp4.ActionExperimenterHeader(act).Experimenter())
				} else {
					ids = append(ids, act.Type())
				}
			}
			switch prop.Type() {
			case ofp4.OFPTFPT_WRITE_ACTIONS:
				self.hit.writeActions = ids
			case ofp4.OFPTFPT_WRITE_ACTIONS_MISS:
				self.miss.writeActions = ids
			case ofp4.OFPTFPT_APPLY_ACTIONS:
				self.hit.applyActions = ids
			case ofp4.OFPTFPT_APPLY_ACTIONS_MISS:
				self.miss.applyActions = ids
			}
		case ofp4.OFPTFPT_MATCH, ofp4.OFPTFPT_WILDCARDS,
			ofp4.OFPTFPT_WRITE_SETFIELD, ofp4.OFPTFPT_WRITE_SETFIELD_MISS,
			ofp4.OFPTFPT_APPLY_SETFIELD, ofp4.OFPTFPT_APPLY_SETFIELD_MISS:
			var ids []oxmKey
			for _, oxm := range ofp4.TableFeaturePropOxm(prop).OxmIds().Iter() {
				if oxm.Header().Class() == ofp4.OFPXMC_EXPERIMENTER {
					ids = append(ids, ofp4.OxmExperimenterHeader(oxm).Experimenter())
				} else {
					ids = append(ids, oxm.Header().Type())
				}
			}
			switch prop.Type() {
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
			}
		case ofp4.OFPTFPT_EXPERIMENTER, ofp4.OFPTFPT_EXPERIMENTER_MISS:
			msg := ofp4.TableFeaturePropExperimenter(prop)
			eKey := experimenterKey{
				Experimenter: msg.Experimenter(),
				ExpType:      msg.ExpType(),
			}
			if _, ok := tableHandlers[eKey]; !ok {
				return ofp4.MakeErrorMsg(
					ofp4.OFPET_TABLE_FEATURES_FAILED,
					ofp4.OFPTFFC_BAD_ARGUMENT,
				)
			}
			exp := experimenterProp{
				experimenterKey: eKey,
				Data:            msg.ExperimenterData(),
			}
			switch prop.Type() {
			case ofp4.OFPTFPT_EXPERIMENTER:
				self.hit.experimenter = append(self.hit.experimenter, exp)
			case ofp4.OFPTFPT_EXPERIMENTER_MISS:
				self.miss.experimenter = append(self.hit.experimenter, exp)
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
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_INSTRUCTION,
				ofp4.OFPBIC_UNSUP_INST,
			)
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
				return ofp4.MakeErrorMsg(
					ofp4.OFPET_BAD_INSTRUCTION,
					ofp4.OFPBIC_BAD_TABLE_ID,
				)
			}
		}
	}

	if entry.instMetadata != nil {
		if instKeys != nil && !instKeys.Have(uint16(ofp4.OFPIT_WRITE_METADATA)) {
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_INSTRUCTION,
				ofp4.OFPBIC_UNSUP_INST,
			)
		}
		if entry.instMetadata.metadata&^self.metadataWrite != 0 {
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_INSTRUCTION,
				ofp4.OFPBIC_UNSUP_METADATA,
			)
		}
		if entry.instMetadata.mask&^self.metadataWrite != 0 {
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_INSTRUCTION,
				ofp4.OFPBIC_UNSUP_METADATA_MASK,
			)
		}
	}

	if !isTableMiss && self.match != nil {
		specified := make(map[oxmKey]bool)
		for _, k := range self.match {
			specified[k] = false
		}
		for _, m := range entry.fields.basic {
			if !oxmKeyList(self.match).Have(m.Type) {
				return ofp4.MakeErrorMsg(
					ofp4.OFPET_BAD_MATCH,
					ofp4.OFPBMC_BAD_FIELD,
				)
			}
			if specified[m.Type] {
				return ofp4.MakeErrorMsg(
					ofp4.OFPET_BAD_MATCH,
					ofp4.OFPBMC_DUP_FIELD,
				)
			} else {
				specified[m.Type] = true
			}
		}
		for key, _ := range entry.fields.exp {
			if !oxmKeyList(self.match).Have(key) {
				return ofp4.MakeErrorMsg(
					ofp4.OFPET_BAD_MATCH,
					ofp4.OFPBMC_BAD_FIELD,
				)
			}
			specified[key] = true
		}
		for _, k := range self.wildcards {
			specified[k] = true
		}
		for _, v := range specified {
			if !v {
				return ofp4.MakeErrorMsg(
					ofp4.OFPET_BAD_MATCH,
					ofp4.OFPBMC_BAD_WILDCARDS,
				)
			}
		}
	}

	if len([]action(entry.instApply)) > 0 {
		if instKeys != nil && !instKeys.Have(uint16(ofp4.OFPIT_APPLY_ACTIONS)) {
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_INSTRUCTION,
				ofp4.OFPBIC_UNSUP_INST,
			)
		}
		var keys []actionKey
		if isTableMiss && self.miss.applyActions != nil {
			keys = self.miss.applyActions
		} else if self.hit.applyActions != nil {
			keys = self.hit.applyActions
		}
		if keys != nil {
			for _, act := range []action(entry.instApply) {
				aKey := act.Key()
				if !actionKeyList(keys).Have(aKey) {
					return ofp4.MakeErrorMsg(
						ofp4.OFPET_BAD_ACTION,
						ofp4.OFPBAC_BAD_TYPE,
					)
				}
			}
			// XXX: Experimenter
		}
	}

	if entry.instWrite.Len() > 0 {
		if instKeys != nil && !instKeys.Have(uint16(ofp4.OFPIT_WRITE_ACTIONS)) {
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_INSTRUCTION,
				ofp4.OFPBIC_UNSUP_INST,
			)
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
					return ofp4.MakeErrorMsg(
						ofp4.OFPET_BAD_ACTION,
						ofp4.OFPBAC_BAD_TYPE,
					)
				}
			}
			for k, _ := range entry.instWrite.exp {
				if !actionKeyList(keys).Have(k) {
					return ofp4.MakeErrorMsg(
						ofp4.OFPET_BAD_ACTION,
						ofp4.OFPBAC_BAD_TYPE,
					)
				}
			}
		}
	}

	for _, insts := range entry.instExp {
		for _, inst := range insts {
			if instKeys != nil && !instKeys.Have(inst.Experimenter) {
				return ofp4.MakeErrorMsg(
					ofp4.OFPET_BAD_INSTRUCTION,
					ofp4.OFPBIC_UNSUP_INST,
				)
			}
		}
	}

	if entry.instMeter != 0 {
		if instKeys != nil && !instKeys.Have(uint16(ofp4.OFPIT_METER)) {
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_INSTRUCTION,
				ofp4.OFPBIC_UNSUP_INST,
			)
		}
	}

	return nil
}
