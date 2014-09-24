package ofp4sw

import (
	"encoding"
	"github.com/hkwi/gopenflow/ofp4"
)

// Experimenter instructions and actions are identified by (experimenter-id, experimenter-type) pairwise.
type experimenterKey struct {
	Id   uint32
	Type uint32
}

type experimenterProp struct {
	experimenterKey
	Data []byte
}

// special rule here. nil means "NOT SET"
type flowTableFeatureProps struct {
	inst            []uint16          // OFPIT_
	instExp         []experimenterKey // experimenter (Id,Type)
	next            []uint8           // tableId
	writeActions    []uint16          // OFPAT_
	writeActionsExp []experimenterKey // experimenter (Id,Type)
	applyActions    []uint16          // OFPAT_
	applyActionsExp []experimenterKey // experimenter ID
	writeSetfield   []uint32          // OFPXMC_OPENFLOW_BASIC oxm field
	applySetfield   []uint32          // OFPXMC_OPENFLOW_BASIC oxm field
	experimenter    []experimenterProp
}

type flowTableFeature struct {
	name          string
	metadataMatch uint64
	metadataWrite uint64
	config        uint32
	maxEntries    uint32
	// properties
	match     []uint32 // OFPXMC_OPENFLOW_BASIC oxm field
	wildcards []uint32 // OFPXMC_OPENFLOW_BASIC oxm field
	hit       flowTableFeatureProps
	miss      flowTableFeatureProps
}

func (self *flowTableFeature) importProps(props []encoding.BinaryMarshaler) {
	for _, prop := range props {
		switch p := prop.(type) {
		case *ofp4.TableFeaturePropInstructions:
			var ids []uint16
			var exp []experimenterKey
			for _, instId := range p.InstructionIds {
				switch inst := instId.(type) {
				case *ofp4.InstructionId:
					ids = append(ids, inst.Type)
				case *ofp4.InstructionExperimenter:
					exp = append(exp, experimenterKey{
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
				self.hit.instExp = exp
			case ofp4.OFPTFPT_INSTRUCTIONS_MISS:
				self.miss.inst = ids
				self.miss.instExp = exp
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
			var ids []uint16
			var exp []experimenterKey
			for _, act := range p.ActionIds {
				switch a := act.(type) {
				case *ofp4.ActionGeneric:
					ids = append(ids, a.Type)
				case *ofp4.ActionExperimenter:
					exp = append(exp, experimenterKey{
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
				self.hit.writeActionsExp = exp
			case ofp4.OFPTFPT_WRITE_ACTIONS_MISS:
				self.miss.writeActions = ids
				self.miss.writeActionsExp = exp
			case ofp4.OFPTFPT_APPLY_ACTIONS:
				self.hit.applyActions = ids
				self.hit.applyActionsExp = exp
			case ofp4.OFPTFPT_APPLY_ACTIONS_MISS:
				self.miss.applyActions = ids
				self.miss.applyActionsExp = exp
			default:
				panic("unexpected")
			}
		case *ofp4.TableFeaturePropOxm:
			ids := make([]uint32, len(p.OxmIds))
			for i, v := range p.OxmIds {
				ids[i] = uint32(v)
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
			exp := experimenterProp{
				experimenterKey: experimenterKey{
					Id:   p.Experimenter,
					Type: p.ExpType,
				},
				Data: p.Data,
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
}
