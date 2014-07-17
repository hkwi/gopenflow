package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
)

type action interface {
	process(f *frame, pipe Pipeline) (flowEntryResult, error)
}

type actionOutput ofp4.ActionOutput

func (a actionOutput) process(data *frame, pipe Pipeline) (flowEntryResult, error) {
	buf, err := data.data()
	if err != nil {
		log.Print(err)
		buf = nil // inform output port as tx_error that packet was broken by actions
	}
	ret := flowEntryResult{
		outputs: []packetOut{
			packetOut{
				outPort: a.Port,
				queueId: data.queueId,
				data:    buf,
				maxLen:  a.MaxLen,
				match:   data.match,
			},
		},
	}
	return ret, nil
}

type actionGeneric ofp4.ActionGeneric

func (a actionGeneric) process(data *frame, pipe Pipeline) (ret flowEntryResult, err error) {
	switch a.Type {
	default:
		err = ofp4.Error{Type: ofp4.OFPET_BAD_ACTION, Code: ofp4.OFPBAC_BAD_TYPE}
		return
	case ofp4.OFPAT_COPY_TTL_OUT:
		var ttl uint8
		found := 0
		for _, layer := range data.layers {
			switch clayer := layer.(type) {
			case *layers.MPLS:
				ttl = clayer.TTL
				found++
			case *layers.IPv4:
				ttl = clayer.TTL
				found++
			case *layers.IPv6:
				ttl = clayer.HopLimit
				found++
			}
			if found == 2 {
				break // capture the second value
			}
		}
		if found > 1 {
			for _, layer := range data.layers {
				switch clayer := layer.(type) {
				case *layers.MPLS:
					clayer.TTL = ttl
					break
				case *layers.IPv4:
					clayer.TTL = ttl
					break
				case *layers.IPv6:
					clayer.HopLimit = ttl
					break
				}
			}
		}
	case ofp4.OFPAT_COPY_TTL_IN:
		var ttl uint8
		found := 0
		for _, layer := range data.layers {
			switch clayer := layer.(type) {
			case *layers.MPLS:
				if found > 0 {
					clayer.TTL = ttl
					break
				} else {
					ttl = clayer.TTL
					found++
				}
			case *layers.IPv4:
				if found > 0 {
					clayer.TTL = ttl
					break
				} else {
					ttl = clayer.TTL
					found++
				}
			case *layers.IPv6:
				if found > 0 {
					clayer.HopLimit = ttl
					break
				} else {
					ttl = clayer.HopLimit
					found++
				}
			}
		}
	case ofp4.OFPAT_DEC_MPLS_TTL:
		for _, layer := range data.layers {
			switch clayer := layer.(type) {
			case *layers.MPLS:
				if clayer.TTL > 1 {
					clayer.TTL--
				} else {
					// packet_in ?
				}
			}
		}
	case ofp4.OFPAT_POP_VLAN:
		var buf []gopacket.Layer
		found := false
		for i, layer := range data.layers {
			if found == false {
				var ethertype layers.EthernetType
				switch layer.LayerType() {
				case layers.LayerTypeDot1Q:
					ethertype = layer.(*layers.Dot1Q).Type
					found = true
				}
				if found {
					if i < 1 {
						err = errors.New("bare vlan")
						return
					}
					base := data.layers[i-1]
					if base.LayerType() == layers.LayerTypeEthernet {
						base.(*layers.Ethernet).EthernetType = ethertype
					} else {
						err = errors.New("unsupported")
						panic(err)
					}
					continue
				}
			}
			buf = append(buf, layer)
		}
		if found {
			data.layers = buf
		} else {
			err = errors.New("pop vlan failed")
		}
	case ofp4.OFPAT_DEC_NW_TTL:
		for _, layer := range data.layers {
			switch clayer := layer.(type) {
			case *layers.IPv4:
				if clayer.TTL > 1 {
					clayer.TTL--
				} else {
					// packet_in ?
				}
				break
			case *layers.IPv6:
				if clayer.HopLimit > 1 {
					clayer.HopLimit--
				} else {
					// packet_in ?
				}
				break
			}
		}
	case ofp4.OFPAT_POP_PBB:
		err = ofp4.Error{Type: ofp4.OFPET_BAD_ACTION, Code: ofp4.OFPBAC_BAD_TYPE}
		return
	}
	return
}

type actionPush ofp4.ActionPush

func (a actionPush) process(data *frame, pipe Pipeline) (ret flowEntryResult, err error) {
	var buf []gopacket.Layer
	found := false
	switch a.Type {
	case ofp4.OFPAT_PUSH_VLAN:
		for _, layer := range data.layers {
			var ethertype layers.EthernetType
			if found == false {
				switch layer.LayerType() {
				case layers.LayerTypeEthernet:
					eth := layer.(*layers.Ethernet)
					ethertype = eth.EthernetType
					eth.EthernetType = layers.EthernetType(a.Ethertype)
					found = true
				}
			}
			buf = append(buf, layer)
			if found {
				buf = append(buf, &layers.Dot1Q{Type: ethertype})
			}
		}
	case ofp4.OFPAT_PUSH_MPLS:
		for i, layer := range data.layers {
			if found == false {
				var ttl uint8
				var base gopacket.Layer
				var mpls *layers.MPLS

				switch t := layer.(type) {
				case *layers.MPLS:
					base = data.layers[i-1]
					ttl = t.TTL
					mpls = t
				case *layers.IPv4:
					base = data.layers[i-1]
					ttl = t.TTL
				case *layers.IPv6:
					base = data.layers[i-1]
					ttl = t.HopLimit
				case *layers.ARP:
					base = data.layers[i-1]
				}
				if base != nil {
					if base.LayerType() == layers.LayerTypeEthernet {
						base.(*layers.Ethernet).EthernetType = layers.EthernetType(a.Ethertype)
					} else if base.LayerType() == layers.LayerTypeDot1Q {
						base.(*layers.Dot1Q).Type = layers.EthernetType(a.Ethertype)
					} else {
						err = errors.New("unsupported")
						return
					}
					if mpls != nil {
						buf = append(buf, &layers.MPLS{
							Label:        mpls.Label,
							TrafficClass: mpls.TrafficClass,
							StackBottom:  false,
							TTL:          ttl,
						})
					} else {
						buf = append(buf, &layers.MPLS{
							StackBottom: true,
							TTL:         ttl,
						})
					}
					found = true
				}
			}
			buf = append(buf, layer)
		}
	case ofp4.OFPAT_PUSH_PBB:
		err = ofp4.Error{Type: ofp4.OFPET_BAD_ACTION, Code: ofp4.OFPBAC_BAD_TYPE}
		return
	default:
		err = ofp4.Error{Type: ofp4.OFPET_BAD_ACTION, Code: ofp4.OFPBAC_BAD_TYPE}
		return
	}
	if found {
		data.layers = buf
	} else {
		err = errors.New("push vlan failed")
	}
	return
}

type actionPopMpls ofp4.ActionPopMpls

func (a actionPopMpls) process(data *frame, pipe Pipeline) (ret flowEntryResult, err error) {
	var buf []gopacket.Layer
	found := false
	for i, layer := range data.layers {
		if found == false {
			if layer.LayerType() == layers.LayerTypeMPLS {
				if i < 1 {
					err = errors.New("pop mpls failed due to packet format")
					return
				}
				base := data.layers[i-1]
				if base.LayerType() == layers.LayerTypeEthernet {
					base.(*layers.Ethernet).EthernetType = layers.EthernetType(a.Ethertype)
				} else if base.LayerType() == layers.LayerTypeDot1Q {
					base.(*layers.Dot1Q).Type = layers.EthernetType(a.Ethertype)
				} else {
					err = errors.New("unsupported")
					return
				}
				found = true
				continue
			}
		}
		buf = append(buf, layer)
	}
	if found {
		data.layers = buf
	} else {
		err = errors.New("pop mpls failed")
	}
	return
}

type actionSetQueue ofp4.ActionSetQueue

func (a actionSetQueue) process(data *frame, pipe Pipeline) (ret flowEntryResult, err error) {
	data.queueId = a.QueueId
	return
}

type actionMplsTtl ofp4.ActionMplsTtl

func (a actionMplsTtl) process(data *frame, pipe Pipeline) (ret flowEntryResult, err error) {
	for _, layer := range data.layers {
		if layer.LayerType() == layers.LayerTypeMPLS {
			layer.(*layers.MPLS).TTL = a.MplsTtl
			return
		}
	}
	err = errors.New("set mpls ttl failed")
	return
}

type actionGroup ofp4.ActionGroup

func (a actionGroup) process(data *frame, pipe Pipeline) (ret flowEntryResult, err error) {
	ret = flowEntryResult{
		groups: []groupOut{
			groupOut{
				groupId: a.GroupId,
				data:    *data,
			},
		},
	}
	return
}

type actionNwTtl ofp4.ActionNwTtl

func (a actionNwTtl) process(data *frame, pipe Pipeline) (ret flowEntryResult, err error) {
	for _, layer := range data.layers {
		switch t := layer.(type) {
		case *layers.IPv4:
			t.TTL = a.NwTtl
			return
		case *layers.IPv6:
			t.HopLimit = a.NwTtl
			return
		}
	}
	err = errors.New("set nw ttl failed")
	return
}

type actionSetField ofp4.ActionSetField

func (a actionSetField) process(data *frame, pipe Pipeline) (flowEntryResult, error) {
	var ret flowEntryResult
	var ms matchList
	if err := ms.UnmarshalBinary(a.Field); err != nil {
		return ret, err
	} else {
		for _, m := range []match(ms) {
			if err := data.setValue(m); err != nil {
				return ret, err
			}
		}
	}
	return ret, nil
}

type actionExperimenter ofp4.ActionExperimenter

func (a actionExperimenter) process(data *frame, pipe Pipeline) (ret flowEntryResult, err error) {
	return
}

type actionList []action

func (a *actionList) fromMessage(msg []ofp4.Action) error {
	actions := make([]action, len(msg))
	for i, mact := range msg {
		switch act := mact.(type) {
		default:
			return errors.New("unknown action")
			continue
		case *ofp4.ActionGeneric:
			actions[i] = (*actionGeneric)(act)
		case *ofp4.ActionOutput:
			actions[i] = (*actionOutput)(act)
		case *ofp4.ActionMplsTtl:
			actions[i] = (*actionMplsTtl)(act)
		case *ofp4.ActionPush:
			actions[i] = (*actionPush)(act)
		case *ofp4.ActionPopMpls:
			actions[i] = (*actionPopMpls)(act)
		case *ofp4.ActionSetQueue:
			actions[i] = (*actionSetQueue)(act)
		case *ofp4.ActionGroup:
			actions[i] = (*actionGroup)(act)
		case *ofp4.ActionNwTtl:
			actions[i] = (*actionNwTtl)(act)
		case *ofp4.ActionSetField:
			actions[i] = (*actionSetField)(act)
		case *ofp4.ActionExperimenter:
			actions[i] = (*actionExperimenter)(act)
		}
	}
	*a = actionList(actions)
	return nil
}

func (a actionList) toMessage() (actions []ofp4.Action, err error) {
	actions = make([]ofp4.Action, len([]action(a)))
	for i, mact := range []action(a) {
		switch act := mact.(type) {
		default:
			err = ofp4.Error{Type: ofp4.OFPET_BAD_INSTRUCTION, Code: ofp4.OFPBIC_UNKNOWN_INST}
		case *actionGeneric:
			actions[i] = (*ofp4.ActionGeneric)(act)
		case *actionOutput:
			actions[i] = (*ofp4.ActionOutput)(act)
		case *actionMplsTtl:
			actions[i] = (*ofp4.ActionMplsTtl)(act)
		case *actionPush:
			actions[i] = (*ofp4.ActionPush)(act)
		case *actionPopMpls:
			actions[i] = (*ofp4.ActionPopMpls)(act)
		case *actionSetQueue:
			actions[i] = (*ofp4.ActionSetQueue)(act)
		case *actionGroup:
			actions[i] = (*ofp4.ActionGroup)(act)
		case *actionNwTtl:
			actions[i] = (*ofp4.ActionNwTtl)(act)
		case *actionSetField:
			actions[i] = (*ofp4.ActionSetField)(act)
		case *actionExperimenter:
			actions[i] = (*ofp4.ActionExperimenter)(act)
		}
	}
	return
}

type actionSet map[uint16]action

func (a *actionSet) fromMessage(msg []ofp4.Action) error {
	actions := make(map[uint16]action)
	for _, mact := range msg {
		switch act := mact.(type) {
		default:
			return ofp4.Error{ofp4.OFPET_BAD_ACTION, ofp4.OFPBAC_BAD_TYPE, nil}
		case *ofp4.ActionGeneric:
			actions[act.Type] = (*actionGeneric)(act)
		case *ofp4.ActionOutput:
			actions[ofp4.OFPAT_OUTPUT] = (*actionOutput)(act)
		case *ofp4.ActionMplsTtl:
			actions[ofp4.OFPAT_SET_MPLS_TTL] = (*actionMplsTtl)(act)
		case *ofp4.ActionPush:
			actions[act.Type] = (*actionPush)(act)
		case *ofp4.ActionPopMpls:
			actions[ofp4.OFPAT_POP_MPLS] = (*actionPopMpls)(act)
		case *ofp4.ActionSetQueue:
			actions[ofp4.OFPAT_SET_QUEUE] = (*actionSetQueue)(act)
		case *ofp4.ActionGroup:
			actions[ofp4.OFPAT_GROUP] = (*actionGroup)(act)
		case *ofp4.ActionNwTtl:
			actions[ofp4.OFPAT_SET_NW_TTL] = (*actionNwTtl)(act)
		case *ofp4.ActionSetField:
			actions[ofp4.OFPAT_SET_FIELD] = (*actionSetField)(act)
		case *ofp4.ActionExperimenter: // XXX: should have multiple experimenter in an actionSet?
			actions[ofp4.OFPAT_EXPERIMENTER] = (*actionExperimenter)(act)
		}
	}
	*a = actionSet(actions)
	return nil
}

func (a actionSet) toMessage() (actions []ofp4.Action, err error) {
	actions = make([]ofp4.Action, len(map[uint16]action(a)))
	i := 0
	for _, mact := range map[uint16]action(a) {
		switch act := mact.(type) {
		default:
			err = ofp4.Error{ofp4.OFPET_BAD_ACTION, ofp4.OFPBAC_BAD_TYPE, nil}
			return
		case *actionGeneric:
			actions[i] = (*ofp4.ActionGeneric)(act)
		case *actionOutput:
			actions[i] = (*ofp4.ActionOutput)(act)
		case *actionMplsTtl:
			actions[i] = (*ofp4.ActionMplsTtl)(act)
		case *actionPush:
			actions[i] = (*ofp4.ActionPush)(act)
		case *actionPopMpls:
			actions[i] = (*ofp4.ActionPopMpls)(act)
		case *actionSetQueue:
			actions[i] = (*ofp4.ActionSetQueue)(act)
		case *actionGroup:
			actions[i] = (*ofp4.ActionGroup)(act)
		case *actionNwTtl:
			actions[i] = (*ofp4.ActionNwTtl)(act)
		case *actionSetField:
			actions[i] = (*ofp4.ActionSetField)(act)
		case *actionExperimenter: // XXX: should have multiple experimenter in an actionSet?
			actions[i] = (*ofp4.ActionExperimenter)(act)
		}
	}
	return
}

var actionSetOrder = [...]uint16{
	ofp4.OFPAT_COPY_TTL_IN,
	ofp4.OFPAT_POP_VLAN,
	ofp4.OFPAT_POP_MPLS,
	ofp4.OFPAT_POP_PBB,
	ofp4.OFPAT_PUSH_MPLS,
	ofp4.OFPAT_PUSH_PBB,
	ofp4.OFPAT_PUSH_VLAN,
	ofp4.OFPAT_COPY_TTL_OUT,
	ofp4.OFPAT_DEC_MPLS_TTL,
	ofp4.OFPAT_DEC_NW_TTL,
	ofp4.OFPAT_SET_MPLS_TTL,
	ofp4.OFPAT_SET_NW_TTL,
	ofp4.OFPAT_SET_FIELD,
	ofp4.OFPAT_SET_QUEUE,
	ofp4.OFPAT_GROUP,
	ofp4.OFPAT_OUTPUT,
}

func (obj actionSet) process(data *frame, pipe Pipeline) (result flowEntryResult) {
	actions := map[uint16]action(obj)
	fdata := data.clone()
	for _, k := range actionSetOrder {
		if act, ok := actions[k]; ok {
			if aret, err := act.process(fdata, pipe); err != nil {
				log.Print(err)
			} else {
				result.groups = append(result.groups, aret.groups...)
				result.outputs = append(result.outputs, aret.outputs...)
			}
			if k == ofp4.OFPAT_GROUP {
				break // skip OFPAT_OUTPUT if OFPAT_GROUP found
			}
		}
	}
	return
}
