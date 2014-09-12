package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
)

type outputToPort struct {
	data    *frame
	outPort uint32
	maxLen  uint16
	tableId uint8
	reason  uint8
}

type outputToGroup struct {
	data    *frame // there may be aditional process
	groupId uint32
}

type action interface {
	process(f *frame) (*outputToPort, *outputToGroup, error)
}

type actionOutput ofp4.ActionOutput

func (a actionOutput) process(data *frame) (*outputToPort, *outputToGroup, error) {
	return &outputToPort{
		data:    data.clone(),
		outPort: a.Port,
		maxLen:  a.MaxLen,
		reason:  ofp4.OFPR_ACTION,
	}, nil, nil
}

type actionGeneric ofp4.ActionGeneric

func (a actionGeneric) process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.useLayers()

	switch a.Type {
	default:
		return nil, nil, ofp4.Error{Type: ofp4.OFPET_BAD_ACTION, Code: ofp4.OFPBAC_BAD_TYPE}
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
			func() { // for direct exit from switch
				for _, layer := range data.layers {
					switch clayer := layer.(type) {
					case *layers.MPLS:
						clayer.TTL = ttl
						return
					case *layers.IPv4:
						clayer.TTL = ttl
						return
					case *layers.IPv6:
						clayer.HopLimit = ttl
						return
					}
				}
			}()
		}
	case ofp4.OFPAT_COPY_TTL_IN:
		var ttl uint8
		found := 0
		func() { // for direct exit from switch
			for _, layer := range data.layers {
				switch clayer := layer.(type) {
				case *layers.MPLS:
					if found > 0 {
						clayer.TTL = ttl
						return
					} else {
						ttl = clayer.TTL
						found++
					}
				case *layers.IPv4:
					if found > 0 {
						clayer.TTL = ttl
						return
					} else {
						ttl = clayer.TTL
						found++
					}
				case *layers.IPv6:
					if found > 0 {
						clayer.HopLimit = ttl
						return
					} else {
						ttl = clayer.HopLimit
						found++
					}
				}
			}
		}()
	case ofp4.OFPAT_DEC_MPLS_TTL:
		for _, layer := range data.layers {
			switch clayer := layer.(type) {
			case *layers.MPLS:
				if clayer.TTL > 0 {
					clayer.TTL--
				}
				if clayer.TTL == 0 {
					pout := &outputToPort{
						data:    data.clone(),
						outPort: ofp4.OFPP_CONTROLLER,
						maxLen:  a.MaxLen,
						reason:  ofp4.OFPR_INVALID_TTL,
					}
					// invalidate the frame
					data.serialized = data.serialized[:0]
					data.layers = nil
					return pout, nil, nil
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
						return nil, nil, errors.New("bare vlan")
					}
					base := data.layers[i-1]
					if base.LayerType() == layers.LayerTypeEthernet {
						base.(*layers.Ethernet).EthernetType = ethertype
					} else {
						return nil, nil, errors.New("unsupported")
					}
					continue
				}
			}
			buf = append(buf, layer)
		}
		if found {
			data.layers = buf
		} else {
			return nil, nil, errors.New("pop vlan failed")
		}
	case ofp4.OFPAT_DEC_NW_TTL:
		func() { // for direct exit from switch
			for _, layer := range data.layers {
				switch clayer := layer.(type) {
				case *layers.IPv4:
					if clayer.TTL > 1 {
						clayer.TTL--
					} else {
						// packet_in ?
					}
					return
				case *layers.IPv6:
					if clayer.HopLimit > 1 {
						clayer.HopLimit--
					} else {
						// packet_in ?
					}
					return
				}
			}
		}()
	case ofp4.OFPAT_POP_PBB:
		var buf []gopacket.Layer
		found := false
		for i, layer := range data.layers {
			if found == false {
				switch pbb := layer.(type) {
				case *PBB:
					found = true
					if i < 1 {
						panic("bare pbb")
					} else if eth, ok := data.layers[i-1].(*layers.Ethernet); ok {
						eth.EthernetType = pbb.Type
						eth.SrcMAC = pbb.SrcMAC
						eth.DstMAC = pbb.DstMAC
					} else {
						panic("Unsupported")
					}
					continue
				}
			}
			buf = append(buf, layer)
		}
		if found {
			data.layers = buf
		} else {
			return nil, nil, errors.New("pop vlan failed")
		}
	}
	return nil, nil, nil
}

type actionPush ofp4.ActionPush

func (a actionPush) process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.useLayers()

	var buf []gopacket.Layer
	found := false
	switch a.Type {
	case ofp4.OFPAT_PUSH_VLAN:
		for i, layer := range data.layers {
			buf = append(buf, layer)

			if found == false {
				switch layer.LayerType() {
				case layers.LayerTypeEthernet:
					eth := layer.(*layers.Ethernet)
					ethertype := eth.EthernetType
					eth.EthernetType = layers.EthernetType(a.Ethertype)

					dot1q := &layers.Dot1Q{Type: ethertype}
					if d, ok := data.layers[i+1].(*layers.Dot1Q); ok {
						dot1q.Priority = d.Priority
						dot1q.DropEligible = d.DropEligible
						dot1q.VLANIdentifier = d.VLANIdentifier
					}
					buf = append(buf, dot1q)
					found = true
				}
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
						return nil, nil, errors.New("unsupported")
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
		for _, layer := range data.layers {
			buf = append(buf, layer)
			if found == false {
				switch layer.LayerType() {
				case layers.LayerTypeEthernet:
					eth := layer.(*layers.Ethernet)
					ethertype := eth.EthernetType
					eth.EthernetType = layers.EthernetType(a.Ethertype)
					buf = append(buf, &PBB{
						DstMAC: eth.DstMAC,
						SrcMAC: eth.SrcMAC,
						Type:   ethertype,
					})
					found = true
				}
			}
		}
	default:
		return nil, nil, ofp4.Error{Type: ofp4.OFPET_BAD_ACTION, Code: ofp4.OFPBAC_BAD_TYPE}
	}
	if found {
		data.layers = buf
	} else {
		return nil, nil, errors.New("push vlan failed")
	}
	return nil, nil, nil
}

type actionPopMpls ofp4.ActionPopMpls

func (a actionPopMpls) process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.useLayers()

	var buf []gopacket.Layer
	found := false
	reparse := false
	for i, layer := range data.layers {
		if found == false {
			if layer.LayerType() == layers.LayerTypeMPLS {
				if i < 1 {
					return nil, nil, errors.New("pop mpls failed due to packet format")
				}
				base := data.layers[i-1]
				if base.LayerType() == layers.LayerTypeEthernet {
					base.(*layers.Ethernet).EthernetType = layers.EthernetType(a.Ethertype)
				} else if base.LayerType() == layers.LayerTypeDot1Q {
					base.(*layers.Dot1Q).Type = layers.EthernetType(a.Ethertype)
				} else {
					return nil, nil, errors.New("unsupported")
				}

				if t, ok := layer.(*layers.MPLS); ok {
					if t.StackBottom {
						reparse = true
					}
				}

				found = true
				continue
			}
		}
		buf = append(buf, layer)
	}
	if found {
		data.layers = buf
		if reparse {
			if serialized, err := data.data(); err != nil {
				return nil, nil, err
			} else {
				data.serialized = serialized
				data.layers = buf[:0]
			}
		}
	} else {
		return nil, nil, errors.New("pop mpls failed")
	}
	return nil, nil, nil
}

type actionSetQueue ofp4.ActionSetQueue

func (a actionSetQueue) process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.queueId = a.QueueId
	return nil, nil, nil
}

type actionMplsTtl ofp4.ActionMplsTtl

func (a actionMplsTtl) process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.useLayers()

	for _, layer := range data.layers {
		if layer.LayerType() == layers.LayerTypeMPLS {
			layer.(*layers.MPLS).TTL = a.MplsTtl
			return nil, nil, nil
		}
	}
	return nil, nil, errors.New("set mpls ttl failed")
}

type actionGroup ofp4.ActionGroup

func (a actionGroup) process(data *frame) (*outputToPort, *outputToGroup, error) {
	return nil, &outputToGroup{
		data:    data.clone(),
		groupId: a.GroupId,
	}, nil
}

type actionNwTtl ofp4.ActionNwTtl

func (a actionNwTtl) process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.useLayers()

	for _, layer := range data.layers {
		switch t := layer.(type) {
		case *layers.IPv4:
			t.TTL = a.NwTtl
			return nil, nil, nil
		case *layers.IPv6:
			t.HopLimit = a.NwTtl
			return nil, nil, nil
		}
	}
	return nil, nil, errors.New("set nw ttl failed")
}

type actionSetField ofp4.ActionSetField

func (a actionSetField) process(data *frame) (*outputToPort, *outputToGroup, error) {
	var ms matchList
	if err := ms.UnmarshalBinary(a.Field); err != nil {
		return nil, nil, err
	} else {
		for _, m := range []match(ms) {
			if err := data.setValue(m); err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, nil
}

type actionExperimenter ofp4.ActionExperimenter

func (a actionExperimenter) process(data *frame) (*outputToPort, *outputToGroup, error) {
	return nil, nil, nil
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

func (obj actionSet) process(data *frame) (pouts []*outputToPort, gouts []*outputToGroup) {
	actions := map[uint16]action(obj)
	for _, k := range actionSetOrder {
		if act, ok := actions[k]; ok {
			if pout, gout, err := act.process(data); err != nil {
				log.Print(err)
			} else {
				if pout != nil {
					pouts = append(pouts, pout)
				}
				if gout != nil {
					gouts = append(gouts, gout)
				}
			}
			if data.isInvalid() {
				return
			}
			if k == ofp4.OFPAT_GROUP {
				break // skip OFPAT_OUTPUT if OFPAT_GROUP found
			}
		}
	}
	return
}
