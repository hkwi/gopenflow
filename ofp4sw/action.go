package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
)

const (
	ACTION_ORDER_FIRST_TO_TTLIN = iota
	ACTION_ORDER_TTLIN_TO_POP
	ACTION_ORDER_POP_TO_PUSHMPLS
	ACTION_ORDER_PUSHMPLS_TO_PUSHPBB
	ACTION_ORDER_PUSHPBB_TO_PUSHVLAN
	ACTION_ORDER_PUSHVLAN_TO_TTLOUT
	ACTION_ORDER_TTLOUT_TO_DEC
	ACTION_ORDER_DEC_TO_SET
	ACTION_ORDER_SET_TO_QOS
	ACTION_ORDER_QOS_TO_GROUP
	ACTION_ORDER_GROUP_TO_OUTPUT
	ACTION_ORDER_OUTPUT_TO_LAST
)

/*
AddActionHandler registers this ActionHandler.
*/
type ActionHandler interface {
	Order() int
	Execute(frame Frame, actionData []byte) (Frame, error)
}

var actionHandlers map[experimenterKey]ActionHandler = make(map[experimenterKey]ActionHandler)

func AddActionHandler(experimenter uint32, expType uint32, handle ActionHandler) {
	actionHandlers[experimenterKey{
		Id:   experimenter,
		Type: expType,
	}] = handle
}

type outputToPort struct {
	data      *frame
	outPort   uint32
	maxLen    uint16
	tableId   uint8
	reason    uint8
	tableMiss bool
}

type outputToGroup struct {
	data    *frame // there may be aditional process
	groupId uint32
}

type action interface {
	Key() actionKey
	process(f *frame) (*outputToPort, *outputToGroup, error)
}

type actionOutput ofp4.ActionOutput

func (self actionOutput) Key() actionKey {
	return uint16(ofp4.OFPAT_OUTPUT)
}

func (a actionOutput) process(data *frame) (*outputToPort, *outputToGroup, error) {
	return &outputToPort{
		data:    data.clone(),
		outPort: a.Port,
		maxLen:  a.MaxLen,
		reason:  ofp4.OFPR_ACTION,
	}, nil, nil
}

type actionGeneric ofp4.ActionGeneric

func (self actionGeneric) Key() actionKey {
	return self.Type
}

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

func (self actionPush) Key() actionKey {
	return self.Type
}

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

func (self actionPopMpls) Key() actionKey {
	return uint16(ofp4.OFPAT_POP_MPLS)
}

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

func (self actionSetQueue) Key() actionKey {
	return uint16(ofp4.OFPAT_SET_QUEUE)
}

func (a actionSetQueue) process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.queueId = a.QueueId
	return nil, nil, nil
}

type actionMplsTtl ofp4.ActionMplsTtl

func (self actionMplsTtl) Key() actionKey {
	return uint16(ofp4.OFPAT_SET_MPLS_TTL)
}

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

func (self actionGroup) Key() actionKey {
	return uint16(ofp4.OFPAT_GROUP)
}

func (a actionGroup) process(data *frame) (*outputToPort, *outputToGroup, error) {
	return nil, &outputToGroup{
		data:    data.clone(),
		groupId: a.GroupId,
	}, nil
}

type actionNwTtl ofp4.ActionNwTtl

func (self actionNwTtl) Key() actionKey {
	return uint16(ofp4.OFPAT_SET_NW_TTL)
}

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

func (self actionSetField) Key() actionKey {
	return uint16(ofp4.OFPAT_SET_FIELD)
}

func (a actionSetField) process(data *frame) (*outputToPort, *outputToGroup, error) {
	var ms match
	if err := ms.UnmarshalBinary(a.Field); err != nil {
		return nil, nil, err
	} else {
		for _, m := range ms.basic {
			if err := data.setValue(m); err != nil {
				return nil, nil, err
			}
		}
		for key, oxm := range ms.exp {
			if handler, ok := oxmHandlers[key]; ok {
				var pkt Frame
				if err := pkt.pull(*data); err != nil {
					return nil, nil, err
				}
				if newPkt, err := handler.SetField(pkt, oxm); err != nil {
					return nil, nil, err
				} else if err := newPkt.push(data); err != nil {
					return nil, nil, err
				}
			} else {
				return nil, nil, ofp4.Error{
					Type: ofp4.OFPBAC_BAD_EXPERIMENTER,
					Code: ofp4.OFPBAC_BAD_TYPE,
				}
			}
		}
	}
	return nil, nil, nil
}

type actionExperimenter struct {
	experimenterKey
	Handler ActionHandler
	Data    []byte
}

func (self actionExperimenter) Key() actionKey {
	return self.experimenterKey
}

func (self actionExperimenter) process(data *frame) (*outputToPort, *outputToGroup, error) {
	var pkt Frame
	if err := pkt.pull(*data); err != nil {
		return nil, nil, err
	}
	if newPkt, err := self.Handler.Execute(pkt, self.Data); err != nil {
		return nil, nil, err
	} else if err := newPkt.push(data); err != nil {
		return nil, nil, err
	}
	return nil, nil, nil
}

type actionList []action

func (self *actionList) fromMessage(msg []ofp4.Action) error {
	actions := make([]action, len(msg))
	for i, mact := range msg {
		switch act := mact.(type) {
		default:
			return errors.New("unknown ofp4.Action type")
		case ofp4.ActionGeneric:
			actions[i] = (actionGeneric)(act)
		case ofp4.ActionOutput:
			actions[i] = (actionOutput)(act)
		case ofp4.ActionMplsTtl:
			actions[i] = (actionMplsTtl)(act)
		case ofp4.ActionPush:
			actions[i] = (actionPush)(act)
		case ofp4.ActionPopMpls:
			actions[i] = (actionPopMpls)(act)
		case ofp4.ActionSetQueue:
			actions[i] = (actionSetQueue)(act)
		case ofp4.ActionGroup:
			actions[i] = (actionGroup)(act)
		case ofp4.ActionNwTtl:
			actions[i] = (actionNwTtl)(act)
		case ofp4.ActionSetField:
			actions[i] = (actionSetField)(act)
		case ofp4.ActionExperimenter:
			key := experimenterKey{
				Id:   act.Experimenter,
				Type: act.ExpType,
			}
			if handler, ok := actionHandlers[key]; ok {
				actions[i] = actionExperimenter{
					experimenterKey: key,
					Handler:         handler,
					Data:            act.Data,
				}
			} else {
				for k, _ := range actionHandlers {
					if k.Id == act.Experimenter {
						return ofp4.Error{
							Type: ofp4.OFPET_BAD_ACTION,
							Code: ofp4.OFPBAC_BAD_EXP_TYPE,
						}
					}
				}
				return ofp4.Error{
					Type: ofp4.OFPET_BAD_ACTION,
					Code: ofp4.OFPBAC_BAD_EXPERIMENTER,
				}
			}
		}
	}
	*self = actionList(actions)
	return nil
}

func (self actionList) toMessage() ([]ofp4.Action, error) {
	actions := make([]ofp4.Action, len([]action(self)))
	for i, mact := range []action(self) {
		switch act := mact.(type) {
		default:
			return nil, ofp4.Error{
				Type: ofp4.OFPET_BAD_ACTION,
				Code: ofp4.OFPBAC_BAD_TYPE,
			}
		case actionGeneric:
			actions[i] = ofp4.ActionGeneric(act)
		case actionOutput:
			actions[i] = ofp4.ActionOutput(act)
		case actionMplsTtl:
			actions[i] = ofp4.ActionMplsTtl(act)
		case actionPush:
			actions[i] = ofp4.ActionPush(act)
		case actionPopMpls:
			actions[i] = ofp4.ActionPopMpls(act)
		case actionSetQueue:
			actions[i] = ofp4.ActionSetQueue(act)
		case actionGroup:
			actions[i] = ofp4.ActionGroup(act)
		case actionNwTtl:
			actions[i] = ofp4.ActionNwTtl(act)
		case actionSetField:
			actions[i] = ofp4.ActionSetField(act)
		case actionExperimenter:
			actions[i] = ofp4.ActionExperimenter{
				Experimenter: act.Id,
				ExpType:      act.Type,
				Data:         act.Data,
			}
		}
	}
	return actions, nil
}

type actionSet struct {
	hash map[actionKey]action
	exp  map[int][]actionExperimenter
}

func makeActionSet() actionSet {
	return actionSet{
		hash: make(map[actionKey]action),
		exp:  make(map[int][]actionExperimenter),
	}
}

func (self actionSet) Len() int {
	return len(self.hash)
}

func (self actionSet) Clear() {
	for k, _ := range self.hash {
		delete(self.hash, k)
	}
	for k, _ := range self.exp {
		delete(self.exp, k)
	}
}

/*
Limitation: basic oxm fields could be write-out by the new writeActions,
while experimenter oxm fields are not. This is because we'd accept
multiple oxm tlvs for a specific experimenter oxm field, for exp_type
that inner oxm payload would have.
*/
func (self actionSet) Write(rule actionSet) {
	for k, v := range rule.hash {
		self.hash[k] = v
	}
	for k, exps := range rule.exp {
		self.exp[k] = append(self.exp[k], exps...)
	}
}

func (self actionSet) fromMessage(msg []ofp4.Action) error {
	var alist actionList
	if err := alist.fromMessage(msg); err != nil {
		return err
	}
	for k, _ := range self.hash {
		delete(self.hash, k)
	}
	for k, _ := range self.exp {
		delete(self.exp, k)
	}
	for _, v := range []action(alist) {
		key := v.Key()
		if _, ok := self.hash[key]; !ok {
			self.hash[key] = v
			if e, ok := v.(actionExperimenter); ok {
				o := e.Handler.Order()
				self.exp[o] = append(self.exp[o], e)
			}
		} else {
			return errors.New("duplicate action found in action set.")
		}
	}
	return nil
}

func (self actionSet) toMessage() ([]ofp4.Action, error) {
	actions := make([]action, 0, len(self.hash))
	for _, v := range self.hash {
		actions = append(actions, v)
	}
	return actionList(actions).toMessage()
}

func (self actionSet) process(data *frame) (pouts []*outputToPort, gouts []*outputToGroup) {
	builtinExecute := func(key uint16) (stop bool) {
		if act, ok := self.hash[key]; ok {
			if pout, gout, err := act.process(data); err != nil {
				log.Print(err)
				return true
			} else {
				if pout != nil {
					pouts = append(pouts, pout)
				}
				if gout != nil {
					gouts = append(gouts, gout)
				}
			}
			if key == ofp4.OFPAT_GROUP {
				return true // skip OFPAT_OUTPUT if OFPAT_GROUP found
			}
		}
		if data.isInvalid() {
			return true
		}
		return false
	}
	expExecute := func(order int) (stop bool) {
		for _, act := range self.exp[order] {
			if pout, gout, err := act.process(data); err != nil {
				log.Print(err)
				return true
			} else {
				if pout != nil {
					pouts = append(pouts, pout)
				}
				if gout != nil {
					gouts = append(gouts, gout)
				}
			}
		}
		return false
	}

	if expExecute(ACTION_ORDER_FIRST_TO_TTLIN) {
		return
	}
	if builtinExecute(ofp4.OFPAT_COPY_TTL_IN) {
		return
	}
	if expExecute(ACTION_ORDER_TTLIN_TO_POP) {
		return
	}
	if builtinExecute(ofp4.OFPAT_POP_VLAN) {
		return
	}
	if builtinExecute(ofp4.OFPAT_POP_MPLS) {
		return
	}
	if builtinExecute(ofp4.OFPAT_POP_PBB) {
		return
	}
	if expExecute(ACTION_ORDER_POP_TO_PUSHMPLS) {
		return
	}
	if builtinExecute(ofp4.OFPAT_PUSH_MPLS) {
		return
	}
	if expExecute(ACTION_ORDER_PUSHMPLS_TO_PUSHPBB) {
		return
	}
	if builtinExecute(ofp4.OFPAT_PUSH_PBB) {
		return
	}
	if expExecute(ACTION_ORDER_PUSHPBB_TO_PUSHVLAN) {
		return
	}
	if builtinExecute(ofp4.OFPAT_PUSH_VLAN) {
		return
	}
	if expExecute(ACTION_ORDER_PUSHVLAN_TO_TTLOUT) {
		return
	}
	if builtinExecute(ofp4.OFPAT_COPY_TTL_OUT) {
		return
	}
	if expExecute(ACTION_ORDER_TTLOUT_TO_DEC) {
		return
	}
	if builtinExecute(ofp4.OFPAT_DEC_MPLS_TTL) {
		return
	}
	if builtinExecute(ofp4.OFPAT_DEC_NW_TTL) {
		return
	}
	if expExecute(ACTION_ORDER_DEC_TO_SET) {
		return
	}
	if builtinExecute(ofp4.OFPAT_SET_MPLS_TTL) {
		return
	}
	if builtinExecute(ofp4.OFPAT_SET_NW_TTL) {
		return
	}
	if builtinExecute(ofp4.OFPAT_SET_FIELD) {
		return
	}
	if expExecute(ACTION_ORDER_SET_TO_QOS) {
		return
	}
	if builtinExecute(ofp4.OFPAT_SET_QUEUE) {
		return
	}
	if expExecute(ACTION_ORDER_QOS_TO_GROUP) {
		return
	}
	if builtinExecute(ofp4.OFPAT_GROUP) {
		return
	}
	if expExecute(ACTION_ORDER_GROUP_TO_OUTPUT) {
		return
	}
	if builtinExecute(ofp4.OFPAT_OUTPUT) {
		return
	}
	if expExecute(ACTION_ORDER_OUTPUT_TO_LAST) {
		return
	}
	return
}
