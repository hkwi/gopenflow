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
	Order([]byte) int
	Execute(frame Frame, actionData []byte) (Frame, error)
}

var actionHandlers map[uint32]ActionHandler = make(map[uint32]ActionHandler)

func AddActionHandler(experimenter uint32, handle ActionHandler) {
	actionHandlers[experimenter] = handle
}

type outputToPort struct {
	data      *frame
	outPort   uint32
	maxLen    uint16
	tableId   uint8
	cookie    uint64
	reason    uint8
	tableMiss bool
}

type outputToGroup struct {
	data    *frame // there may be aditional process
	groupId uint32
}

type action interface {
	Key() actionKey
	Process(f *frame) (*outputToPort, *outputToGroup, error)
	MarshalBinary() (data []byte, err error)
}

type actionOutput struct {
	Port   uint32
	MaxLen uint16
}

func (self actionOutput) Key() actionKey {
	return uint16(ofp4.OFPAT_OUTPUT)
}

func (self actionOutput) Process(data *frame) (*outputToPort, *outputToGroup, error) {
	return &outputToPort{
		data:    data.clone(),
		outPort: self.Port,
		maxLen:  self.MaxLen,
		reason:  ofp4.OFPR_ACTION,
	}, nil, nil
}

func (self actionOutput) MarshalBinary() ([]byte, error) {
	return ofp4.MakeActionOutput(self.Port, self.MaxLen), nil
}

type actionGeneric struct {
	Type uint16
}

func (self actionGeneric) Key() actionKey {
	return self.Type
}

func (self actionGeneric) Process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.useLayers()

	switch self.Type {
	default:
		return nil, nil, ofp4.MakeErrorMsg(
			ofp4.OFPET_BAD_ACTION,
			ofp4.OFPBAC_BAD_TYPE,
		)
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

func (self actionGeneric) MarshalBinary() ([]byte, error) {
	return ofp4.MakeActionHeader(self.Type), nil
}

type actionPush struct {
	Type      uint16
	Ethertype uint16
}

func (self actionPush) Key() actionKey {
	return self.Type
}

func (self actionPush) Process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.useLayers()

	var buf []gopacket.Layer
	found := false
	switch self.Type {
	case ofp4.OFPAT_PUSH_VLAN:
		for i, layer := range data.layers {
			buf = append(buf, layer)

			if found == false {
				switch layer.LayerType() {
				case layers.LayerTypeEthernet:
					eth := layer.(*layers.Ethernet)
					ethertype := eth.EthernetType
					eth.EthernetType = layers.EthernetType(self.Ethertype)

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
						base.(*layers.Ethernet).EthernetType = layers.EthernetType(self.Ethertype)
					} else if base.LayerType() == layers.LayerTypeDot1Q {
						base.(*layers.Dot1Q).Type = layers.EthernetType(self.Ethertype)
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
					eth.EthernetType = layers.EthernetType(self.Ethertype)
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
		return nil, nil, ofp4.MakeErrorMsg(
			ofp4.OFPET_BAD_ACTION,
			ofp4.OFPBAC_BAD_TYPE,
		)
	}
	if found {
		data.layers = buf
	} else {
		return nil, nil, errors.New("push vlan failed")
	}
	return nil, nil, nil
}

func (self actionPush) MarshalBinary() ([]byte, error) {
	return ofp4.MakeActionPush(self.Type, self.Ethertype), nil
}

type actionPopMpls struct {
	Ethertype uint16
}

func (self actionPopMpls) Key() actionKey {
	return uint16(ofp4.OFPAT_POP_MPLS)
}

func (self actionPopMpls) Process(data *frame) (*outputToPort, *outputToGroup, error) {
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
					base.(*layers.Ethernet).EthernetType = layers.EthernetType(self.Ethertype)
				} else if base.LayerType() == layers.LayerTypeDot1Q {
					base.(*layers.Dot1Q).Type = layers.EthernetType(self.Ethertype)
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

func (self actionPopMpls) MarshalBinary() ([]byte, error) {
	return ofp4.MakeActionPopMpls(self.Ethertype), nil
}

type actionSetQueue struct {
	QueueId uint32
}

func (self actionSetQueue) Key() actionKey {
	return uint16(ofp4.OFPAT_SET_QUEUE)
}

func (self actionSetQueue) Process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.queueId = self.QueueId
	return nil, nil, nil
}

func (self actionSetQueue) MarshalBinary() ([]byte, error) {
	return ofp4.MakeActionSetQueue(self.QueueId), nil
}

type actionMplsTtl struct {
	MplsTtl uint8
}

func (self actionMplsTtl) Key() actionKey {
	return uint16(ofp4.OFPAT_SET_MPLS_TTL)
}

func (self actionMplsTtl) Process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.useLayers()

	for _, layer := range data.layers {
		if layer.LayerType() == layers.LayerTypeMPLS {
			layer.(*layers.MPLS).TTL = self.MplsTtl
			return nil, nil, nil
		}
	}
	return nil, nil, errors.New("set mpls ttl failed")
}

func (self actionMplsTtl) MarshalBinary() ([]byte, error) {
	return ofp4.MakeActionMplsTtl(self.MplsTtl), nil
}

type actionGroup struct {
	GroupId uint32
}

func (self actionGroup) Key() actionKey {
	return uint16(ofp4.OFPAT_GROUP)
}

func (self actionGroup) Process(data *frame) (*outputToPort, *outputToGroup, error) {
	return nil, &outputToGroup{
		data:    data.clone(),
		groupId: self.GroupId,
	}, nil
}

func (self actionGroup) MarshalBinary() ([]byte, error) {
	return ofp4.MakeActionGroup(self.GroupId), nil
}

type actionNwTtl struct {
	NwTtl uint8
}

func (self actionNwTtl) Key() actionKey {
	return uint16(ofp4.OFPAT_SET_NW_TTL)
}

func (self actionNwTtl) Process(data *frame) (*outputToPort, *outputToGroup, error) {
	data.useLayers()

	for _, layer := range data.layers {
		switch t := layer.(type) {
		case *layers.IPv4:
			t.TTL = self.NwTtl
			return nil, nil, nil
		case *layers.IPv6:
			t.HopLimit = self.NwTtl
			return nil, nil, nil
		}
	}
	return nil, nil, errors.New("set nw ttl failed")
}

func (self actionNwTtl) MarshalBinary() ([]byte, error) {
	return ofp4.MakeActionNwTtl(self.NwTtl), nil
}

type actionSetField struct {
	Field []byte
}

func (self actionSetField) Key() actionKey {
	return uint16(ofp4.OFPAT_SET_FIELD)
}

func (self actionSetField) Process(data *frame) (*outputToPort, *outputToGroup, error) {
	var ms match
	if err := ms.UnmarshalBinary(self.Field); err != nil {
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
				return nil, nil, ofp4.MakeErrorMsg(
					ofp4.OFPBAC_BAD_EXPERIMENTER,
					ofp4.OFPBAC_BAD_TYPE,
				)
			}
		}
	}
	return nil, nil, nil
}

func (self actionSetField) MarshalBinary() ([]byte, error) {
	return ofp4.MakeActionSetField(self.Field), nil
}

type actionExperimenter struct {
	Experimenter uint32
	Data         []byte
	Handler      ActionHandler
}

func (self actionExperimenter) Key() actionKey {
	return self.Experimenter
}

func (self actionExperimenter) Process(data *frame) (*outputToPort, *outputToGroup, error) {
	var pkt Frame
	if err := pkt.pull(*data); err != nil {
		return nil, nil, err
	}
	if handler, ok := actionHandlers[self.Experimenter]; ok {
		if newPkt, err := handler.Execute(pkt, self.Data); err != nil {
			return nil, nil, err
		} else if err := newPkt.push(data); err != nil {
			return nil, nil, err
		}
	} else {
		return nil, nil, errors.New("action handler not registered")
	}
	return nil, nil, nil
}

func (self actionExperimenter) MarshalBinary() ([]byte, error) {
	return ofp4.ActionExperimenterHeader(ofp4.MakeActionExperimenterHeader(self.Experimenter)).AppendData(self.Data), nil
}

type actionList []action

func (self *actionList) UnmarshalBinary(data []byte) error {
	var actions []action
	for cur := 0; cur < len(data); {
		var act action
		msg := ofp4.ActionHeader(data[cur:])
		switch msg.Type() {
		default:
			return errors.New("unknown ofp4.Action type")
		case ofp4.OFPAT_COPY_TTL_OUT,
			ofp4.OFPAT_COPY_TTL_IN,
			ofp4.OFPAT_DEC_MPLS_TTL,
			ofp4.OFPAT_POP_VLAN,
			ofp4.OFPAT_DEC_NW_TTL,
			ofp4.OFPAT_POP_PBB:
			act = actionGeneric{
				Type: msg.Type(),
			}
		case ofp4.OFPAT_OUTPUT:
			a := ofp4.ActionOutput(msg)
			act = actionOutput{
				Port:   a.Port(),
				MaxLen: a.MaxLen(),
			}
		case ofp4.OFPAT_SET_MPLS_TTL:
			act = actionMplsTtl{
				MplsTtl: ofp4.ActionMplsTtl(msg).MplsTtl(),
			}
		case ofp4.OFPAT_PUSH_VLAN,
			ofp4.OFPAT_PUSH_MPLS,
			ofp4.OFPAT_PUSH_PBB:
			act = actionPush{
				Type:      msg.Type(),
				Ethertype: ofp4.ActionPush(msg).Ethertype(),
			}
		case ofp4.OFPAT_POP_MPLS:
			act = actionPopMpls{
				Ethertype: ofp4.ActionPopMpls(msg).Ethertype(),
			}
		case ofp4.OFPAT_SET_QUEUE:
			act = actionSetQueue{
				QueueId: ofp4.ActionSetQueue(msg).QueueId(),
			}
		case ofp4.OFPAT_GROUP:
			act = actionGroup{
				GroupId: ofp4.ActionGroup(msg).GroupId(),
			}
		case ofp4.OFPAT_SET_NW_TTL:
			act = actionNwTtl{
				NwTtl: ofp4.ActionNwTtl(msg).NwTtl(),
			}
		case ofp4.OFPAT_SET_FIELD:
			act = actionSetField{
				Field: ofp4.ActionSetField(msg).Field(),
			}
		case ofp4.OFPAT_EXPERIMENTER:
			a := ofp4.ActionExperimenterHeader(msg)
			if handler, ok := actionHandlers[a.Experimenter()]; ok {
				act = actionExperimenter{
					Experimenter: a.Experimenter(),
					Data:         msg[8:],
					Handler:      handler,
				}
			} else {
				return ofp4.MakeErrorMsg(
					ofp4.OFPET_BAD_ACTION,
					ofp4.OFPBAC_BAD_EXPERIMENTER,
				)
			}
		}
		actions = append(actions, act)
		cur += msg.Len()
	}
	*self = actions
	return nil
}

func (self actionList) MarshalBinary() ([]byte, error) {
	var actions []byte
	for _, mact := range []action(self) {
		if bin, err := mact.MarshalBinary(); err != nil {
			return nil, err
		} else {
			actions = append(actions, bin...)
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

func (self actionSet) MarshalBinary() ([]byte, error) {
	var actions []byte
	for _, action := range self.hash {
		if bin, err := action.MarshalBinary(); err != nil {
			return nil, err
		} else {
			actions = append(actions, bin...)
		}
	}
	return actions, nil
}

func (self *actionSet) UnmarshalBinary(data []byte) error {
	var alist actionList
	if err := alist.UnmarshalBinary(data); err != nil {
		return err
	}
	for k, _ := range self.hash {
		delete(self.hash, k)
	}
	for k, _ := range self.exp {
		delete(self.exp, k)
	}
	for _, act := range []action(alist) {
		key := act.Key()
		if _, ok := self.hash[key]; !ok {
			self.hash[key] = act
			if exp, ok := act.(actionExperimenter); ok {
				order := exp.Handler.Order(exp.Data)
				self.exp[order] = append(self.exp[order], exp)
			}
		} else {
			return errors.New("duplicate action found in action set.")
		}
	}
	return nil
}

func (self actionSet) Process(data *frame) (pouts []*outputToPort, gouts []*outputToGroup) {
	builtinExecute := func(key uint16) (stop bool) {
		if act, ok := self.hash[key]; ok {
			if pout, gout, err := act.Process(data); err != nil {
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
			if pout, gout, err := act.Process(data); err != nil {
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
