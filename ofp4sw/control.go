package ofp4sw

import (
	"encoding"
	"encoding/binary"
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
	"math"
	"sync"
	"time"
)

type controller struct {
	lock         *sync.RWMutex
	channels     []*channelInternal
	buffer       map[uint32]*outputToPort
	nextBufferId uint32

	stats       PortStats
	config      uint32
	missSendLen uint16
	pipe        *Pipeline
}

func newController(pipe *Pipeline) *controller {
	return &controller{
		lock:        &sync.RWMutex{},
		buffer:      make(map[uint32]*outputToPort),
		missSendLen: 128,
		pipe:        pipe,
	}
}

/* OFPT_PACKET_IN async message */
func (self *controller) Outlet(pout *outputToPort) {
	// fixup
	if pout.reason == ofp4.OFPR_INVALID_TTL {
		pout.maxLen = self.missSendLen
	} else if pout.tableMiss {
		pout.reason = ofp4.OFPR_NO_MATCH
	}

	if meter := self.pipe.getMeter(ofp4.OFPM_CONTROLLER); meter != nil {
		if err := meter.process(pout.data); err != nil {
			if _, ok := err.(*packetDrop); ok {
				// no log
			} else {
				log.Println(err)
			}
			return
		}
	}
	// XXX: need to implement queue here
	var buffer_id uint32
	if err := func() error {
		self.lock.Lock()
		defer self.lock.Unlock()

		for len(self.buffer) != math.MaxUint32 {
			buffer_id = self.nextBufferId
			self.nextBufferId++
			if _, ok := self.buffer[buffer_id]; !ok {
				self.buffer[buffer_id] = pout
				return nil
			}
		}
		return errors.New("no buffer_id room")
	}(); err != nil {
		log.Println(err)
	}

	results := make([]chan error, 0, len(self.channels))
	func() {
		self.lock.RLock()
		defer self.lock.RUnlock()

		for _, channel := range self.channels {
			channel := channel
			result := make(chan error)
			results = append(results, result)
			go func() {
				result <- channel.packetIn(buffer_id, pout)
			}()
		}
	}()
	var success bool
	for _, result := range results {
		err := <-result
		if err == nil {
			success = true
			// don't break because this is a synchronous call
		}
	}

	func() {
		self.lock.Lock()
		defer self.lock.Unlock()
		if success {
			self.stats.TxPackets++
			if eth, err := pout.data.data(); err != nil {
				log.Println(err)
			} else {
				self.stats.TxBytes += uint64(len(eth))
			}
		} else {
			self.stats.TxDropped++
		}
	}()
}

/* OFPT_PORT_STATUS async message */
func (self *controller) portChange(portNo uint32, portInt portInternal) {
	results := make([]chan error, 0, len(self.channels))
	func() {
		self.lock.RLock()
		defer self.lock.RUnlock()

		for _, channel := range self.channels {
			channel := channel
			result := make(chan error)
			results = append(results, result)
			go func() {
				result <- channel.portChange(portNo, portInt)
			}()
		}
	}()
	for _, result := range results {
		_ = <-result
	}
}

/* OFPT_FLOW_REMOVED async message */
func (self controller) sendFlowRem(tableId uint8, priority uint16, flow *flowEntry, reason uint8) {
	results := make([]chan error, 0, len(self.channels))
	func() {
		self.lock.RLock()
		defer self.lock.RUnlock()

		for _, channel := range self.channels {
			channel := channel
			result := make(chan error)
			results = append(results, result)
			go func() {
				result <- channel.sendFlowRem(tableId, priority, flow, reason)
			}()
		}
	}()
	for _, result := range results {
		_ = <-result
	}
}

func (self *controller) removeChannel(channel ControlChannel) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	for i, c := range self.channels {
		if c.channel == channel {
			self.channels = append(self.channels[:i], self.channels[i+1:]...)
			return nil
		}
	}
	return errors.New("Not found")
}

func (self *controller) addChannel(channel ControlChannel) error {
	// TODO: if parent control channel was given, allocate auxiliary id
	chanInt := &channelInternal{
		close:   make(chan error),
		lock:    &sync.RWMutex{},
		channel: channel,
	}

	func() {
		self.lock.Lock()
		defer self.lock.Unlock()

		self.channels = append(self.channels, chanInt)
	}()

	if err := chanInt.hello(); err != nil {
		return err
	}

	worker := make(chan MapReducable)
	go MapReduce(worker, 4)
	go func() {
		defer close(worker)

		multipartCollect := make(map[uint32][]encoding.BinaryMarshaler)
		for {
			msg, err := channel.Ingress()
			if err != nil {
				return
			}
			var ofm ofp4.Message
			if err := ofm.UnmarshalBinary(msg); err != nil {
				log.Println(err)
				return
			}
			reply := ofmReply{ctrl: self, channel: channel, req: &ofm}
			switch ofm.Type {
			case ofp4.OFPT_ECHO_REQUEST:
				worker <- &ofmEcho{reply}
			case ofp4.OFPT_EXPERIMENTER:
				worker <- &ofmExperimenter{reply}
			case ofp4.OFPT_FEATURES_REQUEST:
				worker <- &ofmFeaturesRequest{reply}
			case ofp4.OFPT_GET_CONFIG_REQUEST:
				worker <- &ofmGetConfigRequest{reply}
			case ofp4.OFPT_SET_CONFIG:
				worker <- &ofmSetConfig{reply}
			case ofp4.OFPT_PACKET_OUT:
				worker <- &ofmPacketOut{ofmOutput{reply, nil}}
			case ofp4.OFPT_FLOW_MOD:
				worker <- &ofmFlowMod{ofmOutput{reply, nil}}
			case ofp4.OFPT_GROUP_MOD:
				worker <- &ofmGroupMod{reply}
			case ofp4.OFPT_PORT_MOD:
				worker <- &ofmPortMod{reply}
			case ofp4.OFPT_TABLE_MOD:
				worker <- &ofmTableMod{reply}
			case ofp4.OFPT_MULTIPART_REQUEST:
				req := ofm.Body.(ofp4.MultipartRequest)
				multipartCollect[ofm.Xid] = append(multipartCollect[ofm.Xid], req.Body)
				if req.Flags&ofp4.OFPMPF_REQ_MORE == 0 {
					mreply := ofmMulti{reply, multipartCollect[ofm.Xid], nil}
					delete(multipartCollect, ofm.Xid)

					// capture
					switch req.Type {
					case ofp4.OFPMP_DESC:
						worker <- &ofmMpDesc{mreply}
					case ofp4.OFPMP_TABLE:
						worker <- &ofmMpTable{mreply}
					case ofp4.OFPMP_GROUP_DESC:
						worker <- &ofmMpGroupDesc{mreply}
					case ofp4.OFPMP_GROUP_FEATURES:
						worker <- &ofmMpGroupFeatures{mreply}
					case ofp4.OFPMP_METER_FEATURES:
						worker <- &ofmMpMeterFeatures{mreply}
					case ofp4.OFPMP_PORT_DESC:
						worker <- &ofmMpPortDesc{mreply}
					case ofp4.OFPMP_FLOW:
						worker <- &ofmMpFlow{mreply}
					case ofp4.OFPMP_AGGREGATE:
						worker <- &ofmMpAggregate{mreply}
					case ofp4.OFPMP_PORT_STATS:
						worker <- &ofmMpPortStats{mreply}
					case ofp4.OFPMP_QUEUE:
						worker <- &ofmMpQueue{mreply}
					case ofp4.OFPMP_GROUP:
						worker <- &ofmMpGroup{mreply}
					case ofp4.OFPMP_METER:
						worker <- &ofmMpMeter{mreply}
					case ofp4.OFPMP_METER_CONFIG:
						worker <- &ofmMpMeterConfig{mreply}
					case ofp4.OFPMP_TABLE_FEATURES:
						worker <- &ofmMpTableFeatures{mreply}
					case ofp4.OFPMP_EXPERIMENTER:
						worker <- &ofmMpExperimenter{mreply}
					default:
						panic("unknown ofp_multipart_request.type")
					}
				}
			case ofp4.OFPT_BARRIER_REQUEST:
				worker <- &ofmBarrierRequest{reply}
			case ofp4.OFPT_QUEUE_GET_CONFIG_REQUEST:
				worker <- &ofmQueueGetConfigRequest{reply}
			case ofp4.OFPT_ROLE_REQUEST:
				worker <- &ofmRoleRequest{reply}
			case ofp4.OFPT_GET_ASYNC_REQUEST:
				worker <- &ofmGetAsyncRequest{reply}
			case ofp4.OFPT_SET_ASYNC:
				worker <- &ofmSetAsync{reply}
			case ofp4.OFPT_METER_MOD:
				worker <- &ofmMeterMod{reply}
			default:
				panic("unknown ofp_header.type")
			}
		}
	}()
	return nil
}

func (self controller) Stats() *PortStats {
	return &self.stats
}

func (self controller) State() *PortState {
	self.lock.Lock()
	defer self.lock.Unlock()

	var state PortState
	if len(self.channels) > 0 {
		state.Live = true
	}
	return &state
}

func (self controller) GetConfig() uint32 {
	return self.config
}

func (self controller) SetConfig(config uint32) {
	self.config = config
}

type ControlChannel interface {
	Ingress() ([]byte, error)
	Egress([]byte) error
}

type channelInternal struct {
	close     chan error
	lock      *sync.RWMutex
	channel   ControlChannel
	auxiliary uint8
	// XXX: MASTER/SLAVE/EQUAL
	packetInMask    [2]uint32
	portStatusMask  [2]uint32
	flowRemovedMask [2]uint32
	nextXid         uint32
}

func (self *channelInternal) hello() error {
	{ // SEND hello
		msg := ofp4.Message{
			Header: ofp4.Header{
				Version: 4,
				Type:    ofp4.OFPT_HELLO,
				Xid:     self.newXid(),
			},
			Body: ofp4.Array{
				ofp4.HelloElementVersionbitmap{
					Bitmaps: []uint32{uint32(1 << 4)},
				},
			},
		}
		if msgbin, err := msg.MarshalBinary(); err != nil {
			return err
		} else if err := self.channel.Egress(msgbin); err != nil {
			return err
		}
	}

	{ // RECV hello
		var ofm ofp4.Message
		if buf, err := self.channel.Ingress(); err != nil {
			return err
		} else if err := ofm.UnmarshalBinary(buf); err != nil {
			return err
		}
		satisfied := false
		for _, element := range []encoding.BinaryMarshaler(ofm.Body.(ofp4.Array)) {
			switch telement := element.(type) {
			case ofp4.HelloElementVersionbitmap:
				bitmaps := telement.Bitmaps
				if len(bitmaps) > 0 && (bitmaps[0]&(1<<4) != 0) {
					satisfied = true
				}
				// ensure there be no bits higher than ofp4
				for i, b := range bitmaps {
					if i == 0 && (b&0xFFFFFFE0) != 0 {
						satisfied = false
					}
					if i > 0 && b != 0 {
						satisfied = false
					}
				}
			}
		}
		if !satisfied && ofm.Version == 4 {
			satisfied = true
		}
		if !satisfied {
			err := ofp4.Error{
				Type: ofp4.OFPET_HELLO_FAILED,
				Code: ofp4.OFPHFC_INCOMPATIBLE,
			}
			msg := ofp4.Message{
				Header: ofp4.Header{
					Version: 4,
					Type:    ofp4.OFPT_ERROR,
					Xid:     ofm.Xid,
				},
				Body: err,
			}
			if msgbin, err := msg.MarshalBinary(); err != nil {
				return err
			} else {
				return self.channel.Egress(msgbin)
			}
		}
	}
	return nil
}

func (self *channelInternal) newXid() uint32 {
	self.lock.Lock()
	defer self.lock.Unlock()

	ret := self.nextXid
	self.nextXid++ // note: unsigned interger overflow wrap-arounds
	return ret
}

func (self channelInternal) packetIn(buffer_id uint32, pout *outputToPort) error {
	// XXX: assuming EQUAL/MASTER
	if self.packetInMask[0]&(1<<pout.reason) != 0 {
		return nil
	}
	data := pout.data
	eth, err := data.data()
	if err != nil {
		return err
	}
	totalLen := len(eth)
	if int(pout.maxLen) < totalLen {
		eth = eth[:pout.maxLen]
	}
	assocMatch := match{}
	{
		m := oxmBasic{
			Type:  uint32(ofp4.OXM_OF_IN_PORT),
			Mask:  []byte{255, 255, 255, 255},
			Value: []byte{0, 0, 0, 0},
		}
		binary.BigEndian.PutUint32(m.Value, data.inPort)
		assocMatch.basic = append(assocMatch.basic, m)
	}
	if data.phyInPort != 0 && data.phyInPort != data.inPort {
		m := oxmBasic{
			Type:  uint32(ofp4.OXM_OF_IN_PHY_PORT),
			Mask:  []byte{255, 255, 255, 255},
			Value: []byte{0, 0, 0, 0},
		}
		binary.BigEndian.PutUint32(m.Value, data.phyInPort)
		assocMatch.basic = append(assocMatch.basic, m)
	}
	if data.tunnelId != 0 {
		m := oxmBasic{
			Type:  uint32(ofp4.OXM_OF_TUNNEL_ID),
			Mask:  []byte{255, 255, 255, 255, 255, 255, 255, 255},
			Value: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		}
		binary.BigEndian.PutUint64(m.Value, data.tunnelId)
		assocMatch.basic = append(assocMatch.basic, m)
	}
	if data.metadata != 0 {
		m := oxmBasic{
			Type:  uint32(ofp4.OXM_OF_METADATA),
			Mask:  []byte{255, 255, 255, 255, 255, 255, 255, 255},
			Value: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		}
		binary.BigEndian.PutUint64(m.Value, data.metadata)
		assocMatch.basic = append(assocMatch.basic, m)
	}
	fields, e2 := assocMatch.MarshalBinary()
	if e2 != nil {
		return e2
	}
	msg := ofp4.Message{
		Header: ofp4.Header{
			Version: 4,
			Type:    ofp4.OFPT_PACKET_IN,
			Xid:     self.newXid(),
		},
		Body: ofp4.PacketIn{
			BufferId: buffer_id,
			TotalLen: uint16(totalLen),
			Match: ofp4.Match{
				Type: ofp4.OFPMT_OXM,
				Data: fields,
			},
			Reason:  pout.reason,
			TableId: pout.tableId,
			Data:    eth,
		},
	}
	if msgbin, err := msg.MarshalBinary(); err != nil {
		return err
	} else {
		return self.channel.Egress(msgbin)
	}
}

func (self *channelInternal) portChange(portNo uint32, port portInternal) error {
	reason := port.(*normalPort).reason
	if self.portStatusMask[0]&(1<<reason) != 0 {
		return nil
	}

	var state uint32
	portState := port.State()
	if portState.LinkDown {
		state |= ofp4.OFPPS_LINK_DOWN
	}
	if portState.Blocked {
		state |= ofp4.OFPPS_BLOCKED
	}
	if portState.Live {
		state |= ofp4.OFPPS_LIVE
	}

	msg := ofp4.Message{
		Header: ofp4.Header{
			Version: 4,
			Type:    ofp4.OFPT_PORT_STATUS,
			Xid:     self.newXid(),
		},
		Body: ofp4.PortStatus{
			Reason: reason,
			Desc: ofp4.Port{
				PortNo:     portNo,
				HwAddr:     portState.HwAddr,
				Name:       portState.Name,
				Config:     port.GetConfig(),
				State:      state,
				Curr:       portState.Curr,
				Advertised: portState.Advertised,
				Supported:  portState.Supported,
				Peer:       portState.Peer,
				CurrSpeed:  portState.CurrSpeed,
				MaxSpeed:   portState.MaxSpeed,
			},
		},
	}
	msgbin, e2 := msg.MarshalBinary()
	if e2 != nil {
		return e2
	}
	return self.channel.Egress(msgbin)
}

func (self channelInternal) sendFlowRem(tableId uint8, priority uint16, flow *flowEntry, reason uint8) error {
	if self.flowRemovedMask[0]&(1<<reason) != 0 {
		return nil
	}
	fields, e2 := flow.fields.MarshalBinary()
	if e2 != nil {
		return e2
	}

	dur := time.Now().Sub(flow.created)
	msg := ofp4.Message{
		Header: ofp4.Header{
			Version: 4,
			Type:    ofp4.OFPT_FLOW_REMOVED,
			Xid:     self.newXid(),
		},
		Body: ofp4.FlowRemoved{
			Cookie:       flow.cookie,
			Priority:     priority,
			Reason:       reason,
			TableId:      tableId,
			DurationSec:  uint32(dur / time.Second),
			DurationNsec: uint32(dur % time.Second), // time.Nanosecond == 1
			IdleTimeout:  flow.idleTimeout,
			HardTimeout:  flow.hardTimeout,
			PacketCount:  flow.packetCount,
			ByteCount:    flow.byteCount,
			Match: ofp4.Match{
				Type: ofp4.OFPMT_OXM,
				Data: fields,
			},
		},
	}
	msgbin, e3 := msg.MarshalBinary()
	if e3 != nil {
		return e3
	}
	return self.channel.Egress(msgbin)
}

type ofmReply struct {
	ctrl    *controller
	channel ControlChannel
	req     *ofp4.Message
	resps   [][]byte
}

func (self *ofmReply) createError(ofpet uint16, code uint16) {
	if buf, err := self.req.MarshalBinary(); err != nil {
		panic(err)
	} else {
		msg := ofp4.Message{
			Header: ofp4.Header{
				Version: self.req.Version,
				Type:    ofp4.OFPT_ERROR,
				Xid:     self.req.Xid,
			},
			Body: ofp4.Error{
				Type: ofpet,
				Code: code,
				Data: buf,
			},
		}
		if msgbin, err := msg.MarshalBinary(); err != nil {
			panic(err)
		} else {
			self.resps = append(self.resps, msgbin)
		}
	}
}

func (self ofmReply) Reduce() {
	for _, resp := range self.resps {
		if err := self.channel.Egress(resp); err != nil {
			log.Print(err)
		}
	}
}

type ofmEcho struct {
	ofmReply
}

func (self *ofmEcho) Map() Reducable {
	msg := ofp4.Message{
		Header: ofp4.Header{
			Version: self.req.Version,
			Type:    ofp4.OFPT_ECHO_REPLY,
			Xid:     self.req.Xid,
		},
		Body: self.req.Body,
	}
	if msgbin, err := msg.MarshalBinary(); err != nil {
		log.Print(err)
	} else {
		self.resps = append(self.resps, msgbin)
	}
	return self
}

type ofmExperimenter struct {
	ofmReply
}

func (self *ofmExperimenter) Map() Reducable {
	self.createError(ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BAD_EXPERIMENTER)
	return self
}

type ofmFeaturesRequest struct {
	ofmReply
}

func (self *ofmFeaturesRequest) Map() Reducable {
	msg := ofp4.Message{
		Header: ofp4.Header{
			Version: self.req.Version,
			Type:    ofp4.OFPT_FEATURES_REPLY,
			Xid:     self.req.Xid,
		},
		Body: ofp4.SwitchFeatures{
			DatapathId:   self.ctrl.pipe.DatapathId,
			NBuffers:     0x7fffffff,
			NTables:      0xff,
			Capabilities: 0,
		},
	}
	if msgbin, err := msg.MarshalBinary(); err != nil {
		log.Print(err)
	} else {
		self.resps = append(self.resps, msgbin)
	}
	return self
}

type ofmGetConfigRequest struct {
	ofmReply
}

func (self *ofmGetConfigRequest) Map() Reducable {
	msg := ofp4.Message{
		Header: ofp4.Header{
			Version: 4,
			Type:    ofp4.OFPT_GET_CONFIG_REPLY,
			Xid:     self.req.Xid,
		},
		Body: ofp4.SwitchConfig{
			Flags:       self.ctrl.pipe.flags, // XXX:
			MissSendLen: self.ctrl.missSendLen,
		},
	}
	if msgbin, err := msg.MarshalBinary(); err != nil {
		log.Print(err)
	} else {
		self.resps = append(self.resps, msgbin)
	}
	return self
}

type ofmSetConfig struct {
	ofmReply
}

func (self ofmSetConfig) Map() Reducable {
	config := self.req.Body.(ofp4.SwitchConfig)
	self.ctrl.pipe.flags = config.Flags
	self.ctrl.missSendLen = config.MissSendLen
	return self
}

type ofmGroupMod struct {
	ofmReply
}

func (self *ofmGroupMod) Map() Reducable {
	pipe := self.ctrl.pipe
	req := self.req.Body.(ofp4.GroupMod)

	switch req.Command {
	case ofp4.OFPGC_ADD:
		if err := pipe.addGroup(req); err != nil {
			if e, ok := err.(ofp4.Error); ok {
				self.createError(e.Type, e.Code)
			} else {
				log.Print(err)
			}
		}
	case ofp4.OFPGC_MODIFY:
		func() {
			pipe.lock.Lock()
			defer pipe.lock.Unlock()

			if group, exists := pipe.groups[req.GroupId]; exists {
				buckets := make([]bucket, len(req.Buckets))
				for i, _ := range buckets {
					buckets[i].fromMessage(req.Buckets[i])
				}
				group.groupType = req.Type
				group.buckets = buckets
			} else {
				self.createError(ofp4.OFPET_GROUP_MOD_FAILED, ofp4.OFPGMFC_UNKNOWN_GROUP)
			}
		}()
	case ofp4.OFPGC_DELETE:
		if err := func() error {
			pipe.lock.Lock()
			defer pipe.lock.Unlock()

			if req.GroupId == ofp4.OFPG_ALL {
				for groupId, _ := range pipe.groups {
					if err := pipe.deleteGroupInside(groupId); err != nil {
						return err
					}
				}
			} else {
				return pipe.deleteGroupInside(req.GroupId)
			}
			return nil
		}(); err != nil {
			if e, ok := err.(ofp4.Error); ok {
				self.createError(e.Type, e.Code)
			} else {
				log.Print(err)
			}
		}
	}
	return self
}

type ofmPortMod struct {
	ofmReply
}

func (self *ofmPortMod) Map() Reducable {
	pipe := self.ctrl.pipe
	req := self.req.Body.(ofp4.PortMod)

	for _, p := range pipe.getPorts(req.PortNo) {
		switch port := p.(type) {
		case *normalPort:
			port.config = req.Config&req.Mask | port.config&^req.Mask
			if req.Advertise != 0 {
				// XXX:
			}
		default:
			log.Print("port cast error")
		}
	}
	return self
}

type ofmTableMod struct {
	ofmReply
}

func (self ofmTableMod) Map() Reducable {
	req := self.req.Body.(ofp4.TableMod)
	for _, table := range self.ctrl.pipe.getFlowTables(req.TableId) {
		func() {
			table.lock.Lock()
			defer table.lock.Unlock()
			table.feature.config = req.Config
		}()
	}
	return self
}

type ofmOutput struct {
	ofmReply
	outputs []*outputToPort
}

func (self ofmOutput) Reduce() {
	pipe := self.ctrl.pipe

	for _, output := range self.outputs {
		if output.outPort <= ofp4.OFPP_MAX {
			if port := pipe.getPort(output.outPort); port != nil {
				port.Outlet(output)
			}
		} else if output.outPort == ofp4.OFPP_CONTROLLER {
			config := pipe.getPort(output.data.inPort).GetConfig()
			if config&(ofp4.OFPPC_NO_PACKET_IN) != 0 {
				continue
			}
		} else {
			for _, port := range pipe.getPorts(output.outPort) {
				port.Outlet(output)
			}
		}
	}
	self.ofmReply.Reduce()
	return
}

type ofmPacketOut struct {
	ofmOutput
}

func (self *ofmPacketOut) Map() Reducable {
	req := self.req.Body.(ofp4.PacketOut)

	var eth []byte
	if req.BufferId == ofp4.OFP_NO_BUFFER {
		eth = req.Data
	} else {
		func() {
			self.ctrl.lock.Lock()
			defer self.ctrl.lock.Unlock()

			if original, ok := self.ctrl.buffer[req.BufferId]; ok {
				delete(self.ctrl.buffer, req.BufferId)
				if data, err := original.data.data(); err != nil {
					log.Print(err)
				} else {
					eth = data
				}
			} else {
				self.createError(ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BUFFER_UNKNOWN)
			}
		}()
	}
	if eth != nil {
		data := &frame{
			serialized: eth,
			inPort:     req.InPort,
			phyInPort:  self.ctrl.pipe.getPortPhysicalPort(req.InPort),
		}
		var actions actionList
		actions.fromMessage(req.Actions)

		var gouts []*outputToGroup
		for _, act := range []action(actions) {
			if pout, gout, e := act.(action).process(data); e != nil {
				log.Print(e)
			} else {
				if pout != nil {
					self.outputs = append(self.outputs, pout)
				}
				if gout != nil {
					gouts = append(gouts, gout)
				}
			}
		}
		self.outputs = append(self.outputs, self.ctrl.pipe.groupToOutput(gouts, nil)...)
	}
	return self
}

type ofmFlowMod struct {
	ofmOutput
}

func (self *ofmFlowMod) Map() Reducable {
	req := self.req.Body.(ofp4.FlowMod)

	switch req.Command {
	case ofp4.OFPFC_ADD:
		if err := self.ctrl.pipe.addFlowEntry(req); err != nil {
			if e, ok := err.(ofp4.Error); ok {
				self.createError(e.Type, e.Code)
			} else {
				log.Print(err)
			}
		}
	case ofp4.OFPFC_MODIFY, ofp4.OFPFC_MODIFY_STRICT:
		var reqMatch match
		if err := reqMatch.UnmarshalBinary(req.Match.Data); err != nil {
			log.Print(err)
		} else if req.TableId > ofp4.OFPTT_MAX {
			self.createError(ofp4.OFPET_FLOW_MOD_FAILED, ofp4.OFPFMFC_BAD_TABLE_ID)
		} else {
			filter := flowFilter{
				cookie:     req.Cookie,
				cookieMask: req.CookieMask,
				tableId:    req.TableId,
				outPort:    ofp4.OFPP_ANY,
				outGroup:   ofp4.OFPG_ANY,
				match:      reqMatch,
			}
			if req.Command == ofp4.OFPFC_MODIFY_STRICT {
				filter.priority = req.Priority
				filter.opStrict = true
			}
			for _, stat := range self.ctrl.pipe.filterFlows(filter) {
				flow := stat.flow
				if err := func() error {
					flow.lock.Lock()
					defer flow.lock.Unlock()

					if req.Flags&ofp4.OFPFF_RESET_COUNTS != 0 {
						flow.packetCount = 0
						flow.byteCount = 0
					}
					return flow.importInstructions(req.Instructions)
				}(); err != nil {
					if e, ok := err.(ofp4.Error); ok {
						self.createError(e.Type, e.Code)
					} else {
						log.Print(err)
					}
				}
			}
		}
	case ofp4.OFPFC_DELETE, ofp4.OFPFC_DELETE_STRICT:
		var reqMatch match
		if err := reqMatch.UnmarshalBinary(req.Match.Data); err != nil {
			log.Print(err)
		} else {
			filter := flowFilter{
				opUnregister: true,
				cookie:       req.Cookie,
				cookieMask:   req.CookieMask,
				tableId:      req.TableId,
				outPort:      req.OutPort,
				outGroup:     req.OutGroup,
				match:        reqMatch,
			}
			if req.Command == ofp4.OFPFC_DELETE_STRICT {
				filter.priority = req.Priority
				filter.opStrict = true
			}
			for _, stat := range self.ctrl.pipe.filterFlows(filter) {
				if stat.flow.flags&ofp4.OFPFF_SEND_FLOW_REM != 0 {
					self.ctrl.sendFlowRem(stat.tableId, stat.priority, stat.flow, ofp4.OFPRR_DELETE)
				}
			}
		}
	}
	if req.BufferId != ofp4.OFP_NO_BUFFER {
		original, ok := func() (*outputToPort, bool) {
			self.ctrl.lock.Lock()
			defer self.ctrl.lock.Unlock()

			original, ok := self.ctrl.buffer[req.BufferId]
			if ok {
				delete(self.ctrl.buffer, req.BufferId)
			}
			return original, ok
		}()
		if ok {
			pipe := self.ctrl.pipe
			pipe.datapath <- &flowTableWork{
				data:    original.data,
				pipe:    self.ctrl.pipe,
				tableId: 0,
			}
		} else {
			self.createError(ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BUFFER_UNKNOWN)
		}
	}
	return self
}

type ofmMulti struct {
	ofmReply
	reqs   []encoding.BinaryMarshaler // multipart version of ofmReply.req
	chunks []encoding.BinaryMarshaler // multipart response payload chunks
}

func (self *ofmMulti) Reduce() {
	req := self.req.Body.(ofp4.MultipartRequest)
	payloadMaxLength := math.MaxUint16 - 16

	var payload []encoding.BinaryMarshaler
	var payloadLength int
	for _, chunk := range self.chunks {
		data, err := chunk.MarshalBinary()
		if err != nil {
			log.Print(err)
			continue
		}
		payloadLength += len(data)
		if payloadLength >= payloadMaxLength {
			msg := ofp4.Message{
				Header: ofp4.Header{
					Version: self.req.Version,
					Type:    ofp4.OFPT_MULTIPART_REPLY,
					Xid:     self.req.Xid,
				},
				Body: ofp4.MultipartReply{
					Type:  req.Type,
					Flags: ofp4.OFPMPF_REPLY_MORE,
					Body:  ofp4.Array(payload),
				},
			}
			if msgbin, err := msg.MarshalBinary(); err != nil {
				log.Print(err)
			} else {
				self.resps = append(self.resps, msgbin)
			}
			payload = payload[:0]
			payloadLength = 0
		}
		payload = append(payload, chunk)
		payloadLength += len(data)
	}
	msg := ofp4.Message{
		Header: ofp4.Header{
			Version: self.req.Version,
			Type:    ofp4.OFPT_MULTIPART_REPLY,
			Xid:     self.req.Xid,
		},
		Body: ofp4.MultipartReply{
			Type:  req.Type,
			Flags: 0,
			Body:  ofp4.Array(payload),
		},
	}
	if msgbin, err := msg.MarshalBinary(); err != nil {
		log.Print(err)
	} else {
		self.resps = append(self.resps, msgbin)
	}
	self.ofmReply.Reduce()
}

type ofmMpDesc struct {
	ofmMulti
}

func (self *ofmMpDesc) Map() Reducable {
	self.chunks = append(self.chunks, self.ctrl.pipe.Desc)
	return self
}

type ofmMpFlow struct {
	ofmMulti
}

func (self *ofmMpFlow) Map() Reducable {
	pipe := self.ctrl.pipe

	var flows []flowStats
	for _, req := range self.reqs {
		mreq := req.(ofp4.FlowStatsRequest)
		var reqMatch match
		if e := reqMatch.UnmarshalBinary(mreq.Match.Data); e != nil {
			log.Print(e)
		} else {
			filter := flowFilter{
				tableId:    mreq.TableId,
				outPort:    mreq.OutPort,
				outGroup:   mreq.OutGroup,
				cookie:     mreq.Cookie,
				cookieMask: mreq.CookieMask,
				match:      reqMatch,
			}
			for _, f := range pipe.filterFlows(filter) {
				hit := false
				for _, seen := range flows {
					if f.flow == seen.flow {
						hit = true
						break
					}
				}
				if !hit {
					flows = append(flows, f)
				}
			}
		}
	}
	for _, f := range flows {
		duration := time.Now().Sub(f.flow.created)
		if buf, e := f.flow.fields.MarshalBinary(); e != nil {
			log.Print(e)
		} else {
			chunk := ofp4.FlowStats{
				TableId:      f.tableId,
				DurationSec:  uint32(duration.Seconds()),
				DurationNsec: uint32(duration.Nanoseconds() % int64(time.Second)),
				Priority:     f.priority,
				IdleTimeout:  f.flow.idleTimeout,
				HardTimeout:  f.flow.hardTimeout,
				Flags:        f.flow.flags, // OFPFF_
				Cookie:       f.flow.cookie,
				PacketCount:  f.flow.packetCount,
				ByteCount:    f.flow.byteCount,
				Match: ofp4.Match{
					Type: ofp4.OFPMT_OXM,
					Data: buf,
				},
				Instructions: f.flow.exportInstructions(),
			}
			self.chunks = append(self.chunks, chunk)
		}
	}
	return self
}

type ofmMpTable struct {
	ofmMulti
}

func (self *ofmMpTable) Map() Reducable {
	for tableId, table := range self.ctrl.pipe.getFlowTables(ofp4.OFPTT_ALL) {
		chunk := func() encoding.BinaryMarshaler {
			table.lock.RLock()
			defer table.lock.RUnlock()
			return ofp4.TableStats{
				TableId:      tableId,
				ActiveCount:  table.activeCount,
				LookupCount:  table.lookupCount,
				MatchedCount: table.matchCount,
			}
		}()
		self.chunks = append(self.chunks, chunk)
	}
	return self
}

type ofmMpAggregate struct {
	ofmMulti
}

func (self *ofmMpAggregate) Map() Reducable {
	mpreq := self.req.Body.(ofp4.MultipartRequest)
	mreq := mpreq.Body.(ofp4.AggregateStatsRequest)

	var reqMatch match
	if err := reqMatch.UnmarshalBinary(mreq.Match.Data); err != nil {
		log.Print(err)
	} else {
		filter := flowFilter{
			tableId:    mreq.TableId,
			outPort:    mreq.OutPort,
			outGroup:   mreq.OutGroup,
			cookie:     mreq.Cookie,
			cookieMask: mreq.CookieMask,
			match:      reqMatch,
		}
		var chunk ofp4.AggregateStatsReply
		for _, f := range self.ctrl.pipe.filterFlows(filter) {
			chunk.PacketCount += f.flow.packetCount
			chunk.ByteCount += f.flow.byteCount
			chunk.FlowCount++
		}
		self.chunks = append(self.chunks, chunk)
	}
	return self
}

type ofmMpPortStats struct {
	ofmMulti
}

func (self *ofmMpPortStats) Map() Reducable {
	mpreq := self.req.Body.(ofp4.MultipartRequest)
	for portNo, bport := range self.ctrl.pipe.getPorts(mpreq.Body.(ofp4.PortStatsRequest).PortNo) {
		switch port := bport.(type) {
		case *normalPort:
			pstats := port.Stats()
			duration := time.Now().Sub(port.created)
			chunk := ofp4.PortStats{
				PortNo:       portNo,
				RxPackets:    pstats.RxPackets,
				TxPackets:    pstats.TxPackets,
				RxBytes:      pstats.RxBytes,
				TxBytes:      pstats.TxBytes,
				DurationSec:  uint32(duration.Seconds()),
				DurationNsec: uint32(duration.Nanoseconds() % int64(time.Second)),
			}
			self.chunks = append(self.chunks, chunk)
		case *controller:
			// exluding
		default:
			panic("portHelper cast error")
		}
	}
	return self
}

type ofmMpQueue struct {
	ofmMulti
}

func (self *ofmMpQueue) Map() Reducable {
	// XXX: TODO
	return self
}

type ofmMpGroup struct {
	ofmMulti
}

func (self *ofmMpGroup) Map() Reducable {
	// XXX: TODO
	return self
}

type ofmMpGroupDesc struct {
	ofmMulti
}

func (self *ofmMpGroupDesc) Map() Reducable {
	for i, g := range self.ctrl.pipe.getGroups(ofp4.OFPG_ALL) {
		var buckets []encoding.BinaryMarshaler
		for _, b := range g.buckets {
			if bucket, e := b.toMessage(); e != nil {
				panic(e)
			} else {
				buckets = append(buckets, bucket)
			}
		}
		chunk := ofp4.GroupDesc{
			Type:    g.groupType,
			GroupId: i,
			Buckets: buckets,
		}
		self.chunks = append(self.chunks, chunk)
	}
	return self
}

type ofmMpGroupFeatures struct {
	ofmMulti
}

func (self *ofmMpGroupFeatures) Map() Reducable {
	actionBits := uint32(0)
	actionBits |= 1 << ofp4.OFPAT_OUTPUT
	actionBits |= 1 << ofp4.OFPAT_COPY_TTL_OUT
	actionBits |= 1 << ofp4.OFPAT_COPY_TTL_IN
	actionBits |= 1 << ofp4.OFPAT_SET_MPLS_TTL
	actionBits |= 1 << ofp4.OFPAT_DEC_MPLS_TTL
	actionBits |= 1 << ofp4.OFPAT_PUSH_VLAN
	actionBits |= 1 << ofp4.OFPAT_POP_VLAN
	actionBits |= 1 << ofp4.OFPAT_PUSH_MPLS
	actionBits |= 1 << ofp4.OFPAT_POP_MPLS
	actionBits |= 1 << ofp4.OFPAT_SET_QUEUE
	actionBits |= 1 << ofp4.OFPAT_GROUP
	actionBits |= 1 << ofp4.OFPAT_SET_NW_TTL
	actionBits |= 1 << ofp4.OFPAT_DEC_NW_TTL
	actionBits |= 1 << ofp4.OFPAT_SET_FIELD
	actionBits |= 1 << ofp4.OFPAT_PUSH_PBB
	actionBits |= 1 << ofp4.OFPAT_POP_PBB
	// OFPAT_EXPERIMENTER overflows
	chunk := ofp4.GroupFeatures{
		Types:        1<<ofp4.OFPGT_ALL | 1<<ofp4.OFPGT_SELECT | 1<<ofp4.OFPGT_INDIRECT | 1<<ofp4.OFPGT_FF,
		Capabilities: ofp4.OFPGFC_SELECT_WEIGHT | ofp4.OFPGFC_SELECT_LIVENESS | ofp4.OFPGFC_CHAINING | ofp4.OFPGFC_CHAINING_CHECKS,
		MaxGroups:    [...]uint32{ofp4.OFPG_MAX, ofp4.OFPG_MAX, ofp4.OFPG_MAX, ofp4.OFPG_MAX},
		Actions:      [...]uint32{actionBits, actionBits, actionBits, actionBits},
	}
	self.chunks = append(self.chunks, chunk)
	return self
}

type ofmMpMeterFeatures struct {
	ofmMulti
}

func (self *ofmMpMeterFeatures) Map() Reducable {
	// XXX:
	return self
}

type ofmMpMeter struct {
	ofmMulti
}

func (self *ofmMpMeter) Map() Reducable {
	pipe := self.ctrl.pipe

	meterId := self.req.Body.(ofp4.MeterMultipartRequest).MeterId
	for meterId, meter := range pipe.getMeters(meterId) {
		duration := time.Now().Sub(meter.created)
		var bands []encoding.BinaryMarshaler
		for _, bi := range meter.bands {
			switch b := bi.(type) {
			case *bandDrop:
				bands = append(bands, ofp4.MeterBandStats{
					PacketBandCount: b.packetCount,
					ByteBandCount:   b.byteCount,
				})
			case *bandDscpRemark:
				bands = append(bands, ofp4.MeterBandStats{
					PacketBandCount: b.packetCount,
					ByteBandCount:   b.byteCount,
				})
			case *bandExperimenter:
				bands = append(bands, ofp4.MeterBandStats{
					PacketBandCount: b.packetCount,
					ByteBandCount:   b.byteCount,
				})
			}
		}
		chunk := ofp4.MeterStats{
			MeterId: meterId,
			FlowCount: uint32(len(pipe.filterFlows(flowFilter{
				tableId:  ofp4.OFPTT_ALL,
				outPort:  ofp4.OFPP_ANY,
				outGroup: ofp4.OFPG_ANY,
				meterId:  meterId,
			}))),
			PacketInCount: meter.packetCount,
			ByteInCount:   meter.byteCount,
			DurationSec:   uint32(duration.Seconds()),
			DurationNsec:  uint32(duration.Nanoseconds() % int64(time.Second)),
			BandStats:     bands,
		}
		self.chunks = append(self.chunks, chunk)
	}
	return self
}

type ofmMpMeterConfig struct {
	ofmMulti
}

func (self *ofmMpMeterConfig) Map() Reducable {
	mpreq := self.req.Body.(ofp4.MultipartRequest)
	meterId := mpreq.Body.(ofp4.MeterMultipartRequest).MeterId
	for meterId, meter := range self.ctrl.pipe.getMeters(meterId) {
		var bands []ofp4.Band
		for _, bi := range meter.bands {
			switch b := bi.(type) {
			case *bandDrop:
				bands = append(bands, ofp4.MeterBandDrop{
					Rate:      b.rate,
					BurstSize: b.burstSize,
				})
			case *bandDscpRemark:
				bands = append(bands, ofp4.MeterBandDscpRemark{
					Rate:      b.rate,
					BurstSize: b.burstSize,
					PrecLevel: b.precLevel,
				})
			case *bandExperimenter:
				bands = append(bands, ofp4.MeterBandExperimenter{
					Rate:         b.rate,
					BurstSize:    b.burstSize,
					Experimenter: b.experimenter,
					Data:         b.data,
				})
			}
		}
		var flags uint16
		if meter.flagPkts {
			flags |= ofp4.OFPMF_PKTPS
		} else {
			flags |= ofp4.OFPMF_KBPS
		}
		if meter.flagBurst {
			flags |= ofp4.OFPMF_BURST
		}
		if meter.flagStats {
			flags |= ofp4.OFPMF_STATS
		}
		chunk := ofp4.MeterConfig{
			Flags:   flags,
			MeterId: meterId,
			Bands:   bands,
		}
		self.chunks = append(self.chunks, chunk)
	}
	return self
}

type ofmMpTableFeatures struct {
	ofmMulti
}

func (self *ofmMpTableFeatures) Map() Reducable {
	if len(self.reqs) == 0 {
		for tableId, t := range self.ctrl.pipe.getFlowTables(ofp4.OFPTT_ALL) {
			f := t.feature
			rf := ofp4.TableFeatures{
				TableId:       tableId,
				Name:          f.name,
				MetadataMatch: f.metadataMatch,
				MetadataWrite: f.metadataWrite,
				Config:        f.config,
				MaxEntries:    f.maxEntries,
			}
			props := map[uint16][]oxmKey{
				ofp4.OFPTFPT_MATCH:               f.match,
				ofp4.OFPTFPT_WILDCARDS:           f.wildcards,
				ofp4.OFPTFPT_WRITE_SETFIELD:      f.hit.writeSetfield,
				ofp4.OFPTFPT_WRITE_SETFIELD_MISS: f.miss.writeSetfield,
				ofp4.OFPTFPT_APPLY_SETFIELD:      f.hit.applySetfield,
				ofp4.OFPTFPT_APPLY_SETFIELD_MISS: f.miss.applySetfield,
			}
			for pType, oxmTypes := range props {
				var ids []uint32
				for _, oxmType := range oxmTypes {
					switch t := oxmType.(type) {
					case uint32:
						ids = append(ids, t)
					case oxmExperimenterKey:
						if handler, ok := oxmHandlers[t]; ok {
							base := make([]byte, 8)
							binary.BigEndian.PutUint32(base, t.Type)
							binary.BigEndian.PutUint32(base[4:], t.Experimenter)
							if oxmId, err := handler.OxmId(base); err != nil {
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
				if len(oxmTypes) > 0 {
					rf.Properties = append(rf.Properties, ofp4.TableFeaturePropOxm{
						Type:   pType,
						OxmIds: ids,
					})
				}
			}
			self.chunks = append(self.chunks, rf)
		}
	} else {
		// XXX: set
	}
	return self
}

type ofmMpPortDesc struct {
	ofmMulti
}

func (self *ofmMpPortDesc) Map() Reducable {
	for portNo, bport := range self.ctrl.pipe.getPorts(ofp4.OFPP_ANY) {
		switch port := bport.(type) {
		case *normalPort:
			chunk := ofp4.Port{
				PortNo: portNo,
				Name:   port.public.Name(),
				Config: port.config,
			}
			state := port.State()
			if state != nil {
				chunk.Advertised = state.Advertised
				chunk.Curr = state.Curr
				chunk.Peer = state.Peer
				chunk.HwAddr = state.HwAddr
				if state.LinkDown {
					chunk.State |= ofp4.OFPPS_LINK_DOWN
				}
				if state.Blocked {
					chunk.State |= ofp4.OFPPS_BLOCKED
				}
			}
			if chunk.Config&ofp4.OFPPC_PORT_DOWN == 0 && chunk.State&ofp4.OFPPS_LINK_DOWN == 0 {
				chunk.State |= ofp4.OFPPS_LIVE
			}
			self.chunks = append(self.chunks, chunk)
		case *controller:
			// exluding
		default:
			log.Panic("portHelper cast error")
		}
	}
	return self
}

type ofmMpExperimenter struct {
	ofmMulti
}

func (self *ofmMpExperimenter) Map() Reducable {
	// XXX:
	return self
}

type ofmBarrierRequest struct {
	ofmReply
}

func (self *ofmBarrierRequest) Map() Reducable {
	msg := ofp4.Message{
		Header: ofp4.Header{
			Version: self.req.Version,
			Type:    ofp4.OFPT_BARRIER_REPLY,
			Xid:     self.req.Xid,
		},
	}
	if msgbin, err := msg.MarshalBinary(); err != nil {
		log.Print(err)
	} else {
		self.resps = append(self.resps, msgbin)
	}
	return self
}

type ofmQueueGetConfigRequest struct {
	ofmReply
}

func (self *ofmQueueGetConfigRequest) Map() Reducable {
	return self
}

type ofmRoleRequest struct {
	ofmReply
}

func (self *ofmRoleRequest) Map() Reducable {
	return self
}

type ofmGetAsyncRequest struct {
	ofmReply
}

func (self *ofmGetAsyncRequest) Map() Reducable {
	return self
}

type ofmSetAsync struct {
	ofmReply
}

func (self *ofmSetAsync) Map() Reducable {
	return self
}

type ofmMeterMod struct {
	ofmReply
}

func (self *ofmMeterMod) Map() Reducable {
	pipe := self.ctrl.pipe

	req := self.req.Body.(ofp4.MeterMod)
	switch req.Command {
	case ofp4.OFPMC_ADD:
		if req.MeterId == 0 || (req.MeterId > ofp4.OFPM_MAX && req.MeterId != ofp4.OFPM_CONTROLLER) {
			self.createError(ofp4.OFPET_METER_MOD_FAILED, ofp4.OFPMMFC_INVALID_METER)
		} else {
			meter := newMeter(req)
			if err := func() error {
				pipe.lock.Lock()
				defer pipe.lock.Unlock()

				if _, exists := pipe.meters[req.MeterId]; exists {
					return ofp4.Error{
						Type: ofp4.OFPET_METER_MOD_FAILED,
						Code: ofp4.OFPMMFC_METER_EXISTS,
					}
				} else {
					pipe.meters[req.MeterId] = meter
				}
				return nil
			}(); err != nil {
				if e, ok := err.(ofp4.Error); ok {
					self.createError(e.Type, e.Code)
				} else {
					log.Print(err)
				}
			}
		}
	case ofp4.OFPMC_DELETE:
		if err := func() error {
			pipe.lock.Lock()
			defer pipe.lock.Unlock()

			if req.MeterId == ofp4.OFPM_ALL {
				for meterId, _ := range pipe.meters {
					pipe.deleteMeterInside(meterId)
				}
			} else {
				return pipe.deleteMeterInside(req.MeterId)
			}
			return nil
		}(); err != nil {
			if e, ok := err.(ofp4.Error); ok {
				self.createError(e.Type, e.Code)
			} else {
				log.Print(err)
			}
		}
	case ofp4.OFPMC_MODIFY:
		// XXX:
	}
	return self
}
