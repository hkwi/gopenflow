package ofp4sw

import (
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
	"math"
	"sync"
	"time"
)

type MessageHandler interface {
	Execute(request []byte) (response [][]byte)
}

var messageHandlers map[experimenterKey]MessageHandler = make(map[experimenterKey]MessageHandler)

func AddMessageHandler(experimenter uint32, expType uint32, handler MessageHandler) {
	messageHandlers[experimenterKey{
		Experimenter: experimenter,
		ExpType:      expType,
	}] = handler
}

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

		multipartCollect := make(map[uint32][][]byte)
		for {
			msg, err := channel.Ingress()
			if err != nil {
				return
			}
			reply := ofmReply{ctrl: self, channel: channel, req: msg}
			switch ofp4.Header(msg).Type() {
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
				xid := ofp4.Header(msg).Xid()
				req := ofp4.MultipartRequest(msg)

				multipartCollect[xid] = append(multipartCollect[xid], req.Body())
				if req.Flags()&ofp4.OFPMPF_REQ_MORE == 0 {
					reqs := multipartCollect[xid]
					delete(multipartCollect, xid)

					mreply := ofmMulti{
						ofmReply: reply,
						reqs:     reqs,
						chunks:   nil,
					}

					// capture
					switch req.Type() {
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

func (self controller) Stats() PortStats {
	return self.stats
}

func (self controller) State() PortState {
	self.lock.Lock()
	defer self.lock.Unlock()

	var state PortState
	if len(self.channels) > 0 {
		state.Live = true
	}
	return state
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
		msg := ofp4.MakeHello(ofp4.MakeHelloElemVersionbitmap([]uint32{uint32(1 << 4)}))
		msg.SetXid(self.newXid())
		if err := self.channel.Egress(msg); err != nil {
			return err
		}
	}

	{ // RECV hello
		var msg ofp4.Header
		if buf, err := self.channel.Ingress(); err != nil {
			return err
		} else {
			msg = ofp4.Header(buf)
		}
		if msg.Type() != ofp4.OFPT_HELLO {
			return errors.New("The first message must be HELLO")
		}
		satisfied := false
		for _, element := range ofp4.Hello(msg).Elements().Iter() {
			switch element.Type() {
			case ofp4.OFPHET_VERSIONBITMAP:
				bitmaps := ofp4.HelloElemVersionbitmap(element).Bitmaps()
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
		if !satisfied && msg.Version() == 4 {
			satisfied = true
		}
		if !satisfied {
			err := ofp4.MakeErrorMsg(
				ofp4.OFPET_HELLO_FAILED,
				ofp4.OFPHFC_INCOMPATIBLE,
			)
			self.channel.Egress(ofp4.Header(err).SetXid(msg.Xid()))
			return err
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

	var pkt Frame
	if err := pkt.pull(*pout.data); err != nil {
		return err
	}

	eth := pkt.Data
	totalLen := len(pkt.Data)
	if int(pout.maxLen) < totalLen {
		eth = eth[:pout.maxLen]
	}

	msg := ofp4.MakePacketIn(buffer_id,
		uint16(totalLen),
		pout.reason,
		pout.tableId,
		pout.cookie,
		ofp4.MakeMatch(pkt.Match),
		eth)
	return self.channel.Egress(msg.SetXid(self.newXid()))
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

	msg := ofp4.MakePortStatus(reason, ofp4.MakePort(portNo,
		portState.HwAddr,
		[]byte(portState.Name),
		port.GetConfig(),
		state,
		portState.Curr,
		portState.Advertised,
		portState.Supported,
		portState.Peer,
		portState.CurrSpeed,
		portState.MaxSpeed,
	))
	return self.channel.Egress(msg.SetXid(self.newXid()))
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
	msg := ofp4.MakeFlowRemoved(
		flow.cookie,
		priority,
		reason,
		tableId,
		uint32(dur/time.Second),
		uint32(dur%time.Second), // time.Nanosecond == 1
		flow.idleTimeout,
		flow.hardTimeout,
		flow.packetCount,
		flow.byteCount,
		ofp4.MakeMatch(fields))
	return self.channel.Egress(msg.SetXid(self.newXid()))
}

type ofmReply struct {
	ctrl    *controller
	channel ControlChannel
	req     ofp4.Header
	resps   []ofp4.Header
}

func (self *ofmReply) createError(ofpet uint16, code uint16) {
	self.resps = append(self.resps,
		ofp4.Header(ofp4.MakeErrorMsg(ofpet, code)).AppendData(self.req).SetXid(self.req.Xid()))
}

func (self *ofmReply) putError(msg ofp4.ErrorMsg) {
	hdr := ofp4.Header(msg)
	if len(msg) == 12 {
		hdr = hdr.AppendData(self.req)
	}
	self.resps = append(self.resps, hdr.SetXid(self.req.Xid()))
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
	msg := ofp4.MakeHeader(ofp4.OFPT_ECHO_REPLY).AppendData(self.req[8:]).SetXid(self.req.Xid())
	self.resps = append(self.resps, msg)
	return self
}

type ofmExperimenter struct {
	ofmReply
}

func (self *ofmExperimenter) Map() Reducable {
	exp := ofp4.ExperimenterHeader(self.req)
	key := experimenterKey{
		Experimenter: exp.Experimenter(),
		ExpType:      exp.ExpType(),
	}
	if handler, ok := messageHandlers[key]; ok {
		for _, rep := range handler.Execute(exp[16:]) {
			msg := ofp4.MakeExperimenterHeader(exp.Experimenter(), exp.ExpType()).AppendData(rep).SetXid(self.req.Xid())
			self.resps = append(self.resps, msg)
		}
	} else {
		self.putError(ofp4.MakeErrorMsg(ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BAD_EXPERIMENTER))
	}
	return self
}

type ofmFeaturesRequest struct {
	ofmReply
}

func (self *ofmFeaturesRequest) Map() Reducable {
	msg := ofp4.MakeSwitchFeatures(
		self.ctrl.pipe.DatapathId,
		0x7fffffff,
		0xff, // nTables
		0,    // XXX: auxiliaryId
		0,    // XXX: capabilities
	)
	self.resps = append(self.resps, msg.SetXid(self.req.Xid()))
	return self
}

type ofmGetConfigRequest struct {
	ofmReply
}

func (self *ofmGetConfigRequest) Map() Reducable {
	msg := ofp4.MakeSwitchConfig(
		self.ctrl.pipe.flags, // xxx: FRAG not supported yet.
		self.ctrl.missSendLen,
	)
	self.resps = append(self.resps, msg.SetXid(self.req.Xid()))
	return self
}

type ofmSetConfig struct {
	ofmReply
}

func (self ofmSetConfig) Map() Reducable {
	config := ofp4.SwitchConfig(self.req)
	self.ctrl.pipe.flags = config.Flags()
	self.ctrl.missSendLen = config.MissSendLen()
	return self
}

type ofmGroupMod struct {
	ofmReply
}

func (self *ofmGroupMod) Map() Reducable {
	pipe := self.ctrl.pipe
	req := ofp4.GroupMod(self.req)

	switch req.Command() {
	case ofp4.OFPGC_ADD:
		if err := pipe.addGroup(req); err != nil {
			if e, ok := err.(ofp4.ErrorMsg); ok {
				self.putError(e)
			} else {
				log.Print(err)
			}
		}
	case ofp4.OFPGC_MODIFY:
		func() {
			pipe.lock.Lock()
			defer pipe.lock.Unlock()

			if group, exists := pipe.groups[req.GroupId()]; exists {
				var buckets bucketList
				if err := buckets.UnmarshalBinary(req.Buckets()); err != nil {
					log.Print(err)
				}
				group.groupType = req.Type()
				group.buckets = buckets
			} else {
				self.putError(ofp4.MakeErrorMsg(ofp4.OFPET_GROUP_MOD_FAILED, ofp4.OFPGMFC_UNKNOWN_GROUP))
			}
		}()
	case ofp4.OFPGC_DELETE:
		if err := func() error {
			pipe.lock.Lock()
			defer pipe.lock.Unlock()

			if req.GroupId() == ofp4.OFPG_ALL {
				for groupId, _ := range pipe.groups {
					if err := pipe.deleteGroupInside(groupId); err != nil {
						return err
					}
				}
			} else {
				return pipe.deleteGroupInside(req.GroupId())
			}
			return nil
		}(); err != nil {
			if e, ok := err.(ofp4.ErrorMsg); ok {
				self.putError(e)
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
	msg := ofp4.PortMod(self.req)

	for _, p := range pipe.getPorts(msg.PortNo()) {
		switch port := p.(type) {
		case *normalPort:
			port.config = msg.Config()&msg.Mask() | port.config&^msg.Mask()
			if msg.Advertise() != 0 { // zero all bits to prevent any action taking place.
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
	msg := ofp4.TableMod(self.req)
	for _, table := range self.ctrl.pipe.getFlowTables(msg.TableId()) {
		func() {
			table.lock.Lock()
			defer table.lock.Unlock()
			table.feature.config = msg.Config()
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
	msg := ofp4.PacketOut(self.req)

	var eth []byte
	if msg.BufferId() == ofp4.OFP_NO_BUFFER {
		eth = msg.Data()
	} else {
		func() {
			self.ctrl.lock.Lock()
			defer self.ctrl.lock.Unlock()

			if original, ok := self.ctrl.buffer[msg.BufferId()]; ok {
				delete(self.ctrl.buffer, msg.BufferId())
				if data, err := original.data.data(); err != nil {
					log.Print(err)
				} else {
					eth = data
				}
			} else {
				self.putError(ofp4.MakeErrorMsg(ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BUFFER_UNKNOWN))
			}
		}()
	}
	if eth != nil {
		data := &frame{
			serialized: eth,
			inPort:     msg.InPort(),
			phyInPort:  self.ctrl.pipe.getPortPhysicalPort(msg.InPort()),
		}
		var actions actionList
		actions.UnmarshalBinary(msg.Actions())

		var gouts []*outputToGroup
		for _, act := range []action(actions) {
			if pout, gout, e := act.Process(data); e != nil {
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
	msg := ofp4.FlowMod(self.req)

	switch msg.Command() {
	case ofp4.OFPFC_ADD:
		if err := self.ctrl.pipe.addFlowEntry(msg); err != nil {
			if e, ok := err.(ofp4.ErrorMsg); ok {
				self.putError(e)
			} else {
				log.Print(err)
			}
		}
	case ofp4.OFPFC_MODIFY, ofp4.OFPFC_MODIFY_STRICT:
		var reqMatch match
		if err := reqMatch.UnmarshalBinary(msg.Match().OxmFields()); err != nil {
			log.Print(err)
		} else if msg.TableId() > ofp4.OFPTT_MAX {
			self.putError(ofp4.MakeErrorMsg(ofp4.OFPET_FLOW_MOD_FAILED, ofp4.OFPFMFC_BAD_TABLE_ID))
		} else {
			filter := flowFilter{
				cookie:     msg.Cookie(),
				cookieMask: msg.CookieMask(),
				tableId:    msg.TableId(),
				outPort:    ofp4.OFPP_ANY,
				outGroup:   ofp4.OFPG_ANY,
				match:      reqMatch,
			}
			if msg.Command() == ofp4.OFPFC_MODIFY_STRICT {
				filter.priority = msg.Priority()
				filter.opStrict = true
			}
			for _, stat := range self.ctrl.pipe.filterFlows(filter) {
				flow := stat.flow
				if err := func() error {
					flow.lock.Lock()
					defer flow.lock.Unlock()

					if msg.Flags()&ofp4.OFPFF_RESET_COUNTS != 0 {
						flow.packetCount = 0
						flow.byteCount = 0
					}
					return flow.importInstructions(msg.Instructions())
				}(); err != nil {
					if e, ok := err.(ofp4.ErrorMsg); ok {
						self.putError(e)
					} else {
						log.Print(err)
					}
				}
			}
		}
	case ofp4.OFPFC_DELETE, ofp4.OFPFC_DELETE_STRICT:
		var reqMatch match
		if err := reqMatch.UnmarshalBinary(msg.Match().OxmFields()); err != nil {
			log.Print(err)
		} else {
			filter := flowFilter{
				opUnregister: true,
				cookie:       msg.Cookie(),
				cookieMask:   msg.CookieMask(),
				tableId:      msg.TableId(),
				outPort:      msg.OutPort(),
				outGroup:     msg.OutGroup(),
				match:        reqMatch,
			}
			if msg.Command() == ofp4.OFPFC_DELETE_STRICT {
				filter.priority = msg.Priority()
				filter.opStrict = true
			}
			for _, stat := range self.ctrl.pipe.filterFlows(filter) {
				if stat.flow.flags&ofp4.OFPFF_SEND_FLOW_REM != 0 {
					self.ctrl.sendFlowRem(stat.tableId, stat.priority, stat.flow, ofp4.OFPRR_DELETE)
				}
			}
		}
	}
	bufferId := msg.BufferId()
	if bufferId != ofp4.OFP_NO_BUFFER {
		original, ok := func() (*outputToPort, bool) {
			self.ctrl.lock.Lock()
			defer self.ctrl.lock.Unlock()

			original, ok := self.ctrl.buffer[bufferId]
			if ok {
				delete(self.ctrl.buffer, bufferId)
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
			self.putError(ofp4.MakeErrorMsg(ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BUFFER_UNKNOWN))
		}
	}
	return self
}

type ofmMulti struct {
	ofmReply
	reqs   [][]byte // multipart version of ofmReply.req
	chunks [][]byte // multipart response payload chunks
}

func (self *ofmMulti) Reduce() {
	msg := ofp4.MultipartRequest(self.req)
	payloadMaxLength := math.MaxUint16 - 16

	var payload []byte
	var payloadLength int
	for _, chunk := range self.chunks {
		payloadLength += len(chunk)
		if payloadLength >= payloadMaxLength {
			msg := ofp4.MakeMultipartReply(
				msg.Type(),
				ofp4.OFPMPF_REPLY_MORE,
				payload)
			self.resps = append(self.resps, msg.SetXid(self.req.Xid()))
			payload = payload[:0]
			payloadLength = 0
		}
		payload = append(payload, chunk...)
	}
	{
		msg := ofp4.MakeMultipartReply(
			msg.Type(),
			0,
			payload)
		self.resps = append(self.resps, msg.SetXid(self.req.Xid()))
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
		mreq := ofp4.FlowStatsRequest(req)
		var reqMatch match
		if e := reqMatch.UnmarshalBinary(mreq.Match().OxmFields()); e != nil {
			log.Print(e)
		} else {
			filter := flowFilter{
				tableId:    mreq.TableId(),
				outPort:    mreq.OutPort(),
				outGroup:   mreq.OutGroup(),
				cookie:     mreq.Cookie(),
				cookieMask: mreq.CookieMask(),
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
			chunk := ofp4.MakeFlowStats(
				f.tableId,
				uint32(duration.Seconds()),
				uint32(duration.Nanoseconds()%int64(time.Second)),
				f.priority,
				f.flow.idleTimeout,
				f.flow.hardTimeout,
				f.flow.flags, // OFPFF_
				f.flow.cookie,
				f.flow.packetCount,
				f.flow.byteCount,
				ofp4.MakeMatch(buf),
				f.flow.exportInstructions())
			self.chunks = append(self.chunks, chunk)
		}
	}
	return self
}

type ofmMpTable struct {
	ofmMulti
}

func (self *ofmMpTable) Map() Reducable {
	tables := self.ctrl.pipe.getFlowTables(ofp4.OFPTT_ALL)
	for tableId := uint8(0); tableId <= ofp4.OFPTT_MAX; tableId++ {
		if table, ok := tables[tableId]; ok {
			if table != nil {
				chunk := func() []byte {
					table.lock.RLock()
					defer table.lock.RUnlock()

					return ofp4.MakeTableStats(
						tableId,
						table.activeCount,
						table.lookupCount,
						table.matchCount)
				}()
				self.chunks = append(self.chunks, chunk)
			}
		} else {
			chunk := ofp4.MakeTableStats(
				tableId, 0, 0, 0)
			self.chunks = append(self.chunks, chunk)
		}
	}
	return self
}

type ofmMpAggregate struct {
	ofmMulti
}

func (self *ofmMpAggregate) Map() Reducable {
	mpreq := ofp4.MultipartRequest(self.req)
	mreq := ofp4.AggregateStatsRequest(mpreq.Body())

	var reqMatch match
	if err := reqMatch.UnmarshalBinary(mreq.Match().OxmFields()); err != nil {
		log.Print(err)
	} else {
		filter := flowFilter{
			tableId:    mreq.TableId(),
			outPort:    mreq.OutPort(),
			outGroup:   mreq.OutGroup(),
			cookie:     mreq.Cookie(),
			cookieMask: mreq.CookieMask(),
			match:      reqMatch,
		}
		var packetCount uint64
		var byteCount uint64
		var flowCount uint32
		for _, f := range self.ctrl.pipe.filterFlows(filter) {
			packetCount += f.flow.packetCount
			byteCount += f.flow.byteCount
			flowCount++
		}
		var chunk ofp4.AggregateStatsReply

		self.chunks = append(self.chunks, chunk)
	}
	return self
}

type ofmMpPortStats struct {
	ofmMulti
}

func (self *ofmMpPortStats) Map() Reducable {
	mpreq := ofp4.MultipartRequest(self.req)
	for portNo, bport := range self.ctrl.pipe.getPorts(ofp4.PortStatsRequest(mpreq.Body()).PortNo()) {
		switch port := bport.(type) {
		case *normalPort:
			pstats := port.Stats()
			duration := time.Now().Sub(port.created)
			chunk := ofp4.MakePortStats(
				portNo,
				pstats.RxPackets,
				pstats.TxPackets,
				pstats.RxBytes,
				pstats.TxBytes,
				0, // rxDropped
				0, // txDropped
				0, // rxErrors
				0, // txErrors
				0, // rxFrameErr
				0, // rxOverErr
				0, // rxCrcErr
				0, // collisions
				uint32(duration.Seconds()),
				uint32(duration.Nanoseconds()%int64(time.Second)),
			)
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
		var buckets []byte
		for _, b := range g.buckets {
			if bin, err := b.MarshalBinary(); err != nil {
				panic(err)
			} else {
				buckets = append(buckets, bin...)
			}
		}
		chunk := ofp4.MakeGroupDesc(
			g.groupType,
			i,
			buckets)
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

	chunk := ofp4.MakeGroupFeatures(
		1<<ofp4.OFPGT_ALL|1<<ofp4.OFPGT_SELECT|1<<ofp4.OFPGT_INDIRECT|1<<ofp4.OFPGT_FF,
		ofp4.OFPGFC_SELECT_WEIGHT|ofp4.OFPGFC_SELECT_LIVENESS|ofp4.OFPGFC_CHAINING|ofp4.OFPGFC_CHAINING_CHECKS,
		[...]uint32{ofp4.OFPG_MAX, ofp4.OFPG_MAX, ofp4.OFPG_MAX, ofp4.OFPG_MAX},
		[...]uint32{actionBits, actionBits, actionBits, actionBits})
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

	meterId := ofp4.MeterMultipartRequest(ofp4.MultipartRequest(self.req).Body()).MeterId()
	for meterId, meter := range pipe.getMeters(meterId) {
		duration := time.Now().Sub(meter.created)
		var bands []byte
		for _, b := range meter.bands {
			bands = append(bands, ofp4.MakeMeterBandStats(b.getPacketCount(), b.getByteCount())...)
		}
		flowCount := len(pipe.filterFlows(flowFilter{
			tableId:  ofp4.OFPTT_ALL,
			outPort:  ofp4.OFPP_ANY,
			outGroup: ofp4.OFPG_ANY,
			meterId:  meterId,
		}))
		chunk := ofp4.MakeMeterStats(
			meterId,
			uint32(flowCount),
			meter.packetCount,
			meter.byteCount,
			uint32(duration.Seconds()),
			uint32(duration.Nanoseconds()%int64(time.Second)),
			bands)
		self.chunks = append(self.chunks, chunk)
	}
	return self
}

type ofmMpMeterConfig struct {
	ofmMulti
}

func (self *ofmMpMeterConfig) Map() Reducable {
	mpreq := ofp4.MeterMultipartRequest(ofp4.MultipartRequest(self.req).Body())
	meterId := mpreq.MeterId()
	for meterId, meter := range self.ctrl.pipe.getMeters(meterId) {
		var bands []byte
		for _, b := range meter.bands {
			if bin, err := b.MarshalBinary(); err != nil {
				panic(err)
			} else {
				bands = append(bands, bin...)
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
		chunk := ofp4.MakeMeterConfig(flags, meterId, bands)
		self.chunks = append(self.chunks, chunk)
	}
	return self
}

type ofmMpTableFeatures struct {
	ofmMulti
}

func (self *ofmMpTableFeatures) Map() Reducable {
	if len(self.reqs) == 0 { // This is getter.
		tables := self.ctrl.pipe.getFlowTables(ofp4.OFPTT_ALL)
		for tableId := uint8(0); tableId <= ofp4.OFPTT_MAX; tableId++ {
			if table, ok := tables[tableId]; ok {
				if table != nil {
					f := table.feature
					chunk := ofp4.MakeTableFeatures(
						tableId,
						[]byte(f.name),
						f.metadataMatch,
						f.metadataWrite,
						f.config,
						f.maxEntries,
						f.exportProps())
					self.chunks = append(self.chunks, chunk)
				}
			} else {
				f := makeFlowTableFeature()
				chunk := ofp4.MakeTableFeatures(
					tableId,
					[]byte(f.name),
					f.metadataMatch,
					f.metadataWrite,
					f.config,
					f.maxEntries,
					f.exportProps())
				self.chunks = append(self.chunks, chunk)
			}
		}
	} else { // This is setter.
		pipe := self.ctrl.pipe
		pipe.lock.Lock()
		defer pipe.lock.Unlock()

		candidate := make(map[uint8]*flowTable)
		for _, msg := range self.reqs {
			for _, req := range ofp4.TableFeatures(msg).Iter() {
				feature := flowTableFeature{
					name:          string(req.Name()),
					metadataMatch: req.MetadataMatch(),
					metadataWrite: req.MetadataWrite(),
					config:        req.Config(),
					maxEntries:    req.MaxEntries(),
				}
				feature.importProps(req.Properties())

				if tbl := pipe.flows[req.TableId()]; tbl == nil {
					// table explicitly set to nil means, "that table does not exists."
					self.createError(ofp4.OFPET_TABLE_FEATURES_FAILED, ofp4.OFPTFFC_BAD_TABLE)
				} else if _, ok := candidate[req.TableId()]; ok {
					// DUP in request
					self.createError(ofp4.OFPET_TABLE_FEATURES_FAILED, ofp4.OFPTFFC_EPERM)
				} else {
					candidate[req.TableId()] = &flowTable{
						lock:    &sync.RWMutex{},
						feature: feature,
					}
				}
			}
		}
		for i := uint8(0); i <= ofp4.OFPTT_MAX; i++ {
			if newTable, ok := candidate[i]; ok {
				if oldTable, ok := pipe.flows[i]; ok && oldTable != nil {
					for _, prio := range oldTable.priorities {
						var newFlows []*flowEntry
						for _, flows := range prio.flows {
							for _, flow := range flows {
								if err := newTable.feature.accepts(flow, prio.priority); err == nil {
									newFlows = append(newFlows, flow)
								} else {
									log.Print(err) // notification
								}
							}
						}
						prio.rebuildIndex(newFlows)
					}
					oldTable.feature = newTable.feature
				}
			} else {
				pipe.flows[i] = nil
			}
		}
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
			portState := port.State()

			var state uint32
			if portState.LinkDown {
				state |= ofp4.OFPPS_LINK_DOWN
			}
			if portState.Blocked {
				state |= ofp4.OFPPS_BLOCKED
			}
			if port.config&ofp4.OFPPC_PORT_DOWN == 0 && state&ofp4.OFPPS_LINK_DOWN == 0 {
				state |= ofp4.OFPPS_LIVE
			}

			chunk := ofp4.MakePort(
				portNo,
				portState.HwAddr,
				[]byte(port.public.Name()),
				port.config,
				state,
				portState.Curr,
				portState.Advertised,
				portState.Supported,
				portState.Peer,
				portState.CurrSpeed,
				portState.MaxSpeed)
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
	msg := ofp4.MakeHeader(ofp4.OFPT_BARRIER_REPLY).SetXid(self.req.Xid())
	self.resps = append(self.resps, msg)
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

	req := ofp4.MeterMod(self.req)
	switch req.Command() {
	case ofp4.OFPMC_ADD:
		meterId := req.MeterId()
		if meterId == 0 || (meterId > ofp4.OFPM_MAX && meterId != ofp4.OFPM_CONTROLLER) {
			self.putError(ofp4.MakeErrorMsg(ofp4.OFPET_METER_MOD_FAILED, ofp4.OFPMMFC_INVALID_METER))
		} else {
			var bands bandList
			if err := bands.UnmarshalBinary(req.Bands()); err != nil {
				log.Print(err)
			}

			var highestBand band
			for _, b := range bands {
				if highestBand == nil || highestBand.getRate() < b.getRate() {
					highestBand = b
				}
			}
			newMeter := &meter{
				lock:        &sync.Mutex{},
				created:     time.Now(),
				bands:       bands,
				highestBand: highestBand,
			}
			if req.Flags()&ofp4.OFPMF_PKTPS != 0 {
				newMeter.flagPkts = true
			}
			if req.Flags()&ofp4.OFPMF_BURST != 0 {
				newMeter.flagBurst = true
			}
			if req.Flags()&ofp4.OFPMF_STATS != 0 {
				newMeter.flagStats = true
			}

			if err := func() error {
				pipe.lock.Lock()
				defer pipe.lock.Unlock()

				if _, exists := pipe.meters[meterId]; exists {
					return ofp4.MakeErrorMsg(
						ofp4.OFPET_METER_MOD_FAILED,
						ofp4.OFPMMFC_METER_EXISTS,
					)
				} else {
					pipe.meters[meterId] = newMeter
				}
				return nil
			}(); err != nil {
				if e, ok := err.(ofp4.ErrorMsg); ok {
					self.putError(e)
				} else {
					log.Print(err)
				}
			}
		}
	case ofp4.OFPMC_DELETE:
		meterId := req.MeterId()
		if err := func() error {
			pipe.lock.Lock()
			defer pipe.lock.Unlock()

			if meterId == ofp4.OFPM_ALL {
				for meterId, _ := range pipe.meters {
					pipe.deleteMeterInside(meterId)
				}
			} else {
				return pipe.deleteMeterInside(meterId)
			}
			return nil
		}(); err != nil {
			if e, ok := err.(ofp4.ErrorMsg); ok {
				self.putError(e)
			} else {
				log.Print(err)
			}
		}
	case ofp4.OFPMC_MODIFY:
		// XXX:
	}
	return self
}
