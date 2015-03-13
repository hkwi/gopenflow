package ofp4sw

import (
	"github.com/hkwi/gopenflow"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
	"math"
	"sync"
	"time"
)

var messageHandlers map[experimenterKey]MessageHandler = make(map[experimenterKey]MessageHandler)

func AddMessageHandler(experimenter uint32, expType uint32, handler MessageHandler) {
	messageHandlers[experimenterKey{
		Experimenter: experimenter,
		ExpType:      expType,
	}] = handler
}

type ofmReply struct {
	pipe    *Pipeline
	channel *channel
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
		for len(resp) > 0 {
			if n, err := self.channel.Conn.Write(resp); err != nil {
				log.Print(err)
				if err := self.channel.Conn.Close(); err != nil {
					log.Print(err)
				}
				return
			} else {
				resp = resp[n:]
			}
		}
	}
}

// dummy Map to create ofp_error
func (self *ofmReply) Map() Reducable {
	return self
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
		self.pipe.DatapathId,
		0x7fffffff,
		0xff, // nTables
		0,    // XXX: auxiliaryId
		ofp4.OFPC_FLOW_STATS|ofp4.OFPC_TABLE_STATS|ofp4.OFPC_PORT_STATS|ofp4.OFPC_GROUP_STATS, // XXX: capabilities
	)
	self.resps = append(self.resps, msg.SetXid(self.req.Xid()))
	return self
}

type ofmGetConfigRequest struct {
	ofmReply
}

func (self *ofmGetConfigRequest) Map() Reducable {
	msg := ofp4.MakeSwitchConfig(
		self.pipe.flags, // xxx: FRAG not supported yet.
		self.pipe.missSendLen,
	)
	self.resps = append(self.resps, msg.SetXid(self.req.Xid()))
	return self
}

type ofmSetConfig struct {
	ofmReply
}

func (self ofmSetConfig) Map() Reducable {
	config := ofp4.SwitchConfig(self.req)
	self.pipe.flags = config.Flags()
	self.pipe.missSendLen = config.MissSendLen()
	return self
}

type ofmGroupMod struct {
	ofmReply
}

func (self *ofmGroupMod) Map() Reducable {
	pipe := self.pipe
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
	pipe := self.pipe
	msg := ofp4.PortMod(self.req)

	var confs []gopenflow.PortConfig
	for _, config := range []uint32{
		ofp4.OFPPC_PORT_DOWN,
		ofp4.OFPPC_NO_RECV,
		ofp4.OFPPC_NO_FWD,
		ofp4.OFPPC_NO_PACKET_IN,
	} {
		if msg.Mask()&config != 0 {
			switch config {
			case ofp4.OFPPC_PORT_DOWN:
				confs = append(confs, gopenflow.PortConfigPortDown(msg.Config()&config != 0))
			case ofp4.OFPPC_NO_RECV:
				confs = append(confs, gopenflow.PortConfigNoRecv(msg.Config()&config != 0))
			case ofp4.OFPPC_NO_FWD:
				confs = append(confs, gopenflow.PortConfigNoFwd(msg.Config()&config != 0))
			case ofp4.OFPPC_NO_PACKET_IN:
				confs = append(confs, gopenflow.PortConfigNoPacketIn(msg.Config()&config != 0))
			}
		}
	}
	// ofp_port_mod looks for normal port only.
	if port := pipe.getPort(msg.PortNo()); port != nil {
		port.SetConfig(confs)
	} else {
		self.putError(ofp4.MakeErrorMsg(ofp4.OFPET_PORT_MOD_FAILED, ofp4.OFPPMFC_BAD_PORT))
	}
	return self
}

type ofmTableMod struct {
	ofmReply
}

func (self ofmTableMod) Map() Reducable {
	msg := ofp4.TableMod(self.req)
	for _, table := range self.pipe.getFlowTables(msg.TableId()) {
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
	outputs []outputToPort
}

func (self ofmOutput) Reduce() {
	for _, output := range self.outputs {
		if err := self.pipe.sendOutput(output); err != nil {
			if ofe, ok := err.(ofp4.ErrorMsg); ok {
				self.putError(ofe)
				break
			} else {
				log.Print(err)
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
			self.pipe.lock.Lock()
			defer self.pipe.lock.Unlock()

			if original, ok := self.pipe.buffer[msg.BufferId()]; ok {
				delete(self.pipe.buffer, msg.BufferId())
				if data, err := original.Serialized(); err != nil {
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
		data := &Frame{
			serialized: eth,
			inPort:     msg.InPort(),
			inPhyPort:  self.pipe.getPort(msg.InPort()).PhysicalPort(),
		}
		var actions actionList
		actions.UnmarshalBinary(msg.Actions())

		var gouts []outputToGroup
		for _, act := range []action(actions) {
			if pout, gout, e := act.Process(data); e != nil {
				log.Print(e)
			} else {
				if pout != nil {
					self.outputs = append(self.outputs, *pout)
				}
				if gout != nil {
					gouts = append(gouts, *gout)
				}
			}
		}
		self.outputs = append(self.outputs, self.pipe.groupToOutput(gouts, nil)...)
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
		if err := self.pipe.addFlowEntry(msg); err != nil {
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
			for _, stat := range self.pipe.filterFlows(filter) {
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
			for _, stat := range self.pipe.filterFlows(filter) {
				if stat.flow.flags&ofp4.OFPFF_SEND_FLOW_REM != 0 {
					self.pipe.sendFlowRem(stat.tableId, stat.priority, stat.flow, ofp4.OFPRR_DELETE)
				}
			}
		}
	}
	bufferId := msg.BufferId()
	if bufferId != ofp4.OFP_NO_BUFFER {
		original, ok := func() (outputToPort, bool) {
			self.pipe.lock.Lock()
			defer self.pipe.lock.Unlock()

			original, ok := self.pipe.buffer[bufferId]
			if ok {
				delete(self.pipe.buffer, bufferId)
			}
			return original, ok
		}()
		if ok {
			pipe := self.pipe
			pipe.datapath <- &flowTask{
				Frame:   original.Frame,
				pipe:    self.pipe,
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

	log.Print(self.pipe.Desc)

	self.chunks = append(self.chunks, self.pipe.Desc)
	return self
}

type ofmMpFlow struct {
	ofmMulti
}

func (self *ofmMpFlow) Map() Reducable {
	pipe := self.pipe

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
	tables := self.pipe.getFlowTables(ofp4.OFPTT_ALL)
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
		for _, f := range self.pipe.filterFlows(filter) {
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

	proc := func(portNo uint32, port gopenflow.Port) {
		var pstats gopenflow.PortStats
		var ethinfo gopenflow.PortStatsEthernet
		if p, err := port.Stats(); err != nil {
			log.Print(err)
		} else {
			pstats = p
			if p.Ethernet != nil {
				ethinfo = *p.Ethernet
			}
		}
		duration := self.pipe.portAlive[portNo].Total()
		chunk := ofp4.MakePortStats(
			portNo,
			pstats.RxPackets,
			pstats.TxPackets,
			pstats.RxBytes,
			pstats.TxBytes,
			pstats.RxDropped,
			pstats.TxDropped,
			pstats.RxErrors,
			pstats.TxErrors,
			ethinfo.RxFrameErr,
			ethinfo.RxOverErr,
			ethinfo.RxCrcErr,
			ethinfo.Collisions,
			uint32(duration.Seconds()),
			uint32(duration.Nanoseconds()%int64(time.Second)),
		)
		self.chunks = append(self.chunks, chunk)
	}

	portNo := ofp4.PortStatsRequest(mpreq.Body()).PortNo()
	switch portNo {
	default:
		if portNo > 0 && portNo <= ofp4.OFPP_MAX {
			if port := self.pipe.getPort(portNo); port != nil {
				proc(portNo, port)
			} else {
				self.putError(ofp4.MakeErrorMsg(ofp4.OFPET_PORT_MOD_FAILED, ofp4.OFPPMFC_BAD_PORT))
			}
		} else {
			self.putError(ofp4.MakeErrorMsg(ofp4.OFPET_PORT_MOD_FAILED, ofp4.OFPPMFC_BAD_PORT))
		}
	case ofp4.OFPP_ALL, ofp4.OFPP_ANY:
		for portNo, port := range self.pipe.getAllPorts() {
			proc(portNo, port)
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
	for i, g := range self.pipe.getGroups(ofp4.OFPG_ALL) {
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
	pipe := self.pipe

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
	for meterId, meter := range self.pipe.getMeters(meterId) {
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
		tables := self.pipe.getFlowTables(ofp4.OFPTT_ALL)
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
		pipe := self.pipe
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
	for portNo, port := range self.pipe.getAllPorts() {
		self.chunks = append(self.chunks, makePort(portNo, port))
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
	pipe := self.pipe

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
