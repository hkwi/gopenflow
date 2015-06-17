/*
Package ofp4sw implements openflow 1.3 switch.
*/
package ofp4sw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/hkwi/gopenflow"
	"github.com/hkwi/gopenflow/ofp4"
	"io"
	"log"
	"math"
	"sync"
	"time"
)

type Pipeline struct {
	lock *sync.RWMutex
	// special rule for flows: value nil means that the table is forbidden by table feature spec.
	flows    map[uint8]*flowTable
	groups   map[uint32]*group
	meters   map[uint32]*meter
	datapath chan MapReducable

	ports        map[uint32]gopenflow.Port
	portSnapshot map[uint32]ofp4.Port
	portAlive    map[uint32]watchTimer

	channels     []*channel
	buffer       map[uint32]outputToPort
	nextBufferId uint32

	DatapathId  uint64
	Desc        ofp4.Desc
	flags       uint16 // ofp_config_flags, check capability
	missSendLen uint16
}

type channel struct {
	Conn      io.ReadWriteCloser
	Xid       uint32
	Auxiliary uint8
	// XXX: MASTER/SLAVE/EQUAL
	packetInMask    [2]uint32
	portStatusMask  [2]uint32
	flowRemovedMask [2]uint32
}

func NewPipeline() *Pipeline {
	self := &Pipeline{
		lock:         &sync.RWMutex{},
		flows:        make(map[uint8]*flowTable),
		groups:       make(map[uint32]*group),
		meters:       make(map[uint32]*meter),
		datapath:     make(chan MapReducable),
		ports:        make(map[uint32]gopenflow.Port),
		portSnapshot: make(map[uint32]ofp4.Port),
		portAlive:    make(map[uint32]watchTimer),
		buffer:       make(map[uint32]outputToPort),
		Desc:         ofp4.Desc(make([]byte, 1056)),
		missSendLen:  ofp4.OFPCML_NO_BUFFER,
	}
	go func() {
		for {
			time.Sleep(time.Second)
			self.validate(time.Now())
		}
	}()
	go MapReduce(self.datapath, 4) // XXX: NUM_CPUS
	return self
}

// SetPort sets a port in a specified portNo. To unset the port, pass nil as port argument.
func (self *Pipeline) AddPort(port gopenflow.Port) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	portNo := uint32(1)
	for idx, p := range self.ports {
		if p == port {
			return fmt.Errorf("port already registered")
		}
		if idx >= portNo {
			portNo = idx + 1
		}
	}
	if portNo > ofp4.OFPP_MAX {
		return fmt.Errorf("no port number available")
		// we may reuse the port number
	}
	self.ports[portNo] = port
	self.portAlive[portNo] = watchTimer{}
	updateTimer := func(ofpPort []byte) {
		wt := self.portAlive[portNo]
		if ofp4.Port(ofpPort).State()&ofp4.OFPPS_LIVE != 0 {
			if wt.Active == nil {
				save := time.Now()
				wt.Active = &save
				self.portAlive[portNo] = wt
			}
		} else {
			if wt.Active != nil {
				wt.Past += time.Now().Sub(*wt.Active)
				wt.Active = nil
				self.portAlive[portNo] = wt
			}
		}
	}

	// add port first.
	ofpPort := makePort(portNo, port)
	self.portSnapshot[portNo] = ofpPort
	updateTimer(ofpPort)
	for _, ch := range self.channels {
		ch.Notify(ofp4.MakePortStatus(ofp4.OFPPR_ADD, ofpPort))
	}

	pktIngress := make(chan bool)
	go func() {
		for pkt := range port.Ingress() {
			oob := match(make(map[OxmKey]OxmPayload))
			if err := oob.UnmarshalBinary(pkt.Oob); err != nil {
				log.Print(err)
			} else {
				self.datapath <- &flowTask{
					Frame: Frame{
						serialized: pkt.Data,
						inPort:     portNo,
						inPhyPort:  port.PhysicalPort(),
						Oob:        oob,
					},
					pipe: self,
				}
			}
		}
		pktIngress <- true
	}()
	go func() {
		for _ = range port.Monitor() {
			ofpPort := makePort(portNo, port)
			if bytes.Equal(ofpPort, self.portSnapshot[portNo]) {
				continue
			} else {
				self.portSnapshot[portNo] = ofpPort
			}
			for _, ch := range self.channels {
				ch.Notify(ofp4.MakePortStatus(ofp4.OFPPR_MODIFY, ofpPort))
			}
			updateTimer(ofpPort)
		}
		for _, ch := range self.channels {
			ch.Notify(ofp4.MakePortStatus(ofp4.OFPPR_DELETE, self.portSnapshot[portNo]))
		}
		<-pktIngress
		delete(self.ports, portNo)
		delete(self.portSnapshot, portNo)
		delete(self.portAlive, portNo)
	}()
	return nil
}

func (self *Pipeline) AddChannel(conn io.ReadWriteCloser) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	ch := &channel{
		Conn: conn,
	}

	// process hello
	ch.Notify(ofp4.MakeHello(ofp4.MakeHelloElemVersionbitmap([]uint32{uint32(1 << 4)})))
	head := make([]byte, 4)
	if msg, err := readOfpMessage(conn, head); err != nil {
		return err
	} else if ofp4.Header(msg).Type() != ofp4.OFPT_HELLO {
		return fmt.Errorf("The first message must be HELLO")
	} else {
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
		if !satisfied && ofp4.Header(msg).Version() == 4 {
			satisfied = true
		}
		if !satisfied {
			err := ofp4.MakeErrorMsg(
				ofp4.OFPET_HELLO_FAILED,
				ofp4.OFPHFC_INCOMPATIBLE,
			)
			ch.Response(ofp4.Header(err).SetXid(ofp4.Header(msg).Xid()))
			return err
		}
	}

	self.channels = append(self.channels, ch)

	worker := make(chan MapReducable)
	go MapReduce(worker, 4)
	go func() {
		defer close(worker)
		defer conn.Close()

		multipartCollect := make(map[uint32][][]byte)
		for {
			msg, err := readOfpMessage(conn, head)
			if err != nil {
				log.Print(err)
				break
			}
			reply := ofmReply{pipe: self, channel: ch, req: msg}
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
				for xid, _ := range multipartCollect {
					buf := ofp4.Header(make([]byte, 8))
					buf.SetXid(xid)
					rep := ofmReply{pipe: self, channel: ch, req: buf}
					rep.createError(ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BAD_MULTIPART)
					worker <- &rep
					delete(multipartCollect, xid)
				}
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
			// xxx:
			// log.Print(msg)
		}
	}()
	return nil
}

func (pipe Pipeline) getFlowTable(tableId uint8) *flowTable {
	pipe.lock.RLock()
	defer pipe.lock.RUnlock()
	return pipe.flows[tableId]
}

func (pipe Pipeline) getFlowTables(tableId uint8) map[uint8]*flowTable {
	var buf map[uint8]*flowTable
	if tableId == ofp4.OFPTT_ALL {
		buf = make(map[uint8]*flowTable, len(pipe.flows))
	} else {
		buf = make(map[uint8]*flowTable, 1)
	}

	pipe.lock.RLock()
	defer pipe.lock.RUnlock()

	if tableId == ofp4.OFPTT_ALL {
		for k, v := range pipe.flows {
			buf[k] = v
		}
	} else {
		if table, ok := pipe.flows[tableId]; ok {
			buf[tableId] = table
		}
	}
	return buf
}

func (pipe Pipeline) getGroup(groupId uint32) *group {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()
	return pipe.groups[groupId]
}

func (pipe Pipeline) getGroups(groupId uint32) map[uint32]*group {
	groups := make(map[uint32]*group)

	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	if groupId == ofp4.OFPG_ALL {
		for k, g := range pipe.groups {
			groups[k] = g
		}
	} else {
		if group, ok := pipe.groups[groupId]; ok {
			groups[groupId] = group
		}
	}
	return groups
}

// Call this function inside a pipeline transaction
func (p Pipeline) watchGroup(groupId uint32) bool {
	if group, ok := p.groups[groupId]; ok {
		for _, b := range group.buckets {
			if b.watchPort != ofp4.OFPP_ANY {
				if p.watchPort(b.watchPort) {
					return true
				}
			}
			if b.watchGroup != ofp4.OFPG_ANY {
				if p.watchGroup(b.watchGroup) {
					return true
				}
			}
		}
	}
	return false
}

// Call this function inside a pipeline transaction
func (p Pipeline) watchPort(portNo uint32) bool {
	if port, ok := p.ports[portNo]; ok {
		for _, s := range port.State() {
			switch v := s.(type) {
			case gopenflow.PortStateLive:
				return bool(v)
			}
		}
	}
	return false
}

func (pipe Pipeline) getMeter(meterId uint32) *meter {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()
	return pipe.meters[meterId]
}

func (pipe Pipeline) getMeters(meterId uint32) map[uint32]*meter {
	meters := make(map[uint32]*meter)

	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	if meterId == ofp4.OFPM_ALL {
		for k, m := range pipe.meters {
			meters[k] = m
		}
	} else {
		if meter, ok := pipe.meters[meterId]; ok {
			meters[meterId] = meter
		}
	}
	return meters
}

// panic in out of range
func (pipe Pipeline) getPort(portNo uint32) gopenflow.Port {
	if portNo == 0 || portNo > ofp4.OFPP_MAX {
		panic("invalid portNo")
	}
	pipe.lock.Lock()
	defer pipe.lock.Unlock()
	return pipe.ports[portNo]
}

// rename to all or any
func (pipe Pipeline) getAllPorts() map[uint32]gopenflow.Port {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	ports := make(map[uint32]gopenflow.Port)
	for k, g := range pipe.ports {
		ports[k] = g
	}
	return ports
}

func (self *Pipeline) packetIn(buffer_id uint32, pout outputToPort) error {
	if fr, err := pout.getFrozen(); err != nil {
		return err
	} else {
		totalLen := len(fr.Data)
		if int(pout.maxLen) < totalLen {
			fr.Data = fr.Data[:pout.maxLen]
		}
		msg := ofp4.MakePacketIn(buffer_id,
			uint16(totalLen),
			pout.reason,
			pout.tableId,
			pout.cookie,
			ofp4.MakeMatch(fr.Oob),
			fr.Data)

		for _, ch := range self.channels {
			if ch.packetInMask[0]&(1<<pout.reason) == 0 {
				ch.Notify(msg)
			}
		}
		return nil
	}
}

/* OFPT_FLOW_REMOVED async message */
func (self *Pipeline) sendFlowRem(tableId uint8, priority uint16, flow *flowEntry, reason uint8) {
	if fields, err := flow.fields.MarshalBinary(); err != nil {
		log.Print(err)
	} else {
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

		for _, ch := range self.channels {
			if ch.flowRemovedMask[0]&(1<<reason) == 0 {
				ch.Notify(msg)
			}
		}
	}
}

func (pipe *Pipeline) sendOutput(output outputToPort) error {
	if output.isInvalid() {
		return fmt.Errorf("invalid packet")
	}
	switch output.outPort {
	default:
		portNo := output.outPort
		if 0 < portNo && portNo <= ofp4.OFPP_MAX {
			if port := pipe.getPort(portNo); port == nil {
				return fmt.Errorf("output port missing %d", portNo)
			} else if fr, err := output.getFrozen(); err != nil {
				return err
			} else {
				port.Egress(fr)
			}
		} else {
			return fmt.Errorf("unknown output special port")
		}
	case ofp4.OFPP_IN_PORT:
		if port := pipe.getPort(output.inPort); port == nil {
			return fmt.Errorf("output port missing %d", output.inPort)
		} else if fr, err := output.getFrozen(); err != nil {
			return err
		} else {
			port.Egress(fr)
		}
	case ofp4.OFPP_TABLE:
		defer func() {
			pipe.datapath <- &flowTask{
				Frame: output.Frame,
				pipe:  pipe,
			}
		}()
	case ofp4.OFPP_NORMAL, ofp4.OFPP_FLOOD, ofp4.OFPP_ALL:
		inPort := pipe.getPort(output.inPort)
		if fr, err := output.getFrozen(); err != nil {
			return err
		} else {
			for _, port := range pipe.getAllPorts() {
				if port != inPort {
					port.Egress(fr)
				}
			}
		}
	case ofp4.OFPP_CONTROLLER:
		if nopktin := func() bool {
			for _, config := range pipe.getPort(output.inPort).GetConfig() {
				if flag, ok := config.(gopenflow.PortConfigNoPacketIn); ok && bool(flag) {
					return true
				}
			}
			return false
		}(); nopktin {
			return nil
		}
		var buffer_id uint32
		if output.reason == ofp4.OFPR_INVALID_TTL {
			output.maxLen = pipe.missSendLen
		}
		if output.maxLen == ofp4.OFPCML_NO_BUFFER {
			buffer_id = ofp4.OFP_NO_BUFFER
		} else {
			buffer_id = func() uint32 {
				pipe.lock.Lock()
				defer pipe.lock.Unlock()

				for len(pipe.buffer) <= math.MaxInt32 { // may limit by ofp_switch_features.n_buffers
					buffer_id = pipe.nextBufferId
					pipe.nextBufferId++
					if _, ok := pipe.buffer[buffer_id]; !ok {
						pipe.buffer[buffer_id] = output
						return buffer_id
					}
				}
				return ofp4.OFP_NO_BUFFER
			}()
		}
		if buffer_id == ofp4.OFP_NO_BUFFER {
			output.maxLen = ofp4.OFPCML_NO_BUFFER
		}
		// XXX: need to implement queue here
		pipe.packetIn(buffer_id, output)
	}
	return nil
}

func (self *channel) Response(msg []byte) error {
	for len(msg) > 0 {
		if n, err := self.Conn.Write(msg); err != nil {
			return err
		} else {
			msg = msg[n:]
		}
	}
	return nil
}

func (self *channel) Notify(msg []byte) error {
	binary.BigEndian.PutUint32(msg[4:8], self.Xid)
	self.Xid++
	return self.Response(msg)
}
