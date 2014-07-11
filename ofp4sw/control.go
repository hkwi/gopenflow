package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"encoding"
	"errors"
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"math/rand"
	"time"
)

type controller struct {
	commands chan func()
	clusters map[uint32]*controlCluster
	egress   chan packetOut
	buffer   map[uint32]*packetOut

	missSendLen uint16
	desc        ofp4.Desc
}

const (
	mode_equal  = 0
	mode_master = 1
	mode_slave  = 2
)

type controlCluster struct {
	mode uint8
	main ControlChannel
	aux  map[uint8]ControlChannel
}

type ControlChannel interface {
	Transaction() transaction
	Ingress() <-chan []byte
	Egress() chan<- []byte
	Close()
}

type transaction struct {
	commands chan func()
	current  uint32
	xids     map[uint32]*xid
}

type xid struct {
	oftype  uint8
	release []chan bool
	multi   []ofp4.MultipartRequest
}

func NewTransaction() transaction {
	tr := transaction{
		commands: make(chan func()),
		xids:     make(map[uint32]*xid),
	}
	go func() {
		for cmd := range tr.commands {
			if cmd != nil {
				cmd()
			} else {
				break
			}
		}
	}()
	return tr
}

func newController() controller {
	port := controller{
		commands:    make(chan func()),
		egress:      make(chan packetOut, 4),
		clusters:    make(map[uint32]*controlCluster),
		buffer:      make(map[uint32]*packetOut),
		missSendLen: 128,
	}
	go func() {
		for cmd := range port.commands {
			if cmd != nil {
				cmd()
			} else {
				break
			}
		}
	}()
	go func() {
		for pout := range port.egress {
			// XXX: need to implement queue here

			var buffer_id uint32

			ch := make(chan error)
			port.commands <- func() {
				ch <- func() error {
					for i := 0; i < 32; i++ {
						buffer_id = uint32(rand.Int31())
						if _, ok := port.buffer[buffer_id]; !ok {
							port.buffer[buffer_id] = &pout
							return nil
						}
					}
					return errors.New("No buffer_id room")
				}()
				close(ch)
			}
			if err := <-ch; err != nil {
				panic(err)
			} else {
				port.commands <- func() {
					for _, cluster := range port.clusters {
						switch cluster.mode {
						default:
							channel := cluster.main
							pout2 := pout
							go channel.Transaction().packetIn(buffer_id, pout2, channel)
						case mode_slave:
							// do not packet_in
						}
					}
				}
			}
		}
	}()
	return port
}
func (c controller) Egress() chan<- packetOut { return c.egress }

func (c controller) addControlChannel(con ControlChannel, pipe Pipeline) error {
	ch := make(chan ControlChannel)
	c.commands <- func() {
		ch <- func() ControlChannel {
			var index uint32
			for i := 0; i < 4; i++ {
				index = uint32(rand.Int31())
				if _, exists := c.clusters[index]; !exists {
					c.clusters[index] = &controlCluster{main: con}
					return con
				}
			}
			return nil
		}()
		close(ch)
	}
	if con := <-ch; con != nil {
		if xid, err := con.Transaction().newXid(); err != nil {
			con.Close()
		} else {
			_ = xid
			msg := ofp4.Message{
				Header: ofp4.Header{
					Version: 4,
					Type:    ofp4.OFPT_HELLO,
					Xid:     xid,
				},
				Body: ofp4.Array{
					&ofp4.HelloElementVersionbitmap{
						Bitmaps: []uint32{uint32(1 << 4)},
					},
				},
			}
			if msgbin, err := msg.MarshalBinary(); err != nil {
				con.Close()
			} else {
				con.Egress() <- msgbin
			}
		}

		go func() {
			for msg := range con.Ingress() {
				if msg == nil {
					break
				}
				var ofm ofp4.Message
				if err := ofm.UnmarshalBinary(msg); err != nil {
					fmt.Println(err)
					break
				}
				con.Transaction().handleMessage(ofm, pipe, con)
			}
			con.Close()
			c.commands <- func() {
				for k, v := range c.clusters {
					if v.main == con {
						delete(c.clusters, k)
					}
				}
			}
		}()
	} else {
		return errors.New("channel register failed")
	}
	return nil
}

func (x transaction) handleMessage(ofm ofp4.Message, pipe Pipeline, con ControlChannel) {
	x.commands <- func() {
		count := 0
		ch := make(chan bool)
		xidSelf := &xid{oftype: ofm.Type}
		var multi []ofp4.MultipartRequest

		if ofp4.MessageType(ofm.Type) == ofp4.MSG_REQUEST {
			if ofm.Type == ofp4.OFPT_MULTIPART_REQUEST {
				req := ofm.Body.(*ofp4.MultipartRequest)
				if (req.Flags & ofp4.OFPMPF_REQ_MORE) != uint16(0) {
					if groupXid, ok := x.xids[ofm.Xid]; ok {
						xidSelf = groupXid
					}
					xidSelf.multi = append(xidSelf.multi, *req)
					return
				} else {
					multi = xidSelf.multi
					xidSelf.multi = nil
				}
			}

			if ofm.Type == ofp4.OFPT_BARRIER_REQUEST {
				for _, v := range x.xids {
					if ofp4.MessageType(v.oftype) == ofp4.MSG_REQUEST && v.multi == nil {
						v.release = append(v.release, ch)
						count++
					}
				}
			} else {
				for _, v := range x.xids {
					if v.oftype == ofp4.OFPT_BARRIER_REQUEST && v.multi == nil {
						v.release = append(v.release, ch)
						count++
					}
				}
			}
			x.xids[ofm.Xid] = xidSelf
		}
		go func() {
			response := x.handle(ofm, multi, pipe, con)
			for i := 0; i < count; i++ {
				_ = <-ch
			}
			x.commands <- func() {
				for _, msg := range response {
					fmt.Println("res", msg)
					con.Egress() <- msg
				}
				for k, v := range x.xids {
					if v == xidSelf {
						delete(x.xids, k)
					}
				}
				for _, ch2 := range xidSelf.release {
					ch2 <- true
				}
			}
		}()
	}
}

func (x transaction) newXid() (uint32, error) {
	var xidKey uint32
	ch := make(chan error)
	x.commands <- func() {
		ch <- func() error {
			for i := 0; i < 8; i++ {
				xidKey = uint32(rand.Int31())
				if _, ok := x.xids[xidKey]; !ok {
					return nil
				}
			}
			return errors.New("No room for packet_in xid")
		}()
		close(ch)
	}
	if err := <-ch; err != nil {
		return 0, err
	}
	return xidKey, nil
}

func (x transaction) packetIn(buffer_id uint32, pout packetOut, channel ControlChannel) {
	if xid, err := x.newXid(); err != nil {
		channel.Close()
	} else {
		data := pout.data
		if int(pout.maxLen) < len(pout.data) {
			data = pout.data[:pout.maxLen]
		}

		msg := ofp4.Message{
			Header: ofp4.Header{
				Version: 4,
				Type:    ofp4.OFPT_PACKET_IN,
				Xid:     xid,
			},
			Body: ofp4.PacketIn{
				BufferId: buffer_id,
				TotalLen: uint16(len(pout.data)),
				Reason:   pout.reason,
				TableId:  pout.tableId,
				Data:     data,
			},
		}
		if msgbin, err := msg.MarshalBinary(); err != nil {
			panic(err)
		} else {
			channel.Egress() <- msgbin
		}
	}
}

func (x transaction) handle(ofm ofp4.Message, multi []ofp4.MultipartRequest, pipe Pipeline, con ControlChannel) [][]byte {
	fmt.Println("req", ofm)
	var respMessages [][]byte
	var err error

	switch ofm.Type {
	case ofp4.OFPT_HELLO:
		satisfied := false
		for _, element := range []encoding.BinaryMarshaler(ofm.Body.(ofp4.Array)) {
			switch telement := element.(type) {
			case ofp4.HelloElementVersionbitmap:
				bitmaps := telement.Bitmaps
				if len(bitmaps) > 0 && (bitmaps[0]&(1<<4) != 0) {
					satisfied = true
				}
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
			err = &ofp4.Error{
				Type: ofp4.OFPET_HELLO_FAILED,
				Code: ofp4.OFPHFC_INCOMPATIBLE,
			}
		}
	case ofp4.OFPT_ECHO_REQUEST:
		msg := ofp4.Message{
			Header: ofp4.Header{
				Version: 4,
				Type:    ofp4.OFPT_ECHO_REPLY,
				Xid:     ofm.Xid,
			},
			Body: ofm.Body,
		}
		if msgbin, e := msg.MarshalBinary(); e != nil {
			err = e
		} else {
			respMessages = append(respMessages, msgbin)
		}
	case ofp4.OFPT_EXPERIMENTER:
		err = &ofp4.Error{
			Type: ofp4.OFPET_BAD_REQUEST,
			Code: ofp4.OFPBRC_BAD_EXPERIMENTER,
		}
	case ofp4.OFPT_FEATURES_REQUEST:
		msg := ofp4.Message{
			Header: ofp4.Header{
				Version: 4,
				Type:    ofp4.OFPT_FEATURES_REPLY,
				Xid:     ofm.Xid,
			},
			Body: &ofp4.SwitchFeatures{
				DatapathId:   pipe.DatapathId,
				NBuffers:     0x7fffffff,
				NTables:      0xff,
				Capabilities: 0,
			},
		}
		if msgbin, e := msg.MarshalBinary(); e != nil {
			err = e
		} else {
			respMessages = append(respMessages, msgbin)
		}
	case ofp4.OFPT_GET_CONFIG_REQUEST:
		msg := ofp4.Message{
			Header: ofp4.Header{
				Version: 4,
				Type:    ofp4.OFPT_GET_CONFIG_REPLY,
				Xid:     ofm.Xid,
			},
			Body: &ofp4.SwitchConfig{
				Flags:       pipe.flags,
				MissSendLen: pipe.ports[ofp4.OFPP_CONTROLLER].(controller).missSendLen,
			},
		}
		if msgbin, e := msg.MarshalBinary(); e != nil {
			err = e
		} else {
			respMessages = append(respMessages, msgbin)
		}
	case ofp4.OFPT_SET_CONFIG:
		config := ofm.Body.(*ofp4.SwitchConfig)
		ch := make(chan error)
		pipe.commands <- func() {
			pipe.flags = config.Flags
			control := pipe.ports[ofp4.OFPP_CONTROLLER].(controller)
			control.missSendLen = config.MissSendLen
			ch <- nil
			close(ch)
		}
		err = <-ch
	case ofp4.OFPT_PACKET_OUT:
		req := ofm.Body.(*ofp4.PacketOut)
		control := pipe.ports[ofp4.OFPP_CONTROLLER].(controller)
		var eth []byte
		if req.BufferId == ofp4.OFP_NO_BUFFER {
			eth = req.Data
		} else {
			ch := make(chan []byte)
			control.commands <- func() {
				ch <- func() []byte {
					if original, ok := control.buffer[req.BufferId]; ok {
						delete(control.buffer, req.BufferId)
						return original.data
					}
					return nil
				}()
				close(ch)
			}
			eth = <-ch
		}
		if eth != nil {
			data := frame{
				layers: gopacket.NewPacket(eth, layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true}).Layers(),
				inPort: req.InPort,
			}
			var actionResult flowEntryResult
			for _, act := range req.Actions {
				if aret, e := act.(action).process(&data, pipe); e != nil {
					data.errors = append(data.errors, e)
				} else {
					actionResult.groups = append(actionResult.groups, aret.groups...)
					actionResult.outputs = append(actionResult.outputs, aret.outputs...)
				}
			}
			pouts := append(actionResult.outputs, data.processGroups(actionResult.groups, pipe, nil)...)
			ch := make(chan error)
			pipe.commands <- func() {
				for _, pout := range pouts {
					if port, ok := pipe.ports[pout.outPort]; ok {
						port.Egress() <- pout
					}
				}
				ch <- nil
				close(ch)
			}
			err = <-ch
		} else {
			err = &ofp4.Error{ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BUFFER_UNKNOWN, nil}
		}
	case ofp4.OFPT_FLOW_MOD:
		req := ofm.Body.(*ofp4.FlowMod)
		switch req.Command {
		case ofp4.OFPFC_ADD:
			if err = pipe.addFlowEntry(*req); err == nil {
				if req.BufferId != ofp4.OFP_NO_BUFFER {
					// XXX: do pipeline processing
				}
			}
		case ofp4.OFPFC_MODIFY, ofp4.OFPFC_MODIFY_STRICT:
			// XXX:
		case ofp4.OFPFC_DELETE, ofp4.OFPFC_DELETE_STRICT:
			var reqMatch matchList
			if e := reqMatch.UnmarshalBinary(req.Match.OxmFields); e != nil {
				err = e
			} else {
				filter := flowFilter{
					opUnregister: true,
					cookie:       req.Cookie,
					cookieMask:   req.CookieMask,
					tableId:      req.TableId,
					outPort:      req.OutPort,
					outGroup:     req.OutGroup,
					match:        []match(reqMatch),
				}
				if req.Command == ofp4.OFPFC_DELETE_STRICT {
					filter.priority = req.Priority
					filter.opStrict = true
				}
				pipe.filterFlows(filter)
			}
		}
	case ofp4.OFPT_GROUP_MOD:
		req := ofm.Body.(*ofp4.GroupMod)
		switch req.Command {
		case ofp4.OFPGC_ADD:
			err = pipe.addGroup(*req)
		case ofp4.OFPGC_MODIFY:
			// XXX:
		case ofp4.OFPGC_DELETE:
			err = pipe.deleteGroup(*req)
		}
	case ofp4.OFPT_MULTIPART_REQUEST:
		req := ofm.Body.(*ofp4.MultipartRequest)
		fmt.Println("multipart", req)
		multiReq := append(multi, *req)
		var multiRes []encoding.BinaryMarshaler

		switch req.Type {
		case ofp4.OFPMP_DESC:
			desc := pipe.ports[ofp4.OFPP_CONTROLLER].(controller).desc
			multiRes = append(multiRes, &desc)
		case ofp4.OFPMP_FLOW:
			var flows []flowStats
			for _, req := range multiReq {
				req2 := req.Body.(*ofp4.FlowStatsRequest)
				var reqMatch matchList
				if e := reqMatch.UnmarshalBinary(req2.Match.OxmFields); e != nil {
					err = e
				} else {
					filter := flowFilter{
						tableId:    req2.TableId,
						outPort:    req2.OutPort,
						outGroup:   req2.OutGroup,
						cookie:     req2.Cookie,
						cookieMask: req2.CookieMask,
						match:      []match(reqMatch),
					}
					for _, f := range pipe.filterFlows(filter) {
						hit := false
						for _, seen := range flows {
							if f.entry == seen.entry {
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
				duration := time.Now().Sub(f.entry.created)
				if buf, e := matchList(f.entry.fields).MarshalBinary(); e != nil {
					err = e
				} else {
					var insts []ofp4.Instruction
					if f.entry.instMeter != 0 {
						inst := ofp4.InstructionMeter{f.entry.instMeter}
						insts = append(insts, inst)
					}
					if len([]action(f.entry.instApply)) > 0 {
						if actions, err := f.entry.instApply.toMessage(); err != nil {
							panic(err)
						} else {
							inst := ofp4.InstructionActions{ofp4.OFPIT_APPLY_ACTIONS, actions}
							insts = append(insts, inst)
						}
					}
					if f.entry.instClear {
						inst := ofp4.InstructionActions{ofp4.OFPIT_CLEAR_ACTIONS, nil}
						insts = append(insts, inst)
					}
					if len(map[uint16]action(f.entry.instWrite)) > 0 {
						if actions, err := f.entry.instWrite.toMessage(); err != nil {
							panic(err)
						} else {
							inst := ofp4.InstructionActions{ofp4.OFPIT_WRITE_ACTIONS, actions}
							insts = append(insts, inst)
						}
					}
					if f.entry.instMetadata != nil {
						inst := ofp4.InstructionWriteMetadata{
							f.entry.instMetadata.metadata,
							f.entry.instMetadata.mask,
						}
						insts = append(insts, inst)
					}
					if f.entry.instGoto != 0 {
						inst := ofp4.InstructionGotoTable{f.entry.instGoto}
						insts = append(insts, inst)
					}
					msg := ofp4.FlowStats{
						TableId:      f.tableId,
						DurationSec:  uint32(duration.Seconds()),
						DurationNsec: uint32(duration.Nanoseconds() % int64(time.Second)),
						Priority:     f.priority,
						IdleTimeout:  f.entry.idleTimeout,
						HardTimeout:  f.entry.hardTimeout,
						Flags:        f.entry.flags, // OFPFF_
						Cookie:       f.entry.cookie,
						PacketCount:  f.entry.packetCount,
						ByteCount:    f.entry.byteCount,
						Match: ofp4.Match{
							Type:      ofp4.OFPMT_OXM,
							OxmFields: buf,
						},
						Instructions: insts,
					}
					multiRes = append(multiRes, &msg)
				}
			}
		case ofp4.OFPMP_AGGREGATE:
			// per table stats
			// XXX:
			for req := range multiReq {
				_ = req
			}
		case ofp4.OFPMP_PORT_STATS:
			for portNo, bport := range pipe.getPorts(req.Body.(*ofp4.PortStatsRequest).PortNo) {
				switch port := bport.(type) {
				case portHelper:
					pstats := port.public.GetStats()
					duration := time.Now().Sub(port.created)
					msg := ofp4.PortStats{
						PortNo:       portNo,
						RxPackets:    pstats.RxPackets,
						TxPackets:    pstats.TxPackets,
						RxBytes:      pstats.RxBytes,
						TxBytes:      pstats.TxBytes,
						DurationSec:  uint32(duration.Seconds()),
						DurationNsec: uint32(duration.Nanoseconds() % int64(time.Second)),
					}
					multiRes = append(multiRes, &msg)
				case controller:
					// exluding
				default:
					panic("portHelper cast error")
				}
			}
		case ofp4.OFPMP_METER:
			for meterId, meter := range pipe.getMeters(req.Body.(*ofp4.MeterMultipartRequest).MeterId) {
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
				msg := ofp4.MeterStats{
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
				multiRes = append(multiRes, &msg)
			}
		case ofp4.OFPMP_METER_CONFIG:
			for meterId, meter := range pipe.getMeters(req.Body.(*ofp4.MeterMultipartRequest).MeterId) {
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
				msg := ofp4.MeterConfig{
					Flags:   flags,
					MeterId: meterId,
					Bands:   bands,
				}
				multiRes = append(multiRes, &msg)
			}
		}
		{
			var capture []encoding.BinaryMarshaler
			for _, res := range multiRes {
				prep := append(capture, res)

				msg := ofp4.Message{
					Header: ofp4.Header{
						Version: 4,
						Type:    ofp4.OFPT_MULTIPART_REPLY,
						Xid:     ofm.Xid,
					},
					Body: &ofp4.MultipartReply{
						Type:  req.Type,
						Flags: 0,
						Body:  ofp4.Array(prep),
					},
				}
				if msgbin, err := msg.MarshalBinary(); err != nil || len(msgbin) > 0xFFFF {
					msg := ofp4.Message{
						Header: ofp4.Header{
							Version: 4,
							Type:    ofp4.OFPT_MULTIPART_REPLY,
							Xid:     ofm.Xid,
						},
						Body: &ofp4.MultipartReply{
							Type:  req.Type,
							Flags: ofp4.OFPMPF_REPLY_MORE,
							Body:  ofp4.Array(capture),
						},
					}
					if msgbin, err := msg.MarshalBinary(); err != nil {
						panic(err)
					} else {
						respMessages = append(respMessages, msgbin)
						capture = nil
					}
				} else {
					capture = append(capture, res)
				}
			}
			msg := ofp4.Message{
				Header: ofp4.Header{
					Version: 4,
					Type:    ofp4.OFPT_MULTIPART_REPLY,
					Xid:     ofm.Xid,
				},
				Body: &ofp4.MultipartReply{
					Type:  req.Type,
					Flags: 0,
					Body:  ofp4.Array(capture),
				},
			}
			if msgbin, err := msg.MarshalBinary(); err != nil {
				panic(err)
			} else {
				respMessages = append(respMessages, msgbin)
			}
		}
	case ofp4.OFPT_BARRIER_REQUEST:
		msg := ofp4.Message{
			Header: ofp4.Header{
				Version: 4,
				Type:    ofp4.OFPT_BARRIER_REPLY,
				Xid:     ofm.Xid,
			},
		}
		if msgbin, e := msg.MarshalBinary(); e != nil {
			err = e
		} else {
			respMessages = append(respMessages, msgbin)
		}
	case ofp4.OFPT_METER_MOD:
		req := ofm.Body.(*ofp4.MeterMod)
		switch req.Command {
		case ofp4.OFPMC_ADD:
			meter := newMeter(*req)
			ch := make(chan error)
			pipe.commands <- func() {
				ch <- func() error {
					if req.MeterId == 0 || (req.MeterId > ofp4.OFPM_MAX && req.MeterId != ofp4.OFPM_CONTROLLER) {
						return &ofp4.Error{
							Type: ofp4.OFPET_METER_MOD_FAILED,
							Code: ofp4.OFPMMFC_INVALID_METER,
						}
					}
					if _, exists := pipe.meters[req.MeterId]; exists {
						return &ofp4.Error{
							Type: ofp4.OFPET_METER_MOD_FAILED,
							Code: ofp4.OFPMMFC_METER_EXISTS,
						}
					} else {
						pipe.meters[req.MeterId] = meter
					}
					return nil
				}()
				close(ch)
			}
			if e := <-ch; e != nil {
				meter.commands <- nil
				err = e
			}
		case ofp4.OFPMC_DELETE:
			ch := make(chan error)
			pipe.commands <- func() {
				ch <- func() error {
					if req.MeterId == ofp4.OFPM_ALL {
						for k, m := range pipe.meters {
							m.commands <- nil
							delete(pipe.meters, k)
						}
					} else {
						if meter, exists := pipe.meters[req.MeterId]; exists {
							meter.commands <- nil
							delete(pipe.meters, req.MeterId)
						} else {
							return &ofp4.Error{
								Type: ofp4.OFPET_METER_MOD_FAILED,
								Code: ofp4.OFPMMFC_UNKNOWN_METER,
							}
						}
					}
					return nil
				}()
				close(ch)
			}
			if e := <-ch; e != nil {
				err = e
			}
		case ofp4.OFPMC_MODIFY:
			// XXX:
		}
	}
	if err != nil {
		switch e := err.(type) {
		default:
			panic(e)
		case *ofp4.Error:
			msg := ofp4.Message{
				Header: ofp4.Header{
					Version: 4,
					Type:    ofp4.OFPT_ERROR,
					Xid:     ofm.Xid,
				},
				Body: e,
			}
			if msgbin, err := msg.MarshalBinary(); err != nil {
				panic(err)
			} else {
				respMessages = append(respMessages, msgbin)
			}
		}
	}
	return respMessages
}
