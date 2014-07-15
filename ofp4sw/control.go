package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"encoding"
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
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

func newController() *controller {
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
							pout := pout
							go channel.Transaction().packetIn(buffer_id, pout, channel)
						case mode_slave:
							// do not packet_in
						}
					}
				}
			}
		}
	}()
	return &port
}
func (c controller) Egress() chan<- packetOut { return c.egress }
func (c controller) Live() bool               { return true }

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
	if con := <-ch; con == nil {
		return errors.New("control channel registeration failed")
	} else {
		transaction := con.Transaction()
		if xid, err := transaction.newXid(); err != nil {
			con.Close()
			return err
		} else {
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
				return err
			} else {
				con.Egress() <- msgbin
			}
		}
		go transaction.handleConnection(pipe, con)
		return nil
	}
}

func (x *transaction) handleConnection(pipe Pipeline, con ControlChannel) {
	serialOuts := make(chan chan []packetOut)
	go func() {
		for serialOut := range serialOuts {
			pouts := <-serialOut
			for _, pout := range pouts {
				if pout.data == nil {
					log.Print("packet serialization error")
					continue
				}
				if pout.outPort <= ofp4.OFPP_MAX {
					for _, outPort := range pipe.getPorts(pout.outPort) {
						outPort.Egress() <- pout
					}
				} else if pout.outPort == ofp4.OFPP_ALL {
					for outPortNo, outPort := range pipe.getPorts(pout.outPort) {
						if outPortNo != pout.inPort {
							outPort.Egress() <- pout
						}
					}
				} else if pout.outPort == ofp4.OFPP_TABLE {
					pout := pout
					defer func() {
						data := frame{
							inPort:    pout.inPort,
							layers:    gopacket.NewPacket(pout.data, layers.LayerTypeEthernet, gopacket.NoCopy).Layers(),
							phyInPort: pipe.getPortPhysicalPort(pout.inPort),
						}
						tableOut := make(chan []packetOut)
						serialOuts <- tableOut
						tableOut <- data.process(pipe)
					}()
				} else {
					log.Print("Unsupported special port output")
				}
			}
		}
	}()
	xctnConcurrency := make(chan chan bool, 4)
	go func() {
		for sig := range xctnConcurrency {
			<-sig
		}
	}()
	for msg := range con.Ingress() {
		if msg == nil {
			break
		}
		var ofm ofp4.Message
		if err := ofm.UnmarshalBinary(msg); err != nil {
			log.Println(err)
			break
		}

		xcntNotify := make(chan bool)
		xctnConcurrency <- xcntNotify

		x.commands <- func() {
			var multi []ofp4.MultipartRequest
			xidSelf := &xid{
				oftype: ofm.Type,
			}
			count := 0
			ch := make(chan bool)
			if ofp4.MessageType(ofm.Type) == ofp4.MSG_REQUEST {
				if ofm.Type == ofp4.OFPT_MULTIPART_REQUEST {
					if groupXid, ok := x.xids[ofm.Xid]; ok {
						xidSelf = groupXid
					} else {
						x.xids[ofm.Xid] = xidSelf
					}
					req := ofm.Body.(*ofp4.MultipartRequest)
					if (req.Flags & ofp4.OFPMPF_REQ_MORE) != 0 {
						xidSelf.multi = append(xidSelf.multi, *req)
						xcntNotify <- true
						return
					} else {
						multi = xidSelf.multi
						xidSelf.multi = nil
					}
				} else {
					x.xids[ofm.Xid] = xidSelf
				}
			}

			xidSelf.release = append(xidSelf.release, xcntNotify)
			if ofp4.MessageType(ofm.Type) == ofp4.MSG_REQUEST {
				if ofm.Type == ofp4.OFPT_BARRIER_REQUEST {
					for _, v := range x.xids {
						if v == xidSelf {
							continue
						}
						if ofp4.MessageType(v.oftype) == ofp4.MSG_REQUEST && v.multi == nil {
							v.release = append(v.release, ch)
							count++
						}
					}
				} else {
					for _, v := range x.xids {
						if v == xidSelf {
							continue
						}
						if v.oftype == ofp4.OFPT_BARRIER_REQUEST && v.multi == nil {
							v.release = append(v.release, ch)
							count++
						}
					}
				}
			}

			var serialOut chan []packetOut
			if ofm.Type == ofp4.OFPT_PACKET_OUT {
				serialOut = make(chan []packetOut)
				serialOuts <- serialOut
			} else if ofm.Type == ofp4.OFPT_FLOW_MOD {
				req := ofm.Body.(*ofp4.FlowMod)
				if req.BufferId != ofp4.OFP_NO_BUFFER {
					serialOut = make(chan []packetOut)
					serialOuts <- serialOut
				}
			}

			go func() {
				response := x.handle(ofm, multi, pipe, con, serialOut)
				for i := 0; i < count; i++ {
					_ = <-ch
				}
				for _, msg := range response {
					log.Println("res", msg)
					con.Egress() <- msg
				}
				x.commands <- func() {
					for k, v := range x.xids {
						if v == xidSelf {
							delete(x.xids, k)
						}
					}
				}
				for _, ch2 := range xidSelf.release {
					ch2 <- true
				}
			}()
		}
	}
	con.Close()

	ctrl := pipe.getController()
	ctrl.commands <- func() {
		for k, v := range ctrl.clusters {
			if v.main == con {
				delete(ctrl.clusters, k)
			}
		}
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
		reason := uint8(ofp4.OFPR_ACTION)
		if pout.match.priority == 0 && len(pout.match.rule.fields) == 0 {
			reason = ofp4.OFPR_NO_MATCH
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
				Reason:   reason,
				TableId:  pout.match.tableId,
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

func (x transaction) handle(ofm ofp4.Message, multi []ofp4.MultipartRequest, pipe Pipeline, con ControlChannel, serialOut chan []packetOut) [][]byte {
	//	log.Println("req", ofm)
	var respMessages [][]byte

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
			respMessages = append(respMessages, createError(ofm,
				ofp4.OFPET_HELLO_FAILED, ofp4.OFPHFC_INCOMPATIBLE))
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
			log.Print(e)
		} else {
			respMessages = append(respMessages, msgbin)
		}
	case ofp4.OFPT_EXPERIMENTER:
		respMessages = append(respMessages, createError(ofm,
			ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BAD_EXPERIMENTER))
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
		if msgbin, err := msg.MarshalBinary(); err != nil {
			log.Print(err)
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
				MissSendLen: pipe.getController().missSendLen,
			},
		}
		if msgbin, err := msg.MarshalBinary(); err != nil {
			log.Print(err)
		} else {
			respMessages = append(respMessages, msgbin)
		}
	case ofp4.OFPT_SET_CONFIG:
		config := ofm.Body.(*ofp4.SwitchConfig)
		pipe.flags = config.Flags
		pipe.getController().missSendLen = config.MissSendLen
	case ofp4.OFPT_PACKET_OUT:
		req := ofm.Body.(*ofp4.PacketOut)
		ctrl := pipe.getController()
		var eth []byte
		if req.BufferId == ofp4.OFP_NO_BUFFER {
			eth = req.Data
		} else {
			ch := make(chan []byte)
			ctrl.commands <- func() {
				ch <- func() []byte {
					if original, ok := ctrl.buffer[req.BufferId]; ok {
						delete(ctrl.buffer, req.BufferId)
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
				layers:    gopacket.NewPacket(eth, layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true}).Layers(),
				inPort:    req.InPort,
				phyInPort: pipe.getPortPhysicalPort(req.InPort),
			}

			var actionResult flowEntryResult
			var actions actionList
			actions.fromMessage(req.Actions)
			for _, act := range []action(actions) {
				if aret, e := act.(action).process(&data, pipe); e != nil {
					log.Print(e)
				} else {
					actionResult.groups = append(actionResult.groups, aret.groups...)
					actionResult.outputs = append(actionResult.outputs, aret.outputs...)
				}
			}
			serialOut <- append(actionResult.outputs, data.processGroups(actionResult.groups, pipe, nil)...)
		} else {
			respMessages = append(respMessages, createError(ofm,
				ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BUFFER_UNKNOWN))
		}
	case ofp4.OFPT_FLOW_MOD:
		req := ofm.Body.(*ofp4.FlowMod)
		switch req.Command {
		case ofp4.OFPFC_ADD:
			if err := pipe.addFlowEntry(*req); err != nil {
				log.Print(err)
			} else {
				if req.BufferId != ofp4.OFP_NO_BUFFER {
					// XXX: do pipeline processing
				}
			}
		case ofp4.OFPFC_MODIFY, ofp4.OFPFC_MODIFY_STRICT:
			// XXX:
		case ofp4.OFPFC_DELETE, ofp4.OFPFC_DELETE_STRICT:
			var reqMatch matchList
			if err := reqMatch.UnmarshalBinary(req.Match.OxmFields); err != nil {
				log.Print(err)
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
		if req.BufferId != ofp4.OFP_NO_BUFFER {
			ch := make(chan *packetOut)
			ctrl := pipe.getController()
			ctrl.commands <- func() {
				ch <- func() *packetOut {
					if original, ok := ctrl.buffer[req.BufferId]; ok {
						delete(ctrl.buffer, req.BufferId)
						return original
					}
					return nil
				}()
				close(ch)
			}
			pout := <-ch
			if pout != nil {
				if eth := pout.data; eth != nil {
					data := frame{
						layers:    gopacket.NewPacket(eth, layers.LayerTypeEthernet, gopacket.NoCopy).Layers(),
						inPort:    pout.inPort,
						phyInPort: pipe.getPortPhysicalPort(pout.inPort),
					}
					serialOut <- data.process(pipe)
				}
			} else {
				respMessages = append(respMessages, createError(ofm,
					ofp4.OFPET_BAD_REQUEST, ofp4.OFPBRC_BUFFER_UNKNOWN))
			}
		}
	case ofp4.OFPT_GROUP_MOD:
		req := ofm.Body.(*ofp4.GroupMod)
		switch req.Command {
		case ofp4.OFPGC_ADD:
			if err := pipe.addGroup(*req); err != nil {
				if e, ok := err.(*ofp4.Error); ok {
					respMessages = append(respMessages, createError(ofm,
						e.Type, e.Code))
				} else {
					log.Print(err)
				}
			}
		case ofp4.OFPGC_MODIFY:
			// XXX:
		case ofp4.OFPGC_DELETE:
			ch := make(chan error)
			pipe.commands <- func() {
				ch <- func() error {
					if req.GroupId == ofp4.OFPG_ALL {
						for groupId, _ := range pipe.groups {
							pipe.deleteGroupInside(groupId)
						}
					} else {
						return pipe.deleteGroupInside(req.GroupId)
					}
					return nil
				}()
			}
			if err := <-ch; err != nil {
				if e, ok := err.(*ofp4.Error); ok {
					respMessages = append(respMessages, createError(ofm,
						e.Type, e.Code))
				} else {
					log.Print(err)
				}
			}
		}
	case ofp4.OFPT_MULTIPART_REQUEST:
		req := ofm.Body.(*ofp4.MultipartRequest)
		log.Println("multipart", req)
		multiReq := append(multi, *req)
		var multiRes []encoding.BinaryMarshaler

		switch req.Type {
		case ofp4.OFPMP_DESC:
			multiRes = append(multiRes, pipe.getController().desc)
		case ofp4.OFPMP_FLOW:
			var flows []flowStats
			for _, req := range multiReq {
				mreq := req.Body.(*ofp4.FlowStatsRequest)
				var reqMatch matchList
				if e := reqMatch.UnmarshalBinary(mreq.Match.OxmFields); e != nil {
					log.Print(e)
				} else {
					filter := flowFilter{
						tableId:    mreq.TableId,
						outPort:    mreq.OutPort,
						outGroup:   mreq.OutGroup,
						cookie:     mreq.Cookie,
						cookieMask: mreq.CookieMask,
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
					log.Print(e)
				} else {
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
						Instructions: f.entry.exportInstructions(),
					}
					multiRes = append(multiRes, &msg)
				}
			}
		case ofp4.OFPMP_TABLE:
			for tableId, table := range pipe.getTables(ofp4.OFPTT_ALL) {
				msg := ofp4.TableStats{
					TableId:      tableId,
					ActiveCount:  table.activeCount,
					LookupCount:  table.lookupCount,
					MatchedCount: table.matchCount,
				}
				multiRes = append(multiRes, &msg)
			}
		case ofp4.OFPMP_AGGREGATE:
			mreq := req.Body.(*ofp4.AggregateStatsRequest)
			var reqMatch matchList
			if e := reqMatch.UnmarshalBinary(mreq.Match.OxmFields); e != nil {
				log.Panic(e)
			} else {
				filter := flowFilter{
					tableId:    mreq.TableId,
					outPort:    mreq.OutPort,
					outGroup:   mreq.OutGroup,
					cookie:     mreq.Cookie,
					cookieMask: mreq.CookieMask,
					match:      []match(reqMatch),
				}
				var msg ofp4.AggregateStatsReply
				for _, f := range pipe.filterFlows(filter) {
					msg.PacketCount += f.entry.packetCount
					msg.ByteCount += f.entry.byteCount
					msg.FlowCount++
				}
				multiRes = append(multiRes, &msg)
			}
		case ofp4.OFPMP_PORT_STATS:
			for portNo, bport := range pipe.getPorts(req.Body.(*ofp4.PortStatsRequest).PortNo) {
				switch port := bport.(type) {
				case *portHelper:
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
				case *controller:
					// exluding
				default:
					panic("portHelper cast error")
				}
			}
		case ofp4.OFPMP_GROUP_DESC:
			for i, g := range pipe.getGroups(ofp4.OFPG_ALL) {
				var buckets []encoding.BinaryMarshaler
				for _, b := range g.buckets {
					if bucket, e := b.toMessage(); e != nil {
						panic(e)
					} else {
						buckets = append(buckets, bucket)
					}
				}
				multiRes = append(multiRes, &ofp4.GroupDesc{
					Type:    g.groupType,
					GroupId: i,
					Buckets: buckets,
				})
			}
		case ofp4.OFPMP_GROUP_FEATURES:
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
			multiRes = append(multiRes, &ofp4.GroupFeatures{
				Types:        1<<ofp4.OFPGT_ALL | 1<<ofp4.OFPGT_SELECT | 1<<ofp4.OFPGT_INDIRECT | 1<<ofp4.OFPGT_FF,
				Capabilities: ofp4.OFPGFC_SELECT_WEIGHT | ofp4.OFPGFC_SELECT_LIVENESS | ofp4.OFPGFC_CHAINING | ofp4.OFPGFC_CHAINING_CHECKS,
				MaxGroups:    [...]uint32{ofp4.OFPG_MAX, ofp4.OFPG_MAX, ofp4.OFPG_MAX, ofp4.OFPG_MAX},
				Actions:      [...]uint32{actionBits, actionBits, actionBits, actionBits},
			})
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
		case ofp4.OFPMP_PORT_DESC:
			for _, bport := range pipe.getPorts(ofp4.OFPP_ANY) {
				switch port := bport.(type) {
				case *portHelper:
					msg := port.public.GetPort()
					multiRes = append(multiRes, &msg)
				case *controller:
					// exluding
				default:
					log.Panic("portHelper cast error")
				}
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
			panic(e)
		} else {
			respMessages = append(respMessages, msgbin)
		}
	case ofp4.OFPT_METER_MOD:
		req := ofm.Body.(*ofp4.MeterMod)
		switch req.Command {
		case ofp4.OFPMC_ADD:
			if req.MeterId == 0 || (req.MeterId > ofp4.OFPM_MAX && req.MeterId != ofp4.OFPM_CONTROLLER) {
				respMessages = append(respMessages, createError(ofm,
					ofp4.OFPET_METER_MOD_FAILED, ofp4.OFPMMFC_INVALID_METER))
			} else {
				meter := newMeter(*req)
				ch := make(chan error)
				pipe.commands <- func() {
					ch <- func() error {
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
				if err := <-ch; err != nil {
					meter.commands <- nil
					if e, ok := err.(*ofp4.Error); ok {
						respMessages = append(respMessages, createError(ofm,
							e.Type, e.Code))
					} else {
						log.Print(err)
					}
				}
			}
		case ofp4.OFPMC_DELETE:
			ch := make(chan error)
			pipe.commands <- func() {
				ch <- func() error {
					if req.MeterId == ofp4.OFPM_ALL {
						for meterId, _ := range pipe.meters {
							pipe.deleteMeterInside(meterId)
						}
					} else {
						return pipe.deleteMeterInside(req.MeterId)
					}
					return nil
				}()
			}
			if err := <-ch; err != nil {
				if e, ok := err.(*ofp4.Error); ok {
					respMessages = append(respMessages, createError(ofm,
						e.Type, e.Code))
				} else {
					log.Print(err)
				}
			}
		case ofp4.OFPMC_MODIFY:
			// XXX:
		}
	}
	return respMessages
}

func createError(request ofp4.Message, ofpet uint16, code uint16) []byte {
	if buf, err := request.MarshalBinary(); err != nil {
		panic(err)
	} else {
		msg := ofp4.Message{
			Header: ofp4.Header{
				Version: 4,
				Type:    ofp4.OFPT_ERROR,
				Xid:     request.Xid,
			},
			Body: &ofp4.Error{
				Type: ofpet,
				Code: code,
				Data: buf,
			},
		}
		if msgbin, err := msg.MarshalBinary(); err != nil {
			panic(err)
		} else {
			return msgbin
		}
	}
}
