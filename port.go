// +build linux

package gopenflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/oxm"
	"github.com/hkwi/nlgo"
	syscall2 "github.com/hkwi/suppl/syscall"
	"log"
	"net"
	"sync"
	"syscall"
	"unsafe"
)

type NamedPort struct {
	ifIndex  uint32
	flags    uint32
	name     string
	hasWiphy bool
	wiphy    uint32
	mac      []byte
	mtu      uint32
	config   []PortConfig

	port         uint32
	physicalPort uint32
	ingress      chan Frame
	monitor      chan bool
	lock         *sync.Mutex

	// socket handling
	hatype   uint16
	fd       int
	rhub     *nlgo.RtHub   // pointer to NamedPortManager's rhub
	ghub     *nlgo.GenlHub // GenlHub is here because Frame registration can only be removed by closing the socket.
	txStatus map[uint64]chan error

	// below for non-monitor nl80211
	mgmtFrames []MgmtFramePrefix
	fragmentId uint8
}

func (self NamedPort) Name() string {
	return self.name
}

func (self NamedPort) HwAddr() [6]byte {
	var ret [6]byte
	copy(ret[:], self.mac)
	return ret
}

func (self NamedPort) PhysicalPort() uint32 {
	return self.physicalPort
}

func (self NamedPort) Monitor() <-chan bool {
	return self.monitor
}

func (self NamedPort) Ingress() <-chan Frame {
	return self.ingress
}

func (self NamedPort) Egress(pkt Frame) error {
	if self.fd == -1 {
		return fmt.Errorf("port closed")
	}
	switch self.hatype {
	case syscall.ARPHRD_ETHER:
		dot11 := false
		for _, oob := range fetchOxmExperimenter(pkt.Oob) {
			if oob.Experimenter == oxm.STRATOS_EXPERIMENTER_ID &&
				oob.Field == oxm.STRATOS_OXM_FIELD_BASIC &&
				oob.Type == oxm.STROXM_BASIC_DOT11 &&
				oob.Value[0] == 1 {
				dot11 = true
			}
		}
		if dot11 && self.wiphy != 0 {
			if self.ghub == nil {
				if hub, err := nlgo.NewGenlHub(); err != nil {
					return err
				} else {
					self.ghub = hub
				}
			}
			self.ghub.Add("nl80211", "mlme", self)
			nl80211 := self.ghub.Family("nl80211")
			status := make(chan error)
			defer close(status)

			if err := func() error {
				if buf, err := pkt.Dot11(); err != nil {
					return err
				} else {
					self.lock.Lock()
					defer self.lock.Unlock()

					if res, err := self.ghub.Sync(nl80211.Request(nlgo.NL80211_CMD_FRAME, 0, nil, nlgo.AttrSlice{
						nlgo.Attr{
							Header: syscall.NlAttr{
								Type: nlgo.NL80211_ATTR_FRAME,
							},
							Value: nlgo.Binary(buf),
						},
					}.Bytes())); err != nil {
						return err
					} else {
						for _, r := range res {
							if len(r.Family.Name) == 0 {
								return fmt.Errorf("NL80211_CMD_FRAME failed")
							} else if r.Family.Name == "nl80211" {
								if attrs, err := nlgo.Nl80211Policy.Parse(r.Body()); err != nil {
									return err
								} else {
									cookie := uint64(attrs.(nlgo.AttrMap).Get(nlgo.NL80211_ATTR_COOKIE).(nlgo.U64))
									self.txStatus[cookie] = status
								}
							}
						}
					}
				}
				return nil
			}(); err != nil {
				return err
			}
			if err := <-status; err != nil {
				return err
			}
		} else {
			buf := pkt.Data
			if n, err := syscall.Write(self.fd, buf); err != nil {
				return err
			} else if n != len(buf) {
				return fmt.Errorf("write not complete")
			}
		}
	case syscall.ARPHRD_IEEE80211_RADIOTAP:
		// XXX: only when Dot11 flag ?
		if buf, err := pkt.Radiotap(); err != nil {
			return err
		} else if n, err := syscall.Write(self.fd, buf); err != nil {
			return err
		} else if n != len(buf) {
			return fmt.Errorf("write not complete")
		}
	case syscall2.ARPHRD_6LOWPAN:
		if binary.BigEndian.Uint16(pkt.Data[12:]) == 0x86DD {
			buf := pkt.Data[14:]
			if n, err := syscall.Write(self.fd, buf); err != nil {
				return err
			} else if n != len(buf) {
				return fmt.Errorf("write not complete")
			}
		}
	}
	return nil
}

func (self NamedPort) GetConfig() []PortConfig {
	self.lock.Lock()
	defer self.lock.Unlock()

	return append([]PortConfig{
		PortConfigPortDown(self.flags&syscall.IFF_UP == 0),
	}, self.config...)
}

func (self NamedPort) SetConfig(mods []PortConfig) {
	self.lock.Lock()
	defer self.lock.Unlock()

	var config []PortConfig
	for _, mod := range mods {
		switch m := mod.(type) {
		case PortConfigPortDown:
			if hub, err := nlgo.NewRtHub(); err != nil {
				log.Print(err)
			} else {
				defer hub.Close()
				ifinfo := &syscall.IfInfomsg{
					Index: int32(self.ifIndex),
				}
				if !bool(m) {
					ifinfo.Flags |= syscall.IFF_UP
				}
				ifinfo.Change |= syscall.IFF_UP
				// xxx:should add error check?
				hub.Async(syscall.NetlinkMessage{
					Header: syscall.NlMsghdr{
						Type: syscall.RTM_SETLINK,
					},
					Data: (*[syscall.SizeofIfInfomsg]byte)(unsafe.Pointer(ifinfo))[:],
				}, nil)
			}
		default:
			config = append(config, mod)
		}
	}
	self.config = config
	self.monitor <- true
}

func (self NamedPort) State() []PortState {
	return []PortState{
		PortStateLinkDown(self.flags&syscall2.IFF_LOWER_UP == 0),
		PortStateBlocked(self.flags&syscall2.IFF_DORMANT != 0),
		PortStateLive(self.flags&syscall.IFF_RUNNING != 0),
	}
}

func (self NamedPort) Mtu() uint32 {
	return self.mtu
}

func (self NamedPort) Stats() (PortStats, error) {
	ifinfo := (*[syscall.SizeofIfInfomsg]byte)(unsafe.Pointer(&syscall.IfInfomsg{
		Index: int32(self.ifIndex),
	}))[:]
	if hub, err := nlgo.NewRtHub(); err != nil {
		return PortStats{}, err
	} else {
		defer hub.Close()
		if res, err := hub.Sync(syscall.NetlinkMessage{
			Header: syscall.NlMsghdr{
				Type:  syscall.RTM_GETLINK,
				Flags: syscall.NLM_F_DUMP,
			},
			Data: ifinfo,
		}); err != nil {
			return PortStats{}, err
		} else {
			for _, r := range res {
				rIfinfo := (*syscall.IfInfomsg)(unsafe.Pointer(&r.Data[0]))
				if rIfinfo.Index != int32(self.ifIndex) {
					continue
				}
				switch r.Header.Type {
				case syscall.RTM_NEWLINK:
					msg := nlgo.IfInfoMessage(r)
					if attrs, err := msg.Attrs(); err != nil {
						return PortStats{}, err
					} else if blk := attrs.(nlgo.AttrMap).Get(nlgo.IFLA_STATS64); blk != nil {
						stat := []byte(blk.(nlgo.Binary))
						s := (*nlgo.RtnlLinkStats64)(unsafe.Pointer(&stat[0]))
						ret := PortStats{
							RxPackets: s.RxPackets,
							TxPackets: s.TxPackets,
							RxBytes:   s.RxBytes,
							TxBytes:   s.TxBytes,
							RxDropped: s.RxDropped,
							TxDropped: s.TxDropped,
							RxErrors:  s.RxErrors,
							TxErrors:  s.TxErrors,
						}
						if self.hatype == syscall.ARPHRD_ETHER {
							ret.Ethernet = &PortStatsEthernet{
								RxFrameErr: s.RxFrameErrors,
								RxOverErr:  s.RxOverErrors,
								RxCrcErr:   s.RxCrcErrors,
								Collisions: s.Collisions,
							}
						}
						return ret, nil
					}
				}
			}
		}
	}
	return PortStats{}, fmt.Errorf("rtnetlink query failed")
}

// Up activates packet processing.
// When the interface is down(IFF_UP is unset), opening the socket raise error.
// This is because we have to call Up each time the state changed.
func (self *NamedPort) Up() error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if self.fd != -1 {
		return nil // already up
	}
	if self.flags&syscall.IFF_UP == 0 {
		return nil // not ready for up
	}
	if fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0); err != nil {
		panic(err)
	} else {
		self.fd = fd
	}
	if err := func() error {
		if err := syscall.SetsockoptInt(self.fd, syscall.SOL_PACKET, syscall2.PACKET_AUXDATA, 1); err != nil {
			return err
		}
		if err := syscall.Bind(self.fd, &syscall.SockaddrLinklayer{
			Protocol: syscall2.ETH_P_ALL,
			Ifindex:  int(self.ifIndex),
		}); err != nil {
			return err
		}
		if sa, err := syscall.Getsockname(self.fd); err != nil {
			return err
		} else {
			self.hatype = sa.(*syscall.SockaddrLinklayer).Hatype
			switch self.hatype {
			default:
				panic("unsupported ARPHRD")
			case syscall.ARPHRD_IEEE80211_RADIOTAP:
				// ok
			case syscall.ARPHRD_ETHER:
				// ok
			case syscall2.ARPHRD_6LOWPAN:
				// ok
			}
		}
		return nil
	}(); err != nil {
		self.Down()
		return err
	}
	go func() {
		defer self.Down()
		var fragmentId uint8

		buf := make([]byte, 32*1024)               // enough for jumbo frame
		oob := make([]byte, syscall.CmsgSpace(20)) // msg_control, 20 = sizeof(auxdata)
		for {
			var frame Frame

			if bufN, oobN, flags, _, err := syscall.Recvmsg(self.fd, buf, oob, syscall.MSG_TRUNC); err != nil {
				if e, ok := err.(syscall.Errno); ok && e.Temporary() {
					continue
				} else {
					log.Print("Recvmsg", err)
					break
				}
			} else if bufN == 0 {
				break
			} else if bufN > len(buf) {
				log.Print("MSG_TRUNC")
			} else if flags&syscall.MSG_CTRUNC != 0 {
				log.Print("MSG_CTRUNC")
			} else {
				haveVlan := false
				var vlanTpid uint16 = 0x8100
				var vlanTci uint16
				if cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobN]); err != nil {
					log.Print(err)
					return
				} else {
					for _, cmsg := range cmsgs {
						switch cmsg.Header.Type {
						case syscall2.PACKET_AUXDATA:
							aux := (*syscall2.Auxdata)(unsafe.Pointer(&cmsg.Data[0]))
							switch len(cmsg.Data) {
							case 20:
								if aux.Status&syscall2.TP_STATUS_VLAN_TPID_VALID != 0 {
									vlanTpid = aux.VlanTpid
								}
							case 18:
								// old format. pass
							default:
								log.Print("unexpected PACKET_AUXDATA")
								return
							}
							if aux.Status&syscall2.TP_STATUS_VLAN_VALID != 0 {
								haveVlan = true
								vlanTci = aux.VlanTci
							}
						}
					}
				}
				switch self.hatype {
				case syscall.ARPHRD_ETHER:
					var pkt []byte
					if haveVlan {
						pkt = make([]byte, bufN+4)
						copy(pkt[:12], buf[:12])
						binary.BigEndian.PutUint16(pkt[12:], vlanTpid)
						binary.BigEndian.PutUint16(pkt[14:], vlanTci)
						copy(pkt[16:], buf[12:bufN])
					} else {
						pkt = make([]byte, bufN)
						copy(pkt, buf)
					}
					frame = Frame{
						Data: pkt,
					}
				case syscall.ARPHRD_IEEE80211_RADIOTAP:
					// NOTE: 802.11 + PACKET_AUXDATA unsupported
					bpkt := gopacket.NewPacket(buf[:bufN], layers.LayerTypeRadioTap, gopacket.Lazy)
					if rtl := bpkt.Layer(layers.LayerTypeRadioTap); rtl == nil {
						log.Print("radiotap layer error")
					} else if rt, ok := rtl.(*layers.RadioTap); !ok {
						log.Print("radiotap layer type error")
					} else {
						if f, err := FrameFromRadiotap(rt, self.mac, fragmentId); err != nil {
							if _, ok := err.(frameError); !ok {
								log.Print(err)
							}
						} else {
							frame = f
							fragmentId++
						}
					}
				case syscall2.ARPHRD_6LOWPAN:
					pkt := make([]byte, 14+bufN)
					binary.BigEndian.PutUint16(pkt[12:], 0x86DD)
					copy(pkt[14:], buf[:bufN])

					bpkt := gopacket.NewPacket(buf[:bufN], layers.LayerTypeIPv6, gopacket.Lazy)
					ip6 := bpkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
					if ip6.DstIP.IsMulticast() {
						copy(pkt, []byte{0x33, 0x33})
						copy(pkt[2:6], []byte(ip6.DstIP.To16())[12:16])
						copy(pkt[6:], self.get6lowpanMac(ip6.SrcIP))
					} else {
						copy(pkt[6:], self.get6lowpanMac(ip6.SrcIP))
						copy(pkt, self.get6lowpanMac(ip6.DstIP))
					}
					frame = Frame{
						Data: pkt,
					}
				}
				if len(frame.Data) != 0 {
					func() {
						defer func() {
							if r := recover(); r != nil {
								// this may happen in socket race condition(rtnetlink and pf_packet).
								fmt.Println("dropping packet on closed ingress.")
							}
						}()
						self.ingress <- frame
					}()
				}
			}
		}
	}()
	return nil
}

// v6toMac gets hw addr from ipv6 in lowpan rule
func v6toMac(addr net.IP) net.HardwareAddr {
	gaddr := []byte(addr.To16())
	if gaddr[11] == 0xFF && gaddr[12] == 0xFE {
		return net.HardwareAddr{
			gaddr[8] ^ 0x02,
			gaddr[9],
			gaddr[10],
			gaddr[13],
			gaddr[14],
			gaddr[15],
		}
	}
	return nil
}

func (self NamedPort) get6lowpanMac(addr net.IP) net.HardwareAddr {
	req := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  syscall.RTM_GETROUTE,
			Flags: syscall.NLM_F_REQUEST,
		},
	}
	(*nlgo.RtMessage)(&req).Set(
		syscall.RtMsg{
			Family: syscall.AF_INET6,
		},
		nlgo.AttrSlice{
			nlgo.Attr{
				Header: syscall.NlAttr{
					Type: syscall.RTA_DST,
				},
				Value: nlgo.Binary(addr.To16()),
			},
		},
	)
	if msgs, err := self.rhub.Sync(req); err != nil {
		return nil
	} else {
		for _, msg := range msgs {
			switch msg.Header.Type {
			case syscall.NLMSG_ERROR:
				err := nlgo.NlMsgerr(msg)
				if err.Payload().Error != 0 {
					log.Print(err)
				}
			case syscall.RTM_NEWROUTE:
				if attr, err := nlgo.RtMessage(msg).Attrs(); err != nil {
					return nil
				} else if gw := attr.(nlgo.AttrMap).Get(nlgo.RTA_GATEWAY); gw != nil {
					if mac := v6toMac(net.IP(gw.(nlgo.Binary))); mac != nil {
						return mac
					}
				}
			}
		}
	}
	if mac := v6toMac(addr); mac != nil {
		return mac
	}
	return nil
}

func (self NamedPort) GenlListen(ev nlgo.GenlMessage) {
	if ev.Family.Name != "nl80211" {
		return
	}
	switch ev.Genl().Cmd {
	case nlgo.NL80211_CMD_FRAME:
		if attrs, err := nlgo.Nl80211Policy.Parse(ev.Body()); err != nil {
			log.Print(err)
		} else if frame, err := FrameFromNlAttr(attrs.(nlgo.AttrMap), self.mac, self.fragmentId); err != nil {
			log.Print(err)
		} else {
			self.ingress <- frame
			self.fragmentId++
		}
	case nlgo.NL80211_CMD_FRAME_TX_STATUS:
		var cookie uint64
		var ack bool

		if attrs, err := nlgo.Nl80211Policy.Parse(ev.Body()); err != nil {
			log.Print(err)
		} else if amap, ok := attrs.(nlgo.AttrMap); !ok {
			log.Print("nl80211 policy did not return attr map")
		} else {
			cookie = uint64(amap.Get(nlgo.NL80211_ATTR_COOKIE).(nlgo.U64))
			if value := amap.Get(nlgo.NL80211_ATTR_ACK); value != nil {
				ack = true
			}
		}
		func() {
			self.lock.Lock()
			defer self.lock.Unlock()

			if status, ok := self.txStatus[cookie]; ok {
				if !ack {
					status <- fmt.Errorf("NL80211_ATTR_ACK missing")
				}
				close(status)
				delete(self.txStatus, cookie)
			} else {
				log.Print("unhandled tx cookie")
			}
		}()
	}
}

func (self *NamedPort) Down() {
	self.lock.Lock()
	defer self.lock.Unlock()
	if self.ghub != nil {
		self.ghub.Close()
		self.ghub = nil
	}
	if self.fd != -1 {
		syscall.Close(self.fd)
		self.fd = -1
	}
}

func (self NamedPort) Close() error {
	close(self.monitor)
	close(self.ingress)
	return nil
}

func (self *NamedPort) Vendor(reqAny interface{}) interface{} {
	nl80211 := self.ghub.Family("nl80211")
	mgmtFramesSync := func() error {
		if len(self.mgmtFrames) == 0 {
			return nil
		}
		if self.ghub != nil {
			self.ghub.Close()
			self.ghub = nil
		}
		if self.ghub == nil {
			if hub, err := nlgo.NewGenlHub(); err != nil {
				return err
			} else {
				self.ghub = hub
			}
		}
		for _, fr := range self.mgmtFrames {
			if hres, err := self.ghub.Sync(nl80211.Request(nlgo.NL80211_CMD_REGISTER_FRAME, syscall.NLM_F_REQUEST, nil, nlgo.AttrSlice{
				nlgo.Attr{
					Header: syscall.NlAttr{
						Type: nlgo.NL80211_ATTR_FRAME_MATCH,
					},
					Value: nlgo.Binary(fr),
				},
			}.Bytes())); err != nil {
				return err
			} else {
				for _, hr := range hres {
					if hr.Header.Type == syscall.NLMSG_ERROR {
						return fmt.Errorf("NL80211_CMD_REGISTER_FRAME failed")
					}
				}
			}
		}
		return nil
	}
	switch req := reqAny.(type) {
	case MgmtFrameAdd:
		prefix := MgmtFramePrefix(req)
		for _, p := range self.mgmtFrames {
			if bytes.Equal([]byte(p), []byte(prefix)) {
				return nil
			}
		}
		self.mgmtFrames = append(self.mgmtFrames, prefix)
		if err := mgmtFramesSync(); err != nil {
			return err
		}
	case MgmtFrameRemove:
		prefix := MgmtFramePrefix(req)
		var newMgmtFrames []MgmtFramePrefix
		for _, p := range self.mgmtFrames {
			if !bytes.Equal([]byte(p), []byte(prefix)) {
				newMgmtFrames = append(newMgmtFrames, p)
			}
		}
		self.mgmtFrames = newMgmtFrames
		if err := mgmtFramesSync(); err != nil {
			return err
		}
	}
	return nil
}

type NamedPortManager struct {
	lock          *sync.Mutex
	trackingNames []string
	trackingWiphy []uint32
	// all ports this manager handles. key is ifindex.
	ports map[uint32]*NamedPort

	datapath Datapath
	hub      *nlgo.RtHub
	ghub     *nlgo.GenlHub
	rhub     *nlgo.RtHub // for routing table lookup
}

func NewNamedPortManager(datapath Datapath) (*NamedPortManager, error) {
	self := &NamedPortManager{
		datapath: datapath,
		ports:    make(map[uint32]*NamedPort),
		lock:     &sync.Mutex{},
	}
	if ghub, err := nlgo.NewGenlHub(); err != nil {
		return nil, err
	} else if hub, err := nlgo.NewRtHub(); err != nil {
		ghub.Close()
		return nil, err
	} else if rhub, err := nlgo.NewRtHub(); err != nil {
		ghub.Close()
		hub.Close()
		return nil, err
	} else {
		self.hub = hub
		self.ghub = ghub
		self.rhub = rhub
		if err := hub.Add(syscall.RTNLGRP_LINK, self); err != nil {
			hub.Close()
			ghub.Close()
			return nil, err
		}
	}
	return self, nil
}

func (self NamedPortManager) Close() error {
	self.hub.Close()
	self.ghub.Close()
	self.rhub.Close()
	return nil
}

func (self *NamedPortManager) AddName(name string) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.trackingNames = append(self.trackingNames, name)

	req := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  syscall.RTM_GETLINK,
			Flags: syscall.NLM_F_DUMP,
		},
	}
	(*nlgo.RtMessage)(&req).Set(
		syscall.RtMsg{},
		nlgo.AttrSlice{
			nlgo.Attr{
				Header: syscall.NlAttr{
					Type: syscall.IFLA_IFNAME,
				},
				Value: nlgo.NulString(name),
			},
		})
	if res, err := self.hub.Sync(req); err != nil {
		return err
	} else {
		for _, r := range res {
			self.NetlinkListen(r)
		}
	}
	return nil
}

func (self *NamedPortManager) RemoveName(name string) {
	self.lock.Lock()
	defer self.lock.Unlock()

	var active []string
	for _, a := range self.trackingNames {
		if a != name {
			active = append(active, a)
		}
	}
	self.trackingNames = active
}

func (self *NamedPortManager) NetlinkListen(ev syscall.NetlinkMessage) {
	mtype := ev.Header.Type
	if mtype != syscall.RTM_NEWLINK && mtype != syscall.RTM_DELLINK {
		return // no concern
	}

	msg := nlgo.IfInfoMessage(ev)
	ifinfo := msg.IfInfo()
	evPort := &NamedPort{
		ifIndex: uint32(ifinfo.Index),
		flags:   ifinfo.Flags,
		fd:      -1,
		lock:    &sync.Mutex{},
		rhub:    self.rhub,
	}
	if attrs, err := msg.Attrs(); err != nil {
		log.Print(err)
	} else if amap, ok := attrs.(nlgo.AttrMap); !ok {
		log.Print("route link policy did not return attr map")
	} else {
		if t := amap.Get(nlgo.IFLA_IFNAME); t != nil {
			evPort.name = string(t.(nlgo.NulString))
		}
		if t := amap.Get(nlgo.IFLA_MTU); t != nil {
			evPort.mtu = uint32(t.(nlgo.U32))
		}
		if t := amap.Get(nlgo.IFLA_ADDRESS); t != nil {
			evPort.mac = []byte(t.(nlgo.Binary))
		}
	}
	nl80211 := self.ghub.Family("nl80211")

	switch mtype {
	case syscall.RTM_NEWLINK:
		if port := self.ports[evPort.ifIndex]; port != nil {
			port.flags = ifinfo.Flags
			if len(evPort.name) > 0 {
				port.name = evPort.name
			}
			if evPort.mtu != 0 {
				port.mtu = evPort.mtu
			}
			if len(evPort.mac) != 0 {
				port.mac = evPort.mac
			}
			port.monitor <- true
			if err := port.Up(); err != nil { // maybe ready for up
				log.Print(err)
			}
			return
		}
		// query wiphy
		if res, err := self.ghub.Sync(nl80211.Request(nlgo.NL80211_CMD_GET_INTERFACE, syscall.NLM_F_DUMP, nil, nlgo.AttrSlice{
			nlgo.Attr{
				Header: syscall.NlAttr{
					Type: nlgo.NL80211_ATTR_IFINDEX,
				},
				Value: nlgo.U32(ifinfo.Index),
			},
		}.Bytes())); err != nil {
			log.Print(err)
		} else {
			for _, r := range res {
				if r.Family.Name != "nl80211" {
					continue
				}
				if attrs, err := nlgo.Nl80211Policy.Parse(r.Body()); err != nil {
					log.Print(err)
				} else if amap, ok := attrs.(nlgo.AttrMap); !ok {
					log.Print("nl80211 attr policy error")
				} else {
					if evPort.ifIndex == uint32(amap.Get(nlgo.NL80211_ATTR_IFINDEX).(nlgo.U32)) {
						evPort.hasWiphy = true
						evPort.wiphy = uint32(amap.Get(nlgo.NL80211_ATTR_WIPHY).(nlgo.U32))
					}
				}
			}
		}
		tracking := func(port *NamedPort) bool {
			for _, name := range self.trackingNames {
				if port.name == name {
					return true
				}
			}
			if port.hasWiphy {
				for _, wiphy := range self.trackingWiphy {
					if port.wiphy == wiphy {
						return true
					}
				}
			}
			for idx, _ := range self.ports {
				if idx == port.ifIndex {
					return true
				}
			}
			return false
		}
		if tracking(evPort) {
			port := evPort
			port.ingress = make(chan Frame)
			port.monitor = make(chan bool)
			self.ports[uint32(ifinfo.Index)] = port
			func() {
				if port.hasWiphy {
					for _, wiphy := range self.trackingWiphy {
						if wiphy == port.wiphy {
							return
						}
					}
					self.trackingWiphy = append(self.trackingWiphy, port.wiphy)
				}
			}()
			self.datapath.AddPort(port)
			port.monitor <- true
			if err := port.Up(); err != nil { // maybe ready for up
				log.Print(err)
			}
		}
	case syscall.RTM_DELLINK:
		if port, ok := self.ports[evPort.ifIndex]; ok && port != nil {
			port.Down()
			port.Close()
			delete(self.ports, evPort.ifIndex)
		}
		// for wiphy unplug
		if res, err := self.ghub.Sync(nl80211.DumpRequest(nlgo.NL80211_CMD_GET_WIPHY)); err != nil {
			log.Print(err)
		} else {
			var activeWiphy []uint32
			for _, r := range res {
				if r.Family.Name != "nl80211" {
					continue
				}
				if attrs, err := nlgo.Nl80211Policy.Parse(r.Body()); err != nil {
					log.Print(err)
				} else {
					activeWiphy = append(activeWiphy, uint32(attrs.(nlgo.AttrMap).Get(nlgo.NL80211_ATTR_WIPHY).(nlgo.U32)))
				}
			}
			var trackingWiphy []uint32
			for _, wiphy := range self.trackingWiphy {
				for _, active := range activeWiphy {
					if wiphy == active {
						trackingWiphy = append(trackingWiphy, wiphy)
					}
				}
			}
			self.trackingWiphy = trackingWiphy
		}
	}
}
