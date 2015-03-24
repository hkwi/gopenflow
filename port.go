// +build linux

package gopenflow

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"encoding/binary"
	"fmt"
	"github.com/hkwi/nlgo"
	syscall2 "github.com/hkwi/suppl/syscall"
	"log"
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
	ghub     *nlgo.GenlHub // GenlHub is here because Frame registration can only be removed by closing the socket.
	txStatus map[uint64]chan error

	// below for non-monitor nl80211
	mgmtFrames []MgmtFramePrefix
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
			if oob.Experimenter == STRATOS_EXPERIMENTER_ID &&
				oob.Field == STRATOS_OXM_FIELD_BASIC &&
				oob.Type == STROXM_BASIC_DOT11 &&
				oob.Value[0] > 0 {
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
			status := make(chan error)
			defer close(status)

			if err := func() error {
				if buf, err := pkt.Dot11(); err != nil {
					return err
				} else {
					self.lock.Lock()
					defer self.lock.Unlock()

					if res, err := self.ghub.Request("nl80211", 1, nlgo.NL80211_CMD_FRAME, 0, nil, nlgo.AttrList{
						nlgo.Attr{
							Header: syscall.NlAttr{
								Type: nlgo.NL80211_ATTR_FRAME,
							},
							Value: buf,
						},
					}); err != nil {
						return err
					} else {
						for _, r := range res {
							if len(r.Family) == 0 {
								return fmt.Errorf("NL80211_CMD_FRAME failed")
							} else if r.Family == "nl80211" {
								if attrs, err := nlgo.Nl80211Policy.Parse(r.Payload); err != nil {
									return err
								} else {
									cookie := attrs.Get(nlgo.NL80211_ATTR_COOKIE).(uint64)
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
		if buf, err := pkt.Radiotap(); err != nil {
			return err
		} else if n, err := syscall.Write(self.fd, buf); err != nil {
			return err
		} else if n != len(buf) {
			return fmt.Errorf("write not complete")
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
				hub.Request(syscall.RTM_NEWLINK, 0, (*[syscall.SizeofIfInfomsg]byte)(unsafe.Pointer(ifinfo))[:], nil)
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
		if res, err := hub.Request(syscall.RTM_GETLINK, syscall.NLM_F_DUMP, ifinfo, nil); err != nil {
			return PortStats{}, err
		} else {
			for _, r := range res {
				switch r.Message.Header.Type {
				case syscall.RTM_NEWLINK:
					if attrs, err := nlgo.RouteLinkPolicy.Parse(r.Message.Data[nlgo.NLMSG_ALIGN(syscall.SizeofIfInfomsg):]); err != nil {
						return PortStats{}, err
					} else if blk := attrs.Get(nlgo.IFLA_STATS64); blk != nil {
						s := (*nlgo.RtnlLinkStats64)(unsafe.Pointer(&blk.([]byte)[0]))
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

func (self *NamedPort) Up() error {
	if self.fd != -1 {
		log.Print("programming error")
		return nil
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
			}
		}
		return nil
	}(); err != nil {
		syscall.Close(self.fd)
		self.fd = -1
		return err
	}
	go func() {
		buf := make([]byte, 32*1024)               // enough for jumbo frame
		oob := make([]byte, syscall.CmsgSpace(20)) // msg_control, 20 = sizeof(auxdata)
		for {
			var frame Frame

			if bufN, oobN, flags, _, err := syscall.Recvmsg(self.fd, buf, oob, syscall.MSG_TRUNC); err != nil {
				log.Print(err)
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
						if f, err := FrameFromRadiotap(rt); err != nil {
							log.Print(err)
						} else {
							frame = f
						}
					}
				}
				if len(frame.Data) != 0 {
					self.ingress <- frame
				}
			}
		}
	}()
	return nil
}

func (self NamedPort) GenlListen(ev nlgo.GenlMessage) {
	if ev.Family != "nl80211" || ev.Genl == nil {
		return
	}
	switch ev.Genl.Cmd {
	case nlgo.NL80211_CMD_FRAME:
		if attrs, err := nlgo.Nl80211Policy.Parse(ev.Payload); err != nil {
			log.Print(err)
		} else if frame, err := FrameFromNlAttr(attrs); err != nil {
			log.Print(err)
		} else {
			self.ingress <- frame
		}
	case nlgo.NL80211_CMD_FRAME_TX_STATUS:
		var cookie uint64
		var ack bool

		if attrs, err := nlgo.Nl80211Policy.Parse(ev.Payload); err != nil {
			log.Print(err)
		} else {
			cookie = attrs.Get(nlgo.NL80211_ATTR_COOKIE).(uint64)
			ack = attrs.Get(nlgo.NL80211_ATTR_ACK).(bool)
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
	if self.ghub != nil {
		self.ghub.Close()
		self.ghub = nil
	}
	if self.fd == -1 {
		log.Print("programming error")
		return
	}
	syscall.Close(self.fd)
	self.fd = -1
}

func (self NamedPort) Close() error {
	close(self.ingress)
	close(self.monitor)
	return nil
}

func (self *NamedPort) Vendor(reqAny interface{}) interface{} {
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
			if hres, err := self.ghub.Request("nl80211", 1, nlgo.NL80211_CMD_REGISTER_FRAME, 0, nil, nlgo.AttrList{
				nlgo.Attr{
					Header: syscall.NlAttr{
						Type: nlgo.NL80211_ATTR_FRAME_MATCH | syscall.NLA_F_NESTED,
					},
					Value: nlgo.Attr{
						Header: syscall.NlAttr{
							Type: uint16(nlgo.NLA_BINARY),
						},
						Value: []byte(fr),
					},
				},
			}); err != nil {
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
	} else if err := hub.Add(syscall.RTNLGRP_LINK, self); err != nil {
		hub.Close()
		ghub.Close()
		return nil, err
	} else {
		self.hub = hub
		self.ghub = ghub
		return self, nil
	}
}

func (self NamedPortManager) Close() error {
	self.hub.Close()
	self.ghub.Close()
	return nil
}

func (self *NamedPortManager) AddName(name string) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.trackingNames = append(self.trackingNames, name)

	if res, err := self.hub.Request(syscall.RTM_GETLINK, syscall.NLM_F_DUMP, nil, nlgo.AttrList{
		nlgo.Attr{
			Header: syscall.NlAttr{
				Type: syscall.IFLA_IFNAME | syscall.NLA_F_NESTED,
			},
			Value: nlgo.Attr{
				Header: syscall.NlAttr{
					Type: uint16(nlgo.NLA_STRING),
				},
				Value: name,
			},
		},
	}); err != nil {
		return err
	} else {
		for _, r := range res {
			self.RtListen(r)
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

func (self *NamedPortManager) RtListen(ev nlgo.RtMessage) {
	mtype := ev.Message.Header.Type
	if mtype != syscall.RTM_NEWLINK && mtype != syscall.RTM_DELLINK {
		return
	}

	ifinfo := (*syscall.IfInfomsg)(unsafe.Pointer(&ev.Message.Data[0]))
	evPort := &NamedPort{
		ifIndex: uint32(ifinfo.Index),
		flags:   ifinfo.Flags,
		fd:      -1,
		lock:    &sync.Mutex{},
	}
	if attrs, err := nlgo.RouteLinkPolicy.Parse(ev.Message.Data[nlgo.NLMSG_ALIGN(syscall.SizeofIfInfomsg):]); err != nil {
		log.Print(err)
	} else {
		if t := attrs.Get(nlgo.IFLA_IFNAME); t != nil {
			evPort.name = nlgo.NlaStringRemoveNul(t.(string))
		}
		if t := attrs.Get(nlgo.IFLA_MTU); t != nil {
			evPort.mtu = t.(uint32)
		}
		if t := attrs.Get(nlgo.IFLA_ADDRESS); t != nil {
			evPort.mac = t.([]byte)
		}
	}
	if res, err := self.ghub.Request("nl80211", 1, nlgo.NL80211_CMD_GET_INTERFACE, syscall.NLM_F_DUMP, nil, nlgo.AttrList{
		nlgo.Attr{
			Header: syscall.NlAttr{
				Type: nlgo.NL80211_ATTR_IFINDEX,
			},
			Value: uint32(ifinfo.Index),
		},
	}); err != nil {
		log.Print(err)
	} else {
		for _, r := range res {
			if r.Family != "nl80211" {
				continue
			}
			if attrs, err := nlgo.Nl80211Policy.Parse(r.Payload); err != nil {
				log.Print(err)
			} else {
				evPort.hasWiphy = true
				evPort.wiphy = attrs.Get(nlgo.NL80211_ATTR_WIPHY).(uint32)
			}
		}
	}

	tracking := func(port *NamedPort) bool {
		for _, name := range self.trackingNames {
			if port.name == name {
				return true
			}
		}
		for _, wiphy := range self.trackingWiphy {
			if port.wiphy == wiphy {
				return true
			}
		}
		for idx, _ := range self.ports {
			if idx == port.ifIndex {
				return true
			}
		}
		return false
	}

	switch mtype {
	case syscall.RTM_NEWLINK:
		if port := self.ports[evPort.ifIndex]; port != nil {
			triggerUp := false
			if tracking(evPort) && evPort.flags&syscall.IFF_UP != 0 &&
				(!tracking(port) || port.flags&syscall.IFF_UP == 0) {
				triggerUp = true
			}

			port.flags = (port.flags &^ ifinfo.Change) | (ifinfo.Flags & ifinfo.Change)
			if len(evPort.name) > 0 {
				port.name = evPort.name
			}
			if evPort.hasWiphy {
				port.hasWiphy = true
				port.wiphy = evPort.wiphy
			}
			if evPort.mtu != 0 {
				port.mtu = evPort.mtu
			}
			if len(evPort.mac) != 0 {
				port.mac = evPort.mac
			}
			port.monitor <- true
			if triggerUp {
				if err := port.Up(); err != nil {
					log.Print(err)
				}
			}
		} else if tracking(evPort) {
			port = evPort
			port.ingress = make(chan Frame)
			port.monitor = make(chan bool)
			self.ports[uint32(ifinfo.Index)] = port
			if port.hasWiphy {
				func() {
					for _, wiphy := range self.trackingWiphy {
						if wiphy == port.wiphy {
							return
						}
					}
					self.trackingWiphy = append(self.trackingWiphy, port.wiphy)
				}()
			}
			self.datapath.AddPort(port)
			port.monitor <- true
			if err := port.Up(); err != nil {
				log.Print(err)
			}
		}
	case syscall.RTM_DELLINK:
		if port := self.ports[evPort.ifIndex]; port != nil {
			port.Down()
			port.monitor <- false
		}
		if res, err := self.ghub.Request("nl80211", 1, nlgo.NL80211_CMD_GET_WIPHY, syscall.NLM_F_DUMP, nil, nil); err != nil {
			log.Print(err)
		} else {
			var activeWiphy []uint32
			for _, r := range res {
				if r.Family != "nl80211" {
					continue
				}
				if attrs, err := nlgo.Nl80211Policy.Parse(r.Payload); err != nil {
					log.Print(err)
				} else {
					activeWiphy = append(activeWiphy, attrs.Get(nlgo.NL80211_ATTR_WIPHY).(uint32))
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
