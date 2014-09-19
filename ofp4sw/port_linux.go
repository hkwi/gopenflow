// +build linux

package ofp4sw

import (
	"encoding/binary"
	"errors"
	"log"
	"syscall"
	"unsafe"
)

type NamedPort struct {
	hwAddr       [6]byte
	name         string
	physicalPort uint32
	close        chan error
	ingress      chan []byte
	watch        chan *PortState
	handle       *pktSock
}

func (self NamedPort) Name() string {
	return self.name
}

func (self NamedPort) PhysicalPort() uint32 {
	return self.physicalPort
}

func (self NamedPort) Ingress() <-chan []byte {
	return self.ingress
}

func (self NamedPort) Egress(pkt []byte) error {
	if self.handle != nil {
		return self.handle.Put(pkt)
	}
	return errors.New("not open")
}

func (self NamedPort) Watch() <-chan *PortState {
	return self.watch
}

func NewNamedPort(name string) *NamedPort {
	self := &NamedPort{
		name:    name,
		ingress: make(chan []byte, 64),
		watch:   make(chan *PortState),
	}
	go func() {
		netdevWatch := make(chan NetdevUpdate)
		if err := IfplugdAddListener(netdevWatch); err != nil {
			log.Print(err)
			return
		}
		if evs, err := IfplugdGet(); err != nil {
			log.Print(err)
			return
		} else {
			for _, ev := range evs {
				self.handleNetdev(ev)
			}
		}
		func() {
			for {
				select {
				case <-self.close:
					return
				case ev, ok := <-netdevWatch:
					if ok {
						self.handleNetdev(ev)
					} else {
						return
					}
				}
			}
		}()
		_ = IfplugdRemoveListener(netdevWatch)
		if self.handle != nil {
			self.handle.Close()
		}
		close(self.ingress)
		close(self.watch)
	}()
	return self
}

func (self *NamedPort) handleNetdev(ev NetdevUpdate) {
	if ev.Name == self.name {
		state := &PortState{
			Name:     ev.Name,
			LinkDown: !ev.LowerUp,
			Blocked:  !ev.Up,
			Live:     ev.Running,
			Mtu:      ev.Mtu,
		}
		if ev.Type == syscall.RTM_NEWLINK {
			if ev.Up && self.handle == nil {
				if handle, err := newPktSock(int(ev.Index)); err != nil {
					log.Print(err)
					return
				} else {
					self.handle = handle
					go func() {
						defer func() {
							log.Print(recover())
						}()
						epfd, e1 := syscall.EpollCreate1(0)
						if e1 != nil {
							log.Print(e1)
							return
						}
						defer syscall.Close(epfd)
						e2 := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, handle.fd, &syscall.EpollEvent{
							Events: syscall.EPOLLIN | syscall.EPOLLPRI,
						})
						if e2 != nil {
							log.Print(e2)
							return
						}
						evs := []syscall.EpollEvent{syscall.EpollEvent{}}
						for {
							if data, err := handle.Get(); err != nil {
								switch e := err.(type) {
								case pktSockIgnore:
									// continue
								case syscall.Errno:
									if e.Temporary() || e.Timeout() {
										if err := func() error {
											for {
												if _, err := syscall.EpollWait(epfd, evs, 20); err != nil {
													switch e := err.(type) {
													case syscall.Errno:
														if !e.Timeout() {
															return e
														}
													default:
														return e
													}
												} else {
													return nil
												}
											}
										}(); err != nil {
											log.Print(err)
											return
										}
									} else {
										log.Print(e)
										return
									}
								default:
									log.Print(e)
									return
								}
							} else {
								self.ingress <- data
							}
						}
					}()
				}
			}
			pcapPortState(self.name, state)
		} else {
			if self.handle != nil {
				self.handle.Close()
				self.handle = nil
			}
		}
		self.watch <- state
	}
}

type Auxdata struct {
	Status   uint32
	Len      uint32
	Snaplen  uint32
	Mac      uint16
	Net      uint16
	VlanTci  uint16
	VlanTpid uint16
}

const (
	PACKET_AUXDATA = 8
	PACKET_VERSION = 10
)
const (
	TPACKET_V1 = iota
	TPACKET_V2
	TPACKET_V3
)
const (
	TP_STATUS_VLAN_VALID      = 1 << 4
	TP_STATUS_VLAN_TPID_VALID = 1 << 6
)

type pktSock struct {
	ifindex int
	fd      int
}

func newPktSock(ifindex int) (*pktSock, error) {
	ETH_P_ALL := uint16(0x0300) // htons(syscall.ETH_P_ALL)
	fd, e1 := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if e1 != nil {
		return nil, e1
	}
	e2 := func() error {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, PACKET_AUXDATA, 1); err != nil {
			return err
		}
		if err := syscall.SetNonblock(fd, true); err != nil {
			return err
		}
		if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
			Protocol: ETH_P_ALL,
			Ifindex:  ifindex,
		}); err != nil {
			return err
		}
		return nil
	}()
	if e2 != nil {
		syscall.Close(fd)
		return nil, e2
	}
	return &pktSock{
		ifindex: ifindex,
		fd:      fd,
	}, nil
}

type pktSockIgnore string

func (self pktSockIgnore) Error() string {
	return string(self)
}

func (self pktSock) Get() ([]byte, error) {
	p := make([]byte, 32*1024)                 // enough for jumbo frame
	oob := make([]byte, syscall.CmsgSpace(20)) // msg_control, 20 = sizeof(auxdata)
	n, _, flags, from, err := syscall.Recvmsg(self.fd, p, oob, syscall.MSG_TRUNC|syscall.MSG_DONTWAIT)
	if err != nil {
		return nil, err
	}

	if from.(*syscall.SockaddrLinklayer).Ifindex != self.ifindex {
		return nil, pktSockIgnore("ifindex mismatch")
	}

	if flags&syscall.MSG_CTRUNC == 0 {
		if cmsgs, err := syscall.ParseSocketControlMessage(oob); err != nil {
			return nil, err
		} else {
			for _, cmsg := range cmsgs {
				if cmsg.Header.Type == PACKET_AUXDATA {
					var vlanTpid uint16 = 0x8100
					var vlanTci uint16

					aux := (*Auxdata)(unsafe.Pointer(&cmsg.Data[0]))
					switch len(cmsg.Data) {
					case 20:
						if aux.Status&TP_STATUS_VLAN_TPID_VALID != 0 {
							vlanTpid = aux.VlanTpid
						}
					case 18:
						// pass
					default:
						return nil, errors.New("unexpected PACKET_AUXDATA")
					}
					if aux.Status&TP_STATUS_VLAN_VALID != 0 {
						vlanTci = aux.VlanTci

						copy(p[16:], p[12:n])
						binary.BigEndian.PutUint16(p[12:], vlanTpid)
						binary.BigEndian.PutUint16(p[14:], vlanTci)
						return p[:n+4], nil
					}
				}
			}
		}
	}
	return p[:n], nil
}

func (self pktSock) Put(data []byte) error {
	return syscall.Sendto(self.fd, data, syscall.MSG_DONTWAIT, &syscall.SockaddrLinklayer{
		Ifindex: self.ifindex,
	})
}

func (self pktSock) Close() {
	syscall.Close(self.fd)
}
