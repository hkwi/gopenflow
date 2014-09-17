package ofp4sw

// +build linux,cgo

/*
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ethtool.h>

int ethtool_cmd_call(int fd, char *name, struct ethtool_cmd *ecmd){
	struct ifreq ifr;
	memset(ifr.ifr_name, 0, IFNAMSIZ);
	int i;
	for(i=0; i<strlen(name); i++){
		if(i<IFNAMSIZ){
			ifr.ifr_name[i] = name[i];
		}
	}
	ifr.ifr_data = (char*)ecmd;
	return ioctl(fd, SIOCETHTOOL, &ifr);
}

void* get_hwaddr(int fd, char *name, int *hwaddr_len){
	struct ifreq ifr;
	memset(ifr.ifr_name, 0, IFNAMSIZ);
	int i;
	for(i=0; i<strlen(name); i++){
		if(i<IFNAMSIZ){
			ifr.ifr_name[i] = name[i];
		}
	}
	if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		*hwaddr_len = ETH_ALEN;
		char *hwaddr = malloc(ETH_ALEN);
		memmove(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		return hwaddr;
	}
	return NULL;
}

*/
import "C"
import (
	"encoding/binary"
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
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
						if e1!=nil {
							log.Print(e1)
							return
						}
						defer syscall.Close(epfd)
						e2 := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, handle.fd, &syscall.EpollEvent{
							Events: syscall.EPOLLIN|syscall.EPOLLPRI,
						})
						if e2!=nil {
							log.Print(e2)
							return
						}
						evs := []syscall.EpollEvent{ syscall.EpollEvent{} }
						for {
							if data, err := handle.Get(); err != nil {
								switch e := err.(type) {
								case pktSockIgnore:
									// continue
								case syscall.Errno:
									if e.Temporary() || e.Timeout() {
										if err:=func() error {
											for {
												if _,err := syscall.EpollWait(epfd, evs, 20); err!=nil {
													switch e:=err.(type) {
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
										}(); err!=nil {
											log.Print(err)
											return
										}
									}else{
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

var supportedSpeed map[C.__u32]uint32 = map[C.__u32]uint32{
	C.SUPPORTED_10baseT_Half:       10000,
	C.SUPPORTED_10baseT_Full:       10000,
	C.SUPPORTED_100baseT_Half:      100000,
	C.SUPPORTED_100baseT_Full:      100000,
	C.SUPPORTED_1000baseT_Half:     1000000,
	C.SUPPORTED_1000baseT_Full:     1000000,
	C.SUPPORTED_10000baseT_Full:    10000000,
	C.SUPPORTED_2500baseX_Full:     2500000,
	C.SUPPORTED_1000baseKX_Full:    1000000,
	C.SUPPORTED_10000baseKX4_Full:  10000000,
	C.SUPPORTED_10000baseKR_Full:   10000000,
	C.SUPPORTED_10000baseR_FEC:     10000000,
	C.SUPPORTED_20000baseMLD2_Full: 20000000,
	C.SUPPORTED_20000baseKR2_Full:  20000000,
	C.SUPPORTED_40000baseKR4_Full:  40000000,
	C.SUPPORTED_40000baseCR4_Full:  40000000,
	C.SUPPORTED_40000baseSR4_Full:  40000000,
	C.SUPPORTED_40000baseLR4_Full:  40000000,
}
var supportedConvert map[C.__u32]uint32 = map[C.__u32]uint32{
	C.SUPPORTED_10baseT_Half:       ofp4.OFPPF_10MB_HD,
	C.SUPPORTED_10baseT_Full:       ofp4.OFPPF_10MB_FD,
	C.SUPPORTED_100baseT_Half:      ofp4.OFPPF_100MB_HD,
	C.SUPPORTED_100baseT_Full:      ofp4.OFPPF_100MB_FD,
	C.SUPPORTED_1000baseT_Half:     ofp4.OFPPF_1GB_HD,
	C.SUPPORTED_1000baseT_Full:     ofp4.OFPPF_1GB_FD,
	C.SUPPORTED_Autoneg:            ofp4.OFPPF_AUTONEG,
	C.SUPPORTED_TP:                 ofp4.OFPPF_COPPER,
	C.SUPPORTED_10000baseT_Full:    ofp4.OFPPF_10GB_FD,
	C.SUPPORTED_Pause:              ofp4.OFPPF_PAUSE,
	C.SUPPORTED_Asym_Pause:         ofp4.OFPPF_PAUSE_ASYM,
	C.SUPPORTED_2500baseX_Full:     ofp4.OFPPF_OTHER,
	C.SUPPORTED_1000baseKX_Full:    ofp4.OFPPF_1GB_FD,
	C.SUPPORTED_10000baseKX4_Full:  ofp4.OFPPF_10MB_FD,
	C.SUPPORTED_10000baseKR_Full:   ofp4.OFPPF_10GB_FD,
	C.SUPPORTED_10000baseR_FEC:     ofp4.OFPPF_10GB_FD,
	C.SUPPORTED_20000baseMLD2_Full: ofp4.OFPPF_OTHER,
	C.SUPPORTED_20000baseKR2_Full:  ofp4.OFPPF_OTHER,
	C.SUPPORTED_40000baseKR4_Full:  ofp4.OFPPF_40GB_FD,
	C.SUPPORTED_40000baseCR4_Full:  ofp4.OFPPF_40GB_FD,
	C.SUPPORTED_40000baseSR4_Full:  ofp4.OFPPF_40GB_FD,
	C.SUPPORTED_40000baseLR4_Full:  ofp4.OFPPF_40GB_FD,
}
var advertisedConvert map[C.__u32]uint32 = map[C.__u32]uint32{
	C.ADVERTISED_10baseT_Half:       ofp4.OFPPF_10MB_HD,
	C.ADVERTISED_10baseT_Full:       ofp4.OFPPF_10MB_FD,
	C.ADVERTISED_100baseT_Half:      ofp4.OFPPF_100MB_HD,
	C.ADVERTISED_100baseT_Full:      ofp4.OFPPF_100MB_FD,
	C.ADVERTISED_1000baseT_Half:     ofp4.OFPPF_1GB_HD,
	C.ADVERTISED_1000baseT_Full:     ofp4.OFPPF_1GB_FD,
	C.ADVERTISED_Autoneg:            ofp4.OFPPF_AUTONEG,
	C.ADVERTISED_TP:                 ofp4.OFPPF_COPPER,
	C.ADVERTISED_10000baseT_Full:    ofp4.OFPPF_10GB_FD,
	C.ADVERTISED_Pause:              ofp4.OFPPF_PAUSE,
	C.ADVERTISED_Asym_Pause:         ofp4.OFPPF_PAUSE_ASYM,
	C.ADVERTISED_2500baseX_Full:     ofp4.OFPPF_OTHER,
	C.ADVERTISED_1000baseKX_Full:    ofp4.OFPPF_1GB_FD,
	C.ADVERTISED_10000baseKX4_Full:  ofp4.OFPPF_10MB_FD,
	C.ADVERTISED_10000baseKR_Full:   ofp4.OFPPF_10GB_FD,
	C.ADVERTISED_10000baseR_FEC:     ofp4.OFPPF_10GB_FD,
	C.ADVERTISED_20000baseMLD2_Full: ofp4.OFPPF_OTHER,
	C.ADVERTISED_20000baseKR2_Full:  ofp4.OFPPF_OTHER,
	C.ADVERTISED_40000baseKR4_Full:  ofp4.OFPPF_40GB_FD,
	C.ADVERTISED_40000baseCR4_Full:  ofp4.OFPPF_40GB_FD,
	C.ADVERTISED_40000baseSR4_Full:  ofp4.OFPPF_40GB_FD,
	C.ADVERTISED_40000baseLR4_Full:  ofp4.OFPPF_40GB_FD,
}

func pcapPortState(name string, state *PortState) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	fd := C.socket(C.AF_INET, C.SOCK_DGRAM, 0)
	defer C.close(fd)

	ecmd := C.struct_ethtool_cmd{cmd: C.ETHTOOL_GSET}
	if r, err := C.ethtool_cmd_call(fd, cname, &ecmd); err != nil {
		return err
	} else if r != 0 {
		return errors.New("ethtool_cmd_call error")
	} else {
		for k, v := range supportedSpeed {
			if ecmd.supported&k != 0 && v > state.MaxSpeed {
				state.MaxSpeed = v
			}
		}
		state.Supported = 0
		for k, v := range supportedConvert {
			if ecmd.supported&k != 0 {
				state.Supported |= v
			}
		}
		state.Advertised = 0
		state.Peer = 0
		for k, v := range advertisedConvert {
			if ecmd.advertising&k != 0 {
				state.Advertised |= v
			}
			if ecmd.lp_advertising&k != 0 {
				state.Peer |= v
			}
		}

		var curr uint32
		switch C.ethtool_cmd_speed(&ecmd) {
		case C.SPEED_10:
			state.CurrSpeed = 10000
			switch ecmd.duplex {
			case C.DUPLEX_HALF:
				curr |= ofp4.OFPPF_10MB_HD
			case C.DUPLEX_FULL:
				curr |= ofp4.OFPPF_10MB_FD
			default:
				curr |= ofp4.OFPPF_OTHER
			}
		case C.SPEED_100:
			state.CurrSpeed = 100000
			switch ecmd.duplex {
			case C.DUPLEX_HALF:
				curr |= ofp4.OFPPF_100MB_HD
			case C.DUPLEX_FULL:
				curr |= ofp4.OFPPF_100MB_FD
			default:
				curr |= ofp4.OFPPF_OTHER
			}
		case C.SPEED_1000:
			state.CurrSpeed = 1000000
			switch ecmd.duplex {
			case C.DUPLEX_HALF:
				curr |= ofp4.OFPPF_1GB_HD
			case C.DUPLEX_FULL:
				curr |= ofp4.OFPPF_1GB_FD
			default:
				curr |= ofp4.OFPPF_OTHER
			}
		case C.SPEED_10000:
			state.CurrSpeed = 1000000
			switch ecmd.duplex {
			case C.DUPLEX_FULL:
				curr |= ofp4.OFPPF_10GB_FD
			default:
				curr |= ofp4.OFPPF_OTHER
			}
		default:
			curr |= ofp4.OFPPF_OTHER
		}
		switch ecmd.port {
		case C.PORT_TP:
			curr |= ofp4.OFPPF_COPPER
		case C.PORT_FIBRE:
			curr |= ofp4.OFPPF_FIBER
		}
		if ecmd.autoneg != C.AUTONEG_DISABLE {
			curr |= ofp4.OFPPF_AUTONEG
		}
		state.Curr = curr
	}
	var cHwaddrLen C.int
	if cHwaddr, err := C.get_hwaddr(fd, cname, &cHwaddrLen); err != nil {
		return err
	} else {
		hwAddr := C.GoBytes(unsafe.Pointer(cHwaddr), cHwaddrLen)
		for i, _ := range state.HwAddr {
			if i < int(cHwaddrLen) {
				state.HwAddr[i] = hwAddr[i]
			}
		}
		C.free(cHwaddr)
	}
	return nil
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

func newPktSock(ifindex int) (*pktSock,error) {
	ETH_P_ALL := uint16(0x0300) // htons(syscall.ETH_P_ALL)
	fd, e1 := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if e1 != nil {
		return nil, e1
	}
	e2 := func() error {
		if err:=syscall.SetsockoptInt(fd, syscall.SOL_PACKET, PACKET_AUXDATA, 1); err!=nil {
			return err
		}
		if err:=syscall.SetNonblock(fd, true); err!=nil {
			return err
		}
		if err:=syscall.Bind(fd, &syscall.SockaddrLinklayer{
			Protocol: ETH_P_ALL,
			Ifindex:  ifindex,
		}); err!=nil {
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
	p := make([]byte, 32*1024) // enough for jumbo frame
	oob := make([]byte, syscall.CmsgSpace(20)) // msg_control, 20 = sizeof(auxdata)
	n, _, flags, from, err := syscall.Recvmsg(self.fd, p, oob, syscall.MSG_TRUNC|syscall.MSG_DONTWAIT)
	if err != nil {
		return nil, err
	}
	
	if from.(*syscall.SockaddrLinklayer).Ifindex != self.ifindex {
		return nil, pktSockIgnore("ifindex mismatch")
	}
	
	if flags&syscall.MSG_CTRUNC == 0 {
		if cmsgs, err:=syscall.ParseSocketControlMessage(oob); err!=nil {
			return nil, err
		}else{
			for _,cmsg := range cmsgs {
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

