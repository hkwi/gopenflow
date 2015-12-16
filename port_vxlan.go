package gopenflow

import (
	"net"
	"encoding/binary"
	"github.com/hkwi/gopenflow/oxm"
	"fmt"
	"log"
)

type VxlanPort struct {
	name string
	mac [6]byte
	port int
	mtu int
	ingress chan<-Frame
	conn *net.UDPConn
}

func (self VxlanPort) Name() string{
	return self.name
}

func (self VxlanPort) HwAddr() [6]byte {
	return self.mac
}

func nxm_bytes(oxmtype uint32, value []byte) []byte {
	ret := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(ret, oxmtype + uint32(len(ret)))
	copy(ret[4:], value)
	return ret
}

func (self VxlanPort) Egress(fr Frame) error {
	var dst net.IP
	vxlan := make([]byte, 8+len(fr.Data))
	vxlan[0] = 0x08 // valid flag
	for _, x := range oxm.Oxm(fr.Oob).Iter() {
		switch x.Header().Type(){
		case oxm.OXM_OF_TUNNEL_ID:
			copy(vxlan[4:7], x[9:12])
		case oxm.NXM_NX_TUN_IPV4_DST:
			dst = net.IP(x[4:8])
		}
	}
	copy(vxlan[8:], fr.Data)
	if n, err := self.conn.WriteToUDP(vxlan, &net.UDPAddr{
		IP: dst,
		Port: self.port,
	}); err != nil {
		return err
	} else if n < len(vxlan) {
		fmt.Printf("MTU error?")
	}
	return nil
}

func (self *VxlanPort) Up() error {
	if conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: self.port,
	}); err != nil {
		return err
	} else {
		self.conn = conn
		go func(){
			buf := make([]byte, 8 + self.mtu)
			for {
				if n, addr, err := conn.ReadFromUDP(buf); err != nil {
					log.Print(err)
					break
				} else {
					fr := Frame {
						Data: buf[8:n],
					}
					fr.Oob = append(fr.Oob, nxm_bytes(oxm.OXM_OF_TUNNEL_ID, []byte{
						0,0,0,0,0,buf[4],buf[5],buf[6]})...)
					if src4 := addr.IP.To4(); src4 != nil {
						fr.Oob = append(fr.Oob, nxm_bytes(oxm.NXM_NX_TUN_IPV4_SRC, []byte(src4))...)
					}
					self.ingress <- fr
				}
			}
		}()
	}
	return nil
}

func (self *VxlanPort) Down() error {
	if self.conn != nil {
		self.conn.Close()
	}
	self.conn = nil
	return nil
}
