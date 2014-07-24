package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/hkwi/gopenflow/pcap"
	"log"
)

type PcapPort struct {
	// ofp_port
	portNo uint32
	hwAddr [ofp4.OFP_ETH_ALEN]byte
	name   string
	// ofp_port_config
	configDown       bool
	configNoRecv     bool
	configNoFwd      bool
	configNoPacketIn bool
	stats            PortStats
	PhysicalPort     uint32
	handle           *pcap.Handle
	source           <-chan []byte
	egress           chan<- []byte
}

func (p PcapPort) GetPort() ofp4.Port {
	var info ofp4.Port
	info.Name = p.name
	info.Config = p.GetConfig()
	getPortDetail(&info)
	if info.Config&ofp4.OFPPC_PORT_DOWN == 0 && info.State&ofp4.OFPPS_LINK_DOWN == 0 {
		info.State |= ofp4.OFPPS_LIVE
	}
	return info
}

func (p PcapPort) GetPhysicalPort() uint32 {
	return p.PhysicalPort
}

func (p PcapPort) Ingress() <-chan []byte {
	return p.source
}

func (p PcapPort) Egress() chan<- []byte {
	return p.egress
}

func (p *PcapPort) SetPortNo(portNo uint32) {
	p.portNo = portNo
}

func (p PcapPort) GetConfig() uint32 {
	var config uint32
	if p.configDown {
		config |= ofp4.OFPPC_PORT_DOWN
	}
	if p.configNoRecv {
		config |= ofp4.OFPPC_NO_RECV
	}
	if p.configNoFwd {
		config |= ofp4.OFPPC_NO_FWD
	}
	if p.configNoPacketIn {
		config |= ofp4.OFPPC_NO_PACKET_IN
	}
	return config
}

func (p *PcapPort) SetConfig(config uint32) {
	if config&ofp4.OFPPC_PORT_DOWN == 0 {
		p.configDown = false
	} else {
		p.configDown = true
	}
	if config&ofp4.OFPPC_NO_RECV == 0 {
		p.configNoRecv = false
	} else {
		p.configNoRecv = true
	}
	if config&ofp4.OFPPC_NO_FWD == 0 {
		p.configNoFwd = false
	} else {
		p.configNoFwd = true
	}
	if config&ofp4.OFPPC_NO_PACKET_IN == 0 {
		p.configNoPacketIn = false
	} else {
		p.configNoPacketIn = true
	}
}

func (p PcapPort) GetStats() PortStats {
	stats := p.stats
	return stats
}

func NewPcapPort(name string) (*PcapPort, error) {
	handle, err := pcap.Create(name)
	if err != nil {
		return nil, err
	}
	if e:=handle.SetTimeout(10); e!=nil {
		return nil, e
	}
	if e:=handle.Activate(); e!=nil {
		return nil, e
	}
	if e:=handle.Setnonblock(true); e!=nil {
		return nil, e
	}
	
	fsource := make(chan []byte)
	fout := make(chan []byte)
	port := &PcapPort{
		name:   name,
		handle: handle,
		source: (<-chan []byte)(fsource),
		egress: (chan<- []byte)(fout),
	}
	go func() {
		fsource := (chan<- []byte)(fsource)
		for {
			if packet, err := handle.NextPacket(); err != nil {
				log.Print(err)
				break
			} else {
				port.stats.RxBytes += uint64(len(packet))
				port.stats.RxPackets++
				fsource <- packet
			}
		}
		handle.Close()
	}()
	go func() {
		fout := (<-chan []byte)(fout)
		for b := range fout {
			if err := handle.Sendpacket(b); err != nil {
				log.Print(err)
				break
			}
			port.stats.TxBytes += uint64(len(b))
			port.stats.TxPackets++
		}
		handle.Close()
	}()
	return port, nil
}
