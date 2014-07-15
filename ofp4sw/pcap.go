package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"github.com/hkwi/gopenflow/ofp4"
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
	// TODO: ioctl system call with ETHTOOL_GMODULEINFO/ETHTOOL_GMODULEEEPROM
	// TODO: netlink IFF_UP
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
	if stat, err := p.handle.Stats(); err != nil {
		log.Print(err)
	} else {
		stats.RxDropped = uint64(stat.PacketsDropped) + uint64(stat.PacketsIfDropped)
	}
	return stats
}

func NewPcapPort(name string) (*PcapPort, error) {
	handle, err := pcap.OpenLive(name, 16000, true, pcap.BlockForever)
	if err != nil {
		return nil, err
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
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
		// packetSource.Packets() buffers too much
		for {
			if packet, err := packetSource.NextPacket(); err != nil {
				log.Print(err)
				break
			} else {
				b := packet.Data()
				port.stats.RxBytes += uint64(len(b))
				port.stats.RxPackets++
				fsource <- b
			}
		}
		port.handle.Close()
	}()
	go func() {
		fout := (<-chan []byte)(fout)
		for b := range fout {
			if err := handle.WritePacketData(b); err != nil {
				log.Print(err)
				break
			}
			port.stats.TxBytes += uint64(len(b))
			port.stats.TxPackets++
		}
		port.handle.Close()
	}()
	return port, nil
}
