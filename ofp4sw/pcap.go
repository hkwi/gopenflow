package ofp4sw

import (
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket"
	"log"
)

type PcapPort struct {
	Name string
	PhysicalPort uint32
	Desc string
	handle *pcap.Handle
	source chan []byte
	egress chan []byte
	stats PortStats
}

func (p PcapPort) GetName() string {
	return p.Name
}

func (p PcapPort) GetDesc() string {
	return p.Desc
}

func (p PcapPort) Ingress() <-chan []byte {
	return p.source
}

func (p PcapPort) Egress() chan<- []byte {
	return p.egress
}

func (p PcapPort) GetPhysicalPort() uint32 {
	return p.PhysicalPort
}

func (p PcapPort) GetStats() PortStats {
	if stat,err := p.handle.Stats(); err != nil {
		log.Print(err)
	} else {
//		p.stats.RxPackets = uint64(stat.PacketsReceived)
		p.stats.RxDropped = uint64(stat.PacketsDropped)+uint64(stat.PacketsIfDropped)
	}
	return p.stats
}

func NewPcapPort(name string) (*PcapPort,error) {
	handle, err := pcap.OpenLive(name, 16000, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	fsource := make(chan []byte)
	fout := make(chan []byte, 8)
	port := &PcapPort{
		Name: name,
		handle: handle,
		source: fsource,
		egress: fout,
	}
	go func(){
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.DecodeOptions = gopacket.DecodeOptions{Lazy:true,NoCopy:true}
		for p := range packetSource.Packets() {
			b := p.Data()
			port.stats.RxBytes += uint64(len(b))
			port.stats.RxPackets++
			fsource <- b
		}
	}()
	go func(){
		for b := range fout {
			if err := handle.WritePacketData(b); err != nil {
				panic(err)
			}
			port.stats.TxBytes += uint64(len(b))
			port.stats.TxPackets++
		}
	}()
	return port, nil
}
