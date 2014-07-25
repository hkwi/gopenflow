package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
)

type PcapPort struct {
	// ofp_port
	portNo       uint32
	hwAddr       [ofp4.OFP_ETH_ALEN]byte
	name         string
	PhysicalPort uint32
	handle       *pcap.Handle
	source       <-chan []byte
	egress       chan<- []byte
}

func (p PcapPort) Name() string {
	return p.name
}

func (p PcapPort) State() *PortState {
	if state, err := pcapPortState(p.name); err != nil {
		log.Println(err)
		return nil
	} else {
		return state
	}
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

func NewPcapPort(name string) (*PcapPort, error) {
	handle, err := pcap.OpenLive(name, 16000, false, -1)
	if err != nil {
		return nil, err
	}
	fsource := make(chan []byte)
	fout := make(chan []byte, 16)
	port := &PcapPort{
		name:   name,
		handle: handle,
		source: (<-chan []byte)(fsource),
		egress: (chan<- []byte)(fout),
	}
	go func() {
		fsource := (chan<- []byte)(fsource)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.DecodeOptions = gopacket.NoCopy
		for {
			if packet, err := packetSource.NextPacket(); err != nil {
				log.Println("next packet", err)
				break
			} else {
				fsource <- packet.Data()
			}
		}
		handle.Close()
	}()
	go func() {
		fout := (<-chan []byte)(fout)
		for b := range fout {
			if err := handle.WritePacketData(b); err != nil {
				log.Print(err)
				break
			}
		}
		handle.Close()
	}()
	return port, nil
}
