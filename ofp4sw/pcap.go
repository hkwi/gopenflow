package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/hkwi/gopenflow/pcap"
	"log"
)

type PcapPort struct {
	// ofp_port
	portNo       uint32
	hwAddr       [ofp4.OFP_ETH_ALEN]byte
	name         string
	PhysicalPort uint32
	handle       *pcap.Handle
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

func NewPcapPort(name string) (*PcapPort, error) {
	handle, err := pcap.Open(name, []interface{}{pcap.TimeoutOption(8)})
	if err != nil {
		return nil, err
	}
	port := &PcapPort{
		name:   name,
		handle: handle,
	}
	return port, nil
}

func (self PcapPort) Get(pkt []byte) ([]byte, error) {
	for {
		if data,err:=self.handle.Get(pkt, 8); err!=nil {
			switch e:=err.(type) {
			case pcap.Timeout:
				// continue
			default:
				return nil,e
			}
		} else {
			return data, nil
		}
	}
}

func (self PcapPort) Put(pkt []byte) error {
	return self.handle.Put(pkt)
}
