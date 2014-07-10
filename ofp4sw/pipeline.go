package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
	"time"
)

type Pipeline struct {
	commands chan func()
	flows    map[uint8]*flowTable
	ports    map[uint32]portInternal
	groups   map[uint32]*group
	meters   map[uint32]*meter

	datapathId uint64
	flags      uint16 // ofp_config_flags, check capability
}

func NewPipeline() *Pipeline {
	pipe := Pipeline{
		commands:   make(chan func(), 16),
		flows:      make(map[uint8]*flowTable),
		ports:      make(map[uint32]portInternal),
		groups:     make(map[uint32]*group),
		meters:     make(map[uint32]*meter),
		datapathId: 1,
	}
	pipe.ports[ofp4.OFPP_CONTROLLER] = newController()
	go func() {
		for cmd := range pipe.commands {
			if cmd != nil {
				cmd()
			} else {
				break
			}
		}
	}()
	return &pipe
}

type portInternal interface {
	Egress() chan<- packetOut
}

type Port interface {
	GetPhysicalPort() uint32
	Ingress() <-chan []byte
	Egress() chan<- []byte
	GetName() string
	GetDesc() string
	GetStats() PortStats
}

type PortStats struct {
	RxPackets  uint64
	TxPackets  uint64
	RxBytes    uint64
	TxBytes    uint64
	RxDropped  uint64
	TxDropped  uint64
	RxErrors   uint64
	TxErrors   uint64
	RxFrameErr uint64
	RxOverErr  uint64
	RxCrcErr   uint64
	Collisions uint64
}

type portHelper struct {
	public  Port
	egress  chan packetOut
	created time.Time
}

type packetOut struct {
	outPort uint32
	queueId uint32
	maxLen  uint16
	tableId uint8
	cookie  uint64
	fields  []match
	reason  uint8
	data    []byte
}

type groupOut struct {
	groupId uint32
	data    frame
}

func (p Pipeline) GetDatapathId() uint64 {
	return p.datapathId
}

func (pipe Pipeline) AddPort(port Port) error {
	ch := make(chan error)
	pipe.commands <- func() {
		ch <- func() error {
			portInt := portHelper{
				public:  port,
				egress:  make(chan packetOut),
				created: time.Now(),
			}
			portNo := uint32(1)
			for existingPortNo, _ := range pipe.ports {
				if existingPortNo > ofp4.OFPP_MAX {
					continue // skip special ports
				}
				if existingPortNo >= portNo {
					portNo = existingPortNo + 1
				}
				if portNo > ofp4.OFPP_MAX {
					return errors.New("No room for port id")
				}
			}
			pipe.ports[portNo] = portInt

			results := make(chan chan []packetOut)
			go func() {
				for eth := range port.Ingress() {
					eth2 := eth
					ch2 := make(chan []packetOut)
					go func() {
						f := frame{
							inPort:    portNo,
							phyInPort: port.GetPhysicalPort(),
							layers:    gopacket.NewPacket(eth2, layers.LayerTypeEthernet, gopacket.NoCopy).Layers(),
						}
						outs := f.process(pipe)
						ch2 <- outs
						close(ch2)
					}()
					results <- ch2
				}
				close(results)
			}()
			go func() {
				for result := range results {
					pouts := <-result
					for _, pout := range pouts {
						ch2 := make(chan portInternal)
						pipe.commands <- func() {
							if pi, ok := pipe.ports[pout.outPort]; ok {
								ch2 <- pi
							} else {
								ch2 <- nil
							}
							close(ch2)
						}
						if pi := <-ch2; pi != nil {
							pi.Egress() <- pout
						}
					}
				}
			}()
			go func() {
				// XXX: need to implement queue here
				for pout := range portInt.egress {
					port.Egress() <- pout.data
				}
			}()
			return nil
		}()
		close(ch)
	}
	return <-ch
}

func (p Pipeline) AddControlChannel(channel ControlChannel) error {
	ret := make(chan portInternal)
	p.commands <- func() {
		ret <- func() portInternal {
			if port, ok := p.ports[ofp4.OFPP_CONTROLLER]; ok {
				return port
			}
			return nil
		}()
		close(ret)
	}
	port := <-ret
	if port != nil {
		if control, ok := port.(controller); ok {
			return control.addControlChannel(channel, p)
		} else {
			return errors.New("controller cast error")
		}
	} else {
		return errors.New("controller port not registered")
	}
}

func (pipe Pipeline) getFlowTables(tableId uint8) []*flowTable {
	ch := make(chan []*flowTable)
	pipe.commands <- func() {
		ch <- func() []*flowTable {
			var buf []*flowTable
			for k, v := range pipe.flows {
				if tableId == ofp4.OFPTT_ALL || tableId == k {
					buf = append(buf, v)
				}
			}
			return buf
		}()
		close(ch)
	}
	return <-ch
}

func (p Pipeline) getGroups(groupId uint32) []group {
	ret := make(chan []group)
	p.commands <- func() {
		ret <- func() []group {
			var groups []group
			for k, g := range p.groups {
				if groupId == ofp4.OFPG_ALL || groupId == k {
					groups = append(groups, *g)
				}
			}
			return groups
		}()
		close(ret)
	}
	return <-ret
}

func (p Pipeline) getMeters(meterId uint32) map[uint32]*meter {
	ret := make(chan map[uint32]*meter)
	p.commands <- func() {
		ret <- func() map[uint32]*meter {
			meters := make(map[uint32]*meter)
			for k, m := range p.meters {
				if meterId == ofp4.OFPM_ALL || meterId == k {
					meters[k] = m
				}
			}
			return meters
		}()
		close(ret)
	}
	return <-ret
}

func (p Pipeline) getPorts(portNo uint32) map[uint32]portInternal {
	ret := make(chan map[uint32]portInternal)
	p.commands <- func() {
		ret <- func() map[uint32]portInternal {
			ports := make(map[uint32]portInternal)
			for k, g := range p.ports {
				if portNo == ofp4.OFPP_ANY || portNo == k {
					ports[k] = g
				}
			}
			return ports
		}()
		close(ret)
	}
	return <-ret
}

func (p portHelper) Egress() chan<- packetOut { return (chan<- packetOut)(p.egress) }
