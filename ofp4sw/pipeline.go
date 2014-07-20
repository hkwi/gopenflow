/*
Package ofp4sw implements openflow 1.3 switch.
*/
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

	DatapathId uint64
	flags      uint16 // ofp_config_flags, check capability
}

func NewPipeline() *Pipeline {
	pipe := Pipeline{
		commands: make(chan func(), 16),
		flows:    make(map[uint8]*flowTable),
		ports:    make(map[uint32]portInternal),
		groups:   make(map[uint32]*group),
		meters:   make(map[uint32]*meter),
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
	Live() bool
	Egress() chan<- packetOut
}

type Port interface {
	GetPhysicalPort() uint32
	GetPort() ofp4.Port
	GetStats() PortStats
	Ingress() <-chan []byte
	Egress() chan<- []byte
	SetPortNo(portNo uint32)
	SetConfig(config uint32)
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
	data    []byte
	// below for OFPT_PACKET_IN
	maxLen uint16
	match  *matchResult
	// below for OFPP_TABLE
	inPort uint32
}

type groupOut struct {
	groupId uint32
	data    frame
}

func (pipe Pipeline) AddPort(port Port, portNo uint32) error {
	ch := make(chan error)
	pipe.commands <- func() {
		ch <- func() error {
			portInt := portHelper{
				public:  port,
				egress:  make(chan packetOut),
				created: time.Now(),
			}
			if portNo != ofp4.OFPP_ANY {
				if _, exists := pipe.ports[portNo]; exists {
					return errors.New("portNo already used")
				}
			} else {
				portNo = uint32(1)
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
			}
			pipe.ports[portNo] = &portInt
			port.SetPortNo(portNo)

			serialOuts := make(chan chan []packetOut, 8)
			go func() {
				for eth := range port.Ingress() {
					eth := eth
					ch2 := make(chan []packetOut, 1)
					serialOuts <- ch2
					go func() {
						ch2 <- func() []packetOut {
							config := port.GetPort().Config
							if config&(ofp4.OFPPC_PORT_DOWN|ofp4.OFPPC_NO_RECV) != 0 {
								return nil
							}
							f := frame{
								inPort:    portNo,
								phyInPort: port.GetPhysicalPort(),
								layers:    gopacket.NewPacket(eth, layers.LayerTypeEthernet, gopacket.NoCopy).Layers(),
							}
							pouts := f.process(pipe)
							if config&(ofp4.OFPPC_NO_PACKET_IN) != 0 {
								var newPouts []packetOut
								for _, pout := range pouts {
									if pout.outPort != ofp4.OFPP_CONTROLLER {
										newPouts = append(newPouts, pout)
									}
								}
								pouts = newPouts
							}
							return pouts
						}()
						close(ch2)
					}()
				}
				close(serialOuts)
			}()
			go func() {
				for result := range serialOuts {
					pouts := <-result
					for _, pout := range pouts {
						pout := pout
						ch2 := make(chan portInternal)
						go func() {
							for pi := range ch2 {
								pi.Egress() <- pout
							}
						}()
						pipe.commands <- func() {
							for outPortNo, outPort := range pipe.ports {
								if pout.outPort == ofp4.OFPP_ALL && outPortNo <= ofp4.OFPP_MAX {
									if portNo != outPortNo {
										ch2 <- outPort
									}
								} else if pout.outPort == outPortNo {
									ch2 <- outPort
								}
							}
							close(ch2)
						}
					}
				}
			}()
			go func() {
				// XXX: need to implement queue here
				for pout := range portInt.egress {
					config := port.GetPort().Config
					if config&(ofp4.OFPPC_PORT_DOWN|ofp4.OFPPC_NO_FWD) != 0 {
						continue
					}
					port.Egress() <- pout.data
				}
			}()
			return nil
		}()
		close(ch)
	}
	return <-ch
}

func (pipe Pipeline) getController() *controller {
	if port, ok := pipe.ports[ofp4.OFPP_CONTROLLER]; ok {
		if control, ok := port.(*controller); ok {
			return control
		}
	}
	return nil
}

func (pipe Pipeline) AddControlChannel(channel ControlChannel) error {
	if ctrl := pipe.getController(); ctrl != nil {
		return ctrl.addControlChannel(channel, pipe)
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

func (p Pipeline) getGroups(groupId uint32) map[uint32]*group {
	ret := make(chan map[uint32]*group)
	p.commands <- func() {
		ret <- func() map[uint32]*group {
			groups := make(map[uint32]*group)
			for k, g := range p.groups {
				if groupId == ofp4.OFPG_ALL || groupId == k {
					groups[k] = g
				}
			}
			return groups
		}()
		close(ret)
	}
	return <-ret
}

// Call this function inside a pipeline transaction
func (p Pipeline) watchGroup(groupId uint32) bool {
	if group, ok := p.groups[groupId]; ok {
		for _, b := range group.buckets {
			if b.watchPort != ofp4.OFPP_ANY {
				if p.watchPort(b.watchPort) {
					return true
				}
			}
			if b.watchGroup != ofp4.OFPG_ANY {
				if p.watchGroup(b.watchGroup) {
					return true
				}
			}
		}
	}
	return false
}

// Call this function inside a pipeline transaction
func (p Pipeline) watchPort(portNo uint32) bool {
	if port, ok := p.ports[portNo]; ok {
		if port.Live() {
			return true
		}
	}
	return false
}

func (p Pipeline) getTables(tableId uint8) map[uint8]*flowTable {
	ret := make(chan map[uint8]*flowTable)
	p.commands <- func() {
		ret <- func() map[uint8]*flowTable {
			tables := make(map[uint8]*flowTable)
			for k, t := range p.flows {
				if tableId == ofp4.OFPTT_ALL || tableId == k {
					tables[k] = t
				}
			}
			return tables
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

func (pipe Pipeline) getPorts(portNo uint32) map[uint32]portInternal {
	ret := make(chan map[uint32]portInternal)
	pipe.commands <- func() {
		ret <- func() map[uint32]portInternal {
			ports := make(map[uint32]portInternal)
			for k, g := range pipe.ports {
				if portNo == ofp4.OFPP_ANY || portNo == ofp4.OFPP_ALL || portNo == k {
					ports[k] = g
				}
			}
			return ports
		}()
		close(ret)
	}
	return <-ret
}

func (pipe Pipeline) getPortPhysicalPort(portNo uint32) uint32 {
	ch := make(chan Port)
	pipe.commands <- func() {
		ch <- func() Port {
			if inPort, ok := pipe.ports[portNo]; ok {
				if ph, ok := inPort.(*portHelper); ok {
					return ph.public
				}
			}
			return nil
		}()
	}
	port := <-ch
	if port != nil {
		return port.GetPhysicalPort()
	}
	return 0
}

func (p portHelper) Egress() chan<- packetOut {
	return (chan<- packetOut)(p.egress)
}

func (p portHelper) Live() bool {
	info := p.public.GetPort()
	if info.Config&ofp4.OFPPC_PORT_DOWN != 0 {
		return false
	}
	if info.State&ofp4.OFPPS_LINK_DOWN != 0 {
		return false
	}
	if info.State&(ofp4.OFPPS_LIVE) != 0 {
		return true
	}
	return false
}
