/*
Package ofp4sw implements openflow 1.3 switch.
*/
package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
	"sync"
	"time"
)

type Pipeline struct {
	lock     *sync.Mutex
	commands chan func() // obsolete
	flows    map[uint8]*flowTable
	ports    map[uint32]portInternal
	groups   map[uint32]*group
	meters   map[uint32]*meter

	DatapathId uint64
	flags      uint16 // ofp_config_flags, check capability
}

func NewPipeline() *Pipeline {
	pipe := Pipeline{
		lock:     &sync.Mutex{},
		commands: make(chan func(), 16),
		flows:    make(map[uint8]*flowTable),
		ports:    make(map[uint32]portInternal),
		groups:   make(map[uint32]*group),
		meters:   make(map[uint32]*meter),
	}
	pipe.ports[ofp4.OFPP_CONTROLLER] = newController()
	return &pipe
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

type PortState struct {
	LinkDown   bool
	Blocked    bool
	Live       bool
	Advertised uint32
	Supported  uint32
	Peer       uint32
	Curr       uint32
	HwAddr     [6]byte
}

type Port interface {
	Name() string
	GetPhysicalPort() uint32
	Ingress() <-chan []byte
	Egress() chan<- []byte
	State() *PortState
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

type portInternal interface {
	Outlet() chan<- packetOut
	Stats() *PortStats
	State() *PortState
	GetConfig() uint32
	SetConfig(uint32) error
}

type normalPort struct {
	public  Port
	outlet  chan packetOut
	stats   PortStats
	config  uint32
	created time.Time
}

func (self normalPort) Outlet() chan<- packetOut {
	return self.outlet
}

func (self normalPort) Stats() *PortStats {
	return &self.stats
}

func (self normalPort) GetConfig() uint32 {
	return self.config
}

func (self normalPort) SetConfig(config uint32) error {
	self.config = config
	return nil
}

func (self normalPort) State() *PortState {
	var info PortState
	info = *self.public.State()

	if self.config&ofp4.OFPPC_PORT_DOWN != 0 || info.LinkDown {
		info.Live = false
	}
	return &info
}

func (self normalPort) start(pipe Pipeline, portNo uint32) {
	// EGRESS
	go func() {
		// XXX: need to implement queue here
		for pout := range self.outlet {
			if pout.data == nil {
				log.Println("packet serialization error")
				continue
			}
			if self.config&(ofp4.OFPPC_PORT_DOWN|ofp4.OFPPC_NO_FWD) != 0 {
				self.stats.TxDropped++
				continue
			}
			select {
			case self.public.Egress() <- pout.data:
				self.stats.TxPackets++
				self.stats.TxBytes += uint64(len(pout.data))
			default:
				self.stats.TxDropped++
			}
		}
	}()

	// INGRESS
	serialOuts := make(chan chan []packetOut, 8) // parallel pipeline processing
	go func() {
		for eth := range self.public.Ingress() {
			eth := eth
			serialOut := make(chan []packetOut, 1)
			serialOuts <- serialOut
			go func() {
				serialOut <- func() []packetOut {
					if self.config&(ofp4.OFPPC_PORT_DOWN|ofp4.OFPPC_NO_RECV) != 0 {
						return nil
					}
					f := frame{
						inPort:     portNo,
						phyInPort:  self.public.GetPhysicalPort(),
						serialized: eth,
						length:     len(eth),
						layers:     gopacket.NewPacket(eth, layers.LayerTypeEthernet, gopacket.NoCopy).Layers(),
					}
					pouts := f.process(pipe)
					if self.config&(ofp4.OFPPC_NO_PACKET_IN) != 0 {
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
				close(serialOut)
			}()
		}
		close(serialOuts)
	}()
	go func() {
		for serialOut := range serialOuts {
			for pouts := range serialOut {
				for _, pout := range pouts {
					ports := func() []portInternal {
						pipe.lock.Lock()
						defer pipe.lock.Unlock()

						var ports []portInternal
						if pout.outPort != ofp4.OFPP_ALL {
							if outInt, ok := pipe.ports[pout.outPort]; ok {
								ports = append(ports, outInt)
							}
						} else {
							for outPortNo, outInt := range pipe.ports {
								if outPortNo <= ofp4.OFPP_MAX && portNo != outPortNo {
									ports = append(ports, outInt)
								}
							}
						}
						return ports
					}()
					for _, outInt := range ports {
						outInt.Outlet() <- pout
					}
				}
			}
		}
	}()
}

// AddPort adds a normal openflow port into the pipeline.
func (pipe Pipeline) AddPort(port Port, portNo uint32) error {
	portInt := &normalPort{
		public:  port,
		outlet:  make(chan packetOut),
		created: time.Now(),
	}
	if err := func() error {
		pipe.lock.Lock()
		defer pipe.lock.Unlock()

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
		pipe.ports[portNo] = portInt
		return nil
	}(); err != nil {
		return err
	}
	portInt.start(pipe, portNo)
	// XXX: trigger ofp_port_status
	return nil
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
		return errors.New("OFPP_CONTROLLER not registered")
	}
}

func (pipe Pipeline) getFlowTables(tableId uint8) map[uint8]*flowTable {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	buf := make(map[uint8]*flowTable)
	if tableId == ofp4.OFPTT_ALL {
		for k, v := range pipe.flows {
			buf[k] = v
		}
	} else {
		if table, ok := pipe.flows[tableId]; ok {
			buf[tableId] = table
		}
	}
	return buf
}

func (pipe Pipeline) getGroups(groupId uint32) map[uint32]*group {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	groups := make(map[uint32]*group)
	if groupId == ofp4.OFPG_ALL {
		for k, g := range pipe.groups {
			groups[k] = g
		}
	} else {
		if group, ok := pipe.groups[groupId]; ok {
			groups[groupId] = group
		}
	}
	return groups
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
		if port.State().Live {
			return true
		}
	}
	return false
}

func (pipe Pipeline) getMeters(meterId uint32) map[uint32]*meter {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	meters := make(map[uint32]*meter)
	if meterId == ofp4.OFPM_ALL {
		for k, m := range pipe.meters {
			meters[k] = m
		}
	} else {
		if meter, ok := pipe.meters[meterId]; ok {
			meters[meterId] = meter
		}
	}
	return meters
}

func (pipe Pipeline) getPorts(portNo uint32) map[uint32]portInternal {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	ports := make(map[uint32]portInternal)
	if portNo == ofp4.OFPP_ANY || portNo == ofp4.OFPP_ALL {
		for k, g := range pipe.ports {
			ports[k] = g
		}
	} else {
		if port, ok := pipe.ports[portNo]; ok {
			ports[portNo] = port
		}
	}
	return ports
}

func (pipe Pipeline) getPortPhysicalPort(portNo uint32) uint32 {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	if portInt, ok := pipe.ports[portNo]; ok {
		if port, ok := portInt.(*normalPort); ok {
			return port.public.GetPhysicalPort()
		}
	}
	return 0
}
