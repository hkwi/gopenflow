/*
Package ofp4sw implements openflow 1.3 switch.
*/
package ofp4sw

import (
	"errors"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
	"sync"
	"time"
)

type Pipeline struct {
	lock *sync.RWMutex
	// special rule for flows: value nil means that the table is forbidden by table feature spec.
	flows    map[uint8]*flowTable
	ports    map[uint32]portInternal
	groups   map[uint32]*group
	meters   map[uint32]*meter
	datapath chan MapReducable

	DatapathId uint64
	Desc       ofp4.Desc
	flags      uint16 // ofp_config_flags, check capability
}

func NewPipeline() *Pipeline {
	self := &Pipeline{
		lock:     &sync.RWMutex{},
		flows:    make(map[uint8]*flowTable),
		ports:    make(map[uint32]portInternal),
		groups:   make(map[uint32]*group),
		meters:   make(map[uint32]*meter),
		datapath: make(chan MapReducable),
	}
	controller := newController(self)
	self.ports[ofp4.OFPP_CONTROLLER] = controller
	go func() {
		for {
			time.Sleep(time.Second)
			self.validate(time.Now())
		}
	}()
	go MapReduce(self.datapath, 4) // XXX: NUM_CPUS
	return self
}

func (pipe Pipeline) AddPort(port Port, portNo uint32) error {
	portInt := &normalPort{
		close:   make(chan error),
		public:  port,
		created: time.Now(),
		reason:  ofp4.OFPPR_ADD,
	}

	if err := func() error {
		pipe.lock.Lock()
		defer pipe.lock.Unlock()

		if portNo == ofp4.OFPP_ANY || portNo == 0 {
			portNo = 1
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
		} else {
			if _, exists := pipe.ports[portNo]; exists {
				return errors.New("portNo already used")
			}
		}
		pipe.ports[portNo] = portInt
		return nil
	}(); err != nil {
		return err
	}

	// port lifecyele
	go func() {
		defer func() {
			pipe.lock.Lock()
			defer pipe.lock.Unlock()
			delete(pipe.ports, portNo)
		}()

		ctrl := pipe.getController()
		phyInPort := port.PhysicalPort()
		for {
			select {
			case _ = <-portInt.close:
				portInt.reason = ofp4.OFPRR_DELETE
				ctrl.portChange(portNo, portInt)
				return
			case pkt := <-port.Ingress():
				if portInt.config&(ofp4.OFPPC_PORT_DOWN|ofp4.OFPPC_NO_RECV) != 0 {
					continue
				}

				portInt.stats.RxPackets++
				portInt.stats.RxBytes += uint64(len(pkt.Data))

				data := &frame{
					inPort:    portNo,
					phyInPort: phyInPort,
				}
				pkt.push(data)

				pipe.datapath <- &flowTableWork{
					data:    data,
					pipe:    &pipe,
					tableId: 0,
				}
			case state := <-port.Watch():
				if state != nil && portInt.state != *state {
					portInt.state = *state
					ctrl.portChange(portNo, portInt)
					portInt.reason = ofp4.OFPPR_MODIFY
				}
			}
		}
	}()
	return nil
}

func (self *Pipeline) AddControl(channel ControlChannel) error {
	// XXX: extend for aux channel
	return self.getController().addChannel(channel)
}

func (self *Pipeline) RemoveControl(channel ControlChannel) error {
	return self.getController().removeChannel(channel)
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
	Outlet(*outputToPort)
	Stats() *PortStats
	State() *PortState
	GetConfig() uint32
	SetConfig(uint32)
}

type normalPort struct {
	close   chan error
	public  Port
	stats   PortStats
	config  uint32
	created time.Time
	state   PortState // copy of current state
	reason  uint8
}

func (self *normalPort) Outlet(pout *outputToPort) {
	if self.config&(ofp4.OFPPC_PORT_DOWN|ofp4.OFPPC_NO_FWD) != 0 {
		self.stats.TxDropped++
		return
	}
	var pkt Frame
	if err := pkt.pull(*pout.data); err != nil {
		log.Print(err)
		return
	}
	if err := self.public.Egress(pkt); err != nil {
		self.stats.TxDropped++
		log.Print(err)
	} else {
		self.stats.TxPackets++
		self.stats.TxBytes += uint64(len(pkt.Data))
	}
}

func (self normalPort) Stats() *PortStats {
	return &self.stats
}

func (self normalPort) GetConfig() uint32 {
	return self.config
}

// we must trigger portChange() outside of SetConfig()
func (self *normalPort) SetConfig(config uint32) {
	self.config = config
}

func (self normalPort) State() *PortState {
	return &self.state
}

func (pipe Pipeline) getController() *controller {
	if port, ok := pipe.ports[ofp4.OFPP_CONTROLLER]; ok {
		if control, ok := port.(*controller); ok {
			return control
		}
	}
	return nil
}

func (pipe Pipeline) getFlowTable(tableId uint8) *flowTable {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()
	return pipe.flows[tableId]
}

func (pipe Pipeline) getFlowTables(tableId uint8) map[uint8]*flowTable {
	var buf map[uint8]*flowTable
	if tableId == ofp4.OFPTT_ALL {
		buf = make(map[uint8]*flowTable, len(pipe.flows))
	} else {
		buf = make(map[uint8]*flowTable, 1)
	}

	pipe.lock.Lock()
	defer pipe.lock.Unlock()

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

func (pipe Pipeline) getGroup(groupId uint32) *group {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()
	return pipe.groups[groupId]
}

func (pipe Pipeline) getGroups(groupId uint32) map[uint32]*group {
	groups := make(map[uint32]*group)

	pipe.lock.Lock()
	defer pipe.lock.Unlock()

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

func (pipe Pipeline) getMeter(meterId uint32) *meter {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()
	return pipe.meters[meterId]
}

func (pipe Pipeline) getMeters(meterId uint32) map[uint32]*meter {
	meters := make(map[uint32]*meter)

	pipe.lock.Lock()
	defer pipe.lock.Unlock()

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

func (pipe Pipeline) getPort(portNo uint32) portInternal {
	pipe.lock.Lock()
	defer pipe.lock.Unlock()
	return pipe.ports[portNo]
}

func (pipe Pipeline) getPorts(portNo uint32) map[uint32]portInternal {
	ports := make(map[uint32]portInternal)

	pipe.lock.Lock()
	defer pipe.lock.Unlock()

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
			return port.public.PhysicalPort()
		}
	}
	return 0
}
