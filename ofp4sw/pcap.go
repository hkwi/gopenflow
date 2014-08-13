package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/hkwi/gopenflow/pcap"
	"sync"
	"syscall"
)

type PcapPort struct {
	lock         *sync.Mutex
	hwAddr       [ofp4.OFP_ETH_ALEN]byte
	name         string
	PhysicalPort uint32
	handle       *pcap.Handle
	netdevWatch  chan NetdevUpdate
	listeners    []PortStateListener
}

func (p PcapPort) Name() string {
	return p.name
}

func (self PcapPort) State() *PortState {
	if evs, err := IfplugdGet(); err == nil {
		for _, ev := range evs {
			if self.name == ev.Name {
				state := &PortState{
					Name:     self.name,
					LinkDown: !ev.LowerUp,
					Blocked:  !ev.Up,
					Live:     ev.Running,
					Mtu:      ev.Mtu,
				}
				if ev.Type != syscall.RTM_NEWLINK {
					return nil
				}
				if pcapPortState(self.name, state) != nil {
					return nil
				}
				return state
			}
		}
	}
	return nil
}

func (p PcapPort) GetPhysicalPort() uint32 {
	return p.PhysicalPort
}

func NewPcapPort(name string) (*PcapPort, error) {
	handle, err := pcap.Open(name, []interface{}{pcap.TimeoutOption(8)})
	if err != nil {
		return nil, err
	}
	self := &PcapPort{
		lock:        &sync.Mutex{},
		name:        name,
		handle:      handle,
		netdevWatch: make(chan NetdevUpdate),
	}
	return self, nil
}

func (self PcapPort) Get(pkt []byte) ([]byte, error) {
	for {
		if data, err := self.handle.Get(pkt, 8); err != nil {
			switch e := err.(type) {
			case pcap.Timeout:
				// continue
			default:
				return nil, e
			}
		} else {
			return data, nil
		}
	}
}

func (self PcapPort) Put(pkt []byte) error {
	return self.handle.Put(pkt)
}

func (self *PcapPort) AddStateListener(listener PortStateListener) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	trigger_start := len(self.listeners) == 0
	self.listeners = append(self.listeners, listener)
	if trigger_start {
		if err := IfplugdAddListener(self.netdevWatch); err != nil {
			self.listeners = nil
			return err
		}
		go func() {
			for ev := range self.netdevWatch {
				if len(self.listeners) == 0 {
					break // No listeners
				}
				if ev.Name == self.name {
					state := &PortState{
						Name:     ev.Name,
						LinkDown: !ev.LowerUp,
						Blocked:  !ev.Up,
						Live:     ev.Running,
						Mtu:      ev.Mtu,
					}
					if ev.Type == syscall.RTM_NEWLINK {
						pcapPortState(self.name, state)
					} // otherwise RTM_DELLINK
					if err := func() error {
						self.lock.Lock()
						defer self.lock.Unlock()
						for _, listener := range self.listeners {
							if err := listener.PortChange(state, ofp4.OFPPR_MODIFY); err != nil {
								return err
							}
						}
						return nil
					}(); err != nil {
						break
					}
				}
			}
			return
		}()
		if err := func() error {
			if evs, err := IfplugdGet(); err != nil {
				return err
			} else {
				for _, ev := range evs {
					if ev.Name == self.name {
						state := &PortState{
							Name:     self.name,
							LinkDown: !ev.LowerUp,
							Blocked:  !ev.Up,
							Live:     ev.Running,
							Mtu:      ev.Mtu,
						}
						if ev.Type == syscall.RTM_NEWLINK {
							pcapPortState(self.name, state)
						}
						for _, listener := range self.listeners {
							if err := listener.PortChange(state, ofp4.OFPPR_ADD); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		}(); err != nil {
			self.listeners = nil
			self.RemoveStateListener(listener)
			return err
		}
	}
	return nil
}

func (self *PcapPort) RemoveStateListener(listener PortStateListener) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	var new_listeners []PortStateListener
	for _, l := range self.listeners {
		if l != listener {
			new_listeners = append(new_listeners, l)
		}
	}
	self.listeners = new_listeners
	if len(self.listeners) == 0 {
		IfplugdRemoveListener(self.netdevWatch)
	}
	return nil
}
