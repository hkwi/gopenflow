package gopenflow

import (
	"io"
)

type Datapath interface {
	AddPort(Port) error
	AddChannel(conn io.ReadWriteCloser) error
}

type Frame struct {
	Data []byte
	Oob  []byte // out-of-band oxm
}

type Port interface {
	Name() string
	HwAddr() [6]byte
	PhysicalPort() uint32
	Monitor() <-chan bool // By passing false, datapath will remove this port.
	Ingress() <-chan Frame
	Egress(Frame) error

	GetConfig() []PortConfig
	SetConfig([]PortConfig)
	State() []PortState
	Mtu() uint32
	Ethernet() (PortEthernetProperty, error)
	Stats() (PortStats, error)

	Vendor(interface{}) interface{}
}

type PortConfig interface{}

type PortConfigPortDown bool

type PortConfigNoRecv bool

type PortConfigNoFwd bool

type PortConfigNoPacketIn bool

type PortState interface{}

type PortStateLinkDown bool

type PortStateBlocked bool

type PortStateLive bool

type PortEthernetProperty struct {
	Curr       uint32
	Advertised uint32
	Supported  uint32
	Peer       uint32
	CurrSpeed  uint32 // kbps
	MaxSpeed   uint32 // kbps
}

type PortStats struct {
	RxPackets uint64
	TxPackets uint64
	RxBytes   uint64
	TxBytes   uint64
	RxDropped uint64
	TxDropped uint64
	RxErrors  uint64
	TxErrors  uint64
	Ethernet  *PortStatsEthernet
	Optical   *PortStatsOptical
}

type PortStatsEthernet struct {
	RxFrameErr uint64
	RxOverErr  uint64
	RxCrcErr   uint64
	Collisions uint64
}

// PortStatsOptical fields are not defined yet
type PortStatsOptical struct{}
