package gopenflow

type Datapath interface {
	GetPort(uint32) Port
	SetPort(uint32, Port) error
}

type Frame struct {
	Data []byte
	Oob  []FrameOob // out-of-band
}

type FrameOob interface{}

type OxmBasic struct {
	Field uint8
	Value interface{}
	Mask  interface{}
}

type OxmExperimenter struct {
	Experimenter uint32
	Field        uint8
	Type         uint16
	Value        interface{}
	Mask         interface{}
}

type Port interface {
	Name() string
	HwAddr() [6]byte
	PhysicalPort() uint32
	Monitor() <-chan []PortMod
	Ingress() <-chan Frame
	Egress(Frame) error

	Config() uint32
	State() uint32
	Mtu() uint32
	Ethernet() (PortEthernetProperty, error)

	Vendor(interface{}) interface{}
}

type PortMod interface{}

type PortModPortDown bool

type PortEthernetProperty struct {
	Curr       uint32
	Advertised uint32
	Supported  uint32
	Peer       uint32
	CurrSpeed  uint32 // kbps
	MaxSpeed   uint32 // kbps
}
