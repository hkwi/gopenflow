package ofp4sw

type PortState struct {
	Name       string
	LinkDown   bool
	Blocked    bool
	Live       bool
	Advertised uint32
	Supported  uint32
	Peer       uint32
	Curr       uint32
	HwAddr     [6]byte
	Mtu        uint32
	CurrSpeed  uint32 // kbps
	MaxSpeed   uint32 // kbps
}

type Port interface {
	Name() string
	PhysicalPort() uint32

	Watch() <-chan *PortState
	Ingress() <-chan Frame
	Egress(Frame) error
}
