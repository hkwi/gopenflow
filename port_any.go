// +build linux,!cgo

package gopenflow

func (self NamedPort) Ethernet() (PortEthernetProperty, error) {
	return PortEthernetProperty{}, nil
}
