package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"encoding/binary"
	"errors"
	"net"
)

func init() {
	layers.MPLSPayloadDecoder = gopacket.DecodeFunc(decodeMPLS)
	layers.EthernetTypeMetadata[ethernetTypeDot1QSTag] = layers.EthernetTypeMetadata[layers.EthernetTypeDot1Q]
	layers.EthernetTypeMetadata[ethernetTypeDot1QITag] = layers.EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodePBB),
		Name:       "PBB",
		LayerType:  layerTypePBB,
	}
}

var (
	layerTypePBB = gopacket.RegisterLayerType(500, gopacket.LayerTypeMetadata{"PBB", gopacket.DecodeFunc(decodePBB)})
)

func decodeMPLS(data []byte, p gopacket.PacketBuilder) error {
	g := layers.ProtocolGuessingDecoder{}
	if err := g.Decode(data, p); err != nil {
		return gopacket.DecodePayload.Decode(data, p)
	}
	return nil
}

const (
	// 802.1QSTagType
	ethernetTypeDot1QSTag layers.EthernetType = 0x88a8
	// 802.1QITagType
	ethernetTypeDot1QITag layers.EthernetType = 0x88e7
)

type PBB struct {
	layers.BaseLayer
	Priority           uint8
	DropEligible       bool
	UseCustomerAddress bool
	ServiceIdentifier  uint32
	DstMAC             net.HardwareAddr
	SrcMAC             net.HardwareAddr
	Type               layers.EthernetType
}

func (p PBB) LayerType() gopacket.LayerType     { return layerTypePBB }
func (p PBB) CanDecode() gopacket.LayerClass    { return layerTypePBB }
func (p PBB) NextLayerType() gopacket.LayerType { return p.Type.LayerType() }
func (p PBB) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if bytes, err := b.PrependBytes(18); err != nil {
		return err
	} else {
		binary.BigEndian.PutUint32(bytes[0:4], p.ServiceIdentifier)
		firstByte := p.Priority << 5
		if p.DropEligible {
			firstByte |= 0x10
		}
		if p.UseCustomerAddress {
			firstByte |= 0x08
		}
		bytes[0] = firstByte

		for i, v := range []byte(p.DstMAC) {
			bytes[4+i] = v
		}
		for i, v := range []byte(p.SrcMAC) {
			bytes[10+i] = v
		}
		binary.BigEndian.PutUint16(bytes[16:18], uint16(p.Type))
	}
	return nil
}

func decodePBB(data []byte, p gopacket.PacketBuilder) error {
	if data[0]&0x3 != 0 {
		return errors.New("I-TAG TCI Res2 must be zero")
	}
	pbb := &PBB{
		Priority:           data[0] >> 5,
		DropEligible:       data[0]&0x10 != 0,
		UseCustomerAddress: data[0]&0x08 != 0,
		ServiceIdentifier:  binary.BigEndian.Uint32(append(make([]byte, 1), data[1:4]...)),
		DstMAC:             net.HardwareAddr(data[4:10]),
		SrcMAC:             net.HardwareAddr(data[10:16]),
		Type:               layers.EthernetType(binary.BigEndian.Uint16(data[16:18])),
		BaseLayer:          layers.BaseLayer{Contents: data[:18], Payload: data[18:]},
	}
	p.AddLayer(pbb)
	return p.NextDecoder(pbb.Type)
}
