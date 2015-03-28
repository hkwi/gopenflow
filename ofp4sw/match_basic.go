package ofp4sw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/ofp4"
	layers2 "github.com/hkwi/suppl/gopacket/layers"
	"net"
)

type oxmBasic struct{}

func (self oxmBasic) Parse(buf []byte) map[OxmKey]OxmPayload {
	ret := make(map[OxmKey]OxmPayload)
	for _, oxm := range ofp4.Oxm(buf).Iter() {
		hdr := oxm.Header()
		length := hdr.Length()
		if hdr.HasMask() {
			length = length / 2
		}
		switch hdr.Class() {
		case ofp4.OFPXMC_OPENFLOW_BASIC:
			ret[OxmKeyBasic(hdr.Type())] = OxmValueMask{
				Value: oxm[4 : 4+length],
				Mask:  oxm[4+length:],
			}
		}
	}
	return ret
}

func (self oxmBasic) OxmId(id uint32) uint32 {
	length, mask := ofp4.OxmOfDefs(id)
	hdr := ofp4.OxmHeader(id)
	hdr.SetMask(mask)
	if mask {
		hdr.SetLength(length * 2)
	} else {
		hdr.SetLength(length)
	}
	return uint32(hdr)
}

func (self oxmBasic) Match(data Frame, key OxmKey, payload OxmPayload) (bool, error) {
	value, err := data.getValue(uint32(key.(OxmKeyBasic)))
	if err != nil {
		return false, err
	}
	vm := payload.(OxmValueMask)
	return bytes.Equal(maskBytes(value, vm.Mask), vm.Value), nil
}

func (self oxmBasic) SetField(data *Frame, key OxmKey, payload OxmPayload) error {
	m := payload.(OxmValueMask)
	switch uint32(key.(OxmKeyBasic)) {
	default:
		return fmt.Errorf("unknown oxm field")
	case ofp4.OXM_OF_IN_PORT:
		data.inPort = binary.BigEndian.Uint32(m.Value)
		return nil
	case ofp4.OXM_OF_IN_PHY_PORT:
		data.inPhyPort = binary.BigEndian.Uint32(m.Value)
		return nil
	case ofp4.OXM_OF_METADATA:
		data.metadata = binary.BigEndian.Uint64(m.Value)
		return nil
	case ofp4.OXM_OF_ETH_DST:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.Ethernet); ok {
				t.DstMAC = net.HardwareAddr(m.Value)
				return nil
			}
		}
	case ofp4.OXM_OF_ETH_SRC:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.Ethernet); ok {
				t.SrcMAC = net.HardwareAddr(m.Value)
				return nil
			}
		}
	case ofp4.OXM_OF_ETH_TYPE:
		var lastLayer gopacket.Layer
		for _, layer := range data.Layers() {
			switch t := layer.(type) {
			case *layers.Ethernet:
				lastLayer = t
			case *layers.Dot1Q:
				lastLayer = t
			}
		}
		if t, ok := lastLayer.(*layers.Ethernet); ok {
			t.EthernetType = layers.EthernetType(binary.BigEndian.Uint16(m.Value))
			return nil
		}
		if t, ok := lastLayer.(*layers.Dot1Q); ok {
			t.Type = layers.EthernetType(binary.BigEndian.Uint16(m.Value))
			return nil
		}
	case ofp4.OXM_OF_VLAN_VID:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.Dot1Q); ok {
				t.VLANIdentifier = binary.BigEndian.Uint16(m.Value) & 0x0fff
				return nil
			}
		}
	case ofp4.OXM_OF_VLAN_PCP:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.Dot1Q); ok {
				t.Priority = m.Value[0]
				return nil
			}
		}
	case ofp4.OXM_OF_IP_DSCP:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				t.TOS = t.TOS&0x03 | m.Value[0]<<2
				return nil
			}
			if t, ok := layer.(*layers.IPv6); ok {
				t.TrafficClass = t.TrafficClass&0x03 | m.Value[0]<<2
				return nil
			}
		}
	case ofp4.OXM_OF_IP_ECN:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				t.TOS = t.TOS&0xFC | m.Value[0]&0x03
				return nil
			}
			if t, ok := layer.(*layers.IPv6); ok {
				t.TrafficClass = t.TrafficClass&0xFC | m.Value[0]&0x03
				return nil
			}
		}
	case ofp4.OXM_OF_IP_PROTO:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				t.Protocol = layers.IPProtocol(m.Value[0])
				return nil
			}
			if t, ok := layer.(*layers.IPv6); ok {
				t.NextHeader = layers.IPProtocol(m.Value[0])
				return nil
			}
		}
	case ofp4.OXM_OF_IPV4_SRC:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				t.SrcIP = net.IP(m.Value)
				return nil
			}
		}
	case ofp4.OXM_OF_IPV4_DST:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				t.DstIP = net.IP(m.Value)
				return nil
			}
		}
	case ofp4.OXM_OF_TCP_SRC:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.TCP); ok {
				t.SrcPort = layers.TCPPort(binary.BigEndian.Uint16(m.Value))
				return nil
			}
		}
	case ofp4.OXM_OF_TCP_DST:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.TCP); ok {
				t.DstPort = layers.TCPPort(binary.BigEndian.Uint16(m.Value))
				return nil
			}
		}
	case ofp4.OXM_OF_UDP_SRC:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.UDP); ok {
				t.SrcPort = layers.UDPPort(binary.BigEndian.Uint16(m.Value))
				return nil
			}
		}
	case ofp4.OXM_OF_UDP_DST:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.UDP); ok {
				t.DstPort = layers.UDPPort(binary.BigEndian.Uint16(m.Value))
				return nil
			}
		}
	case ofp4.OXM_OF_SCTP_SRC:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.SCTP); ok {
				t.SrcPort = layers.SCTPPort(binary.BigEndian.Uint16(m.Value))
				return nil
			}
		}
	case ofp4.OXM_OF_SCTP_DST:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.SCTP); ok {
				t.DstPort = layers.SCTPPort(binary.BigEndian.Uint16(m.Value))
				return nil
			}
		}
	case ofp4.OXM_OF_ICMPV4_TYPE:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ICMPv4); ok {
				t.TypeCode = layers.ICMPv4TypeCode(uint16(t.TypeCode)&0x00FF | uint16(m.Value[0])<<8)
				return nil
			}
		}
	case ofp4.OXM_OF_ICMPV4_CODE:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ICMPv4); ok {
				t.TypeCode = layers.ICMPv4TypeCode(uint16(t.TypeCode)&0xFF00 | uint16(m.Value[0]))
				return nil
			}
		}
	case ofp4.OXM_OF_ARP_OP:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				t.Operation = binary.BigEndian.Uint16(m.Value)
				return nil
			}
		}
	case ofp4.OXM_OF_ARP_SPA:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				t.SourceProtAddress = m.Value
				return nil
			}
		}
	case ofp4.OXM_OF_ARP_TPA:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				t.DstProtAddress = m.Value
				return nil
			}
		}
	case ofp4.OXM_OF_ARP_SHA:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				t.SourceHwAddress = m.Value
				return nil
			}
		}
	case ofp4.OXM_OF_ARP_THA:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				t.DstHwAddress = m.Value
				return nil
			}
		}
	case ofp4.OXM_OF_IPV6_SRC:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.IPv6); ok {
				t.SrcIP = net.IP(m.Value)
				return nil
			}
		}
	case ofp4.OXM_OF_IPV6_DST:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.IPv6); ok {
				t.DstIP = net.IP(m.Value)
				return nil
			}
		}
	case ofp4.OXM_OF_IPV6_FLABEL:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.IPv6); ok {
				t.FlowLabel = binary.BigEndian.Uint32(m.Value)
				return nil
			}
		}
	case ofp4.OXM_OF_ICMPV6_TYPE:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				t.TypeCode = layers.ICMPv6TypeCode(uint16(t.TypeCode)&0x00FF | uint16(m.Value[0])<<8)
				return nil
			}
		}
	case ofp4.OXM_OF_ICMPV6_CODE:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				t.TypeCode = layers.ICMPv6TypeCode(uint16(t.TypeCode)&0xFF00 | uint16(m.Value[0]))
				return nil
			}
		}
	case ofp4.OXM_OF_IPV6_ND_TARGET:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborSolicitation || typ == layers.ICMPv6TypeNeighborAdvertisement {
					copy(t.Payload[:16], m.Value)
					return nil
				}
			}
		}
	case ofp4.OXM_OF_IPV6_ND_SLL:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborSolicitation {
					for cur := 16; cur < len(t.Payload); {
						length := int(t.Payload[cur+1]) * 8
						if t.Payload[cur] == 1 { // source link-layer address (RFC 2461 4.6)
							copy(t.Payload[cur+2:], m.Value)
							return nil
						}
						cur += length
					}
					buf := make([]byte, 8)
					buf[0] = 2
					buf[1] = 1
					copy(buf[2:], m.Value)
					t.Payload = append(t.Payload, buf...)
					return nil
				}
			}
		}
	case ofp4.OXM_OF_IPV6_ND_TLL:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborAdvertisement {
					for cur := 16; cur < len(t.Payload); {
						length := int(t.Payload[cur+1]) * 8
						if t.Payload[cur] == 2 { // target link-layer address (RFC 2461 4.6)
							copy(t.Payload[cur+2:], m.Value)
							return nil
						}
						cur += length
					}
					buf := make([]byte, 8)
					buf[0] = 2
					buf[1] = 1
					copy(buf[2:], m.Value)
					t.Payload = append(t.Payload, buf...)
					return nil
				}
			}
		}
	case ofp4.OXM_OF_MPLS_LABEL:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.MPLS); ok {
				t.Label = binary.BigEndian.Uint32(m.Value)
				return nil
			}
		}
	case ofp4.OXM_OF_MPLS_TC:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.MPLS); ok {
				t.TrafficClass = m.Value[0]
				return nil
			}
		}
	case ofp4.OXM_OF_MPLS_BOS:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers.MPLS); ok {
				if m.Value[0] == 0 {
					t.StackBottom = false
				} else {
					t.StackBottom = true
				}
				return nil
			}
		}
	case ofp4.OXM_OF_PBB_ISID:
		for _, layer := range data.Layers() {
			if t, ok := layer.(*layers2.PBB); ok {
				t.ServiceIdentifier = binary.BigEndian.Uint32(append(make([]byte, 1), m.Value...))
				return nil
			}
		}
	case ofp4.OXM_OF_TUNNEL_ID:
		data.tunnelId = binary.BigEndian.Uint64(m.Value)
		return nil
	case ofp4.OXM_OF_IPV6_EXTHDR:
		return fmt.Errorf("OXM_OF_IPV6_EXTHDR setter is unsupported")
	}
	return fmt.Errorf("layer not found: %v", m)
}

func (self oxmBasic) Fit(k OxmKey, narrow, wide OxmPayload) (bool, error) {
	n := narrow.(OxmValueMask)
	w := wide.(OxmValueMask)
	return bytes.Equal(maskBytes(n.Value, w.Mask), w.Value), nil
}

func (self oxmBasic) Conflict(k OxmKey, a, b OxmPayload) (bool, error) {
	x := a.(OxmValueMask)
	y := b.(OxmValueMask)
	mask := maskBytes(x.Mask, y.Mask)
	return !bytes.Equal(maskBytes(x.Value, mask), maskBytes(y.Value, mask)), nil
}

func (self oxmBasic) Expand(info map[OxmKey]OxmPayload) error {
	req := make(map[OxmKey]OxmPayload)
	for t, _ := range info {
		switch k := t.(type) {
		case OxmKeyBasic:
			switch uint32(k) {
			case ofp4.OXM_OF_IPV4_SRC, ofp4.OXM_OF_IPV4_DST:
				req[OxmKeyBasic(ofp4.OXM_OF_ETH_TYPE)] = OxmValueMask{
					Value: []byte{0x80, 0x00},
					Mask:  []byte{0xFF, 0xFF},
				}
			case ofp4.OXM_OF_TCP_SRC, ofp4.OXM_OF_TCP_DST:
				req[OxmKeyBasic(ofp4.OXM_OF_IP_PROTO)] = OxmValueMask{
					Value: []byte{0x06},
					Mask:  []byte{0xFF},
				}
			case ofp4.OXM_OF_UDP_SRC, ofp4.OXM_OF_UDP_DST:
				req[OxmKeyBasic(ofp4.OXM_OF_IP_PROTO)] = OxmValueMask{
					Value: []byte{0x11},
					Mask:  []byte{0xFF},
				}
			case ofp4.OXM_OF_SCTP_SRC, ofp4.OXM_OF_SCTP_DST:
				req[OxmKeyBasic(ofp4.OXM_OF_IP_PROTO)] = OxmValueMask{
					Value: []byte{0x84},
					Mask:  []byte{0xFF},
				}
			case ofp4.OXM_OF_ICMPV4_TYPE, ofp4.OXM_OF_ICMPV4_CODE:
				req[OxmKeyBasic(ofp4.OXM_OF_IP_PROTO)] = OxmValueMask{
					Value: []byte{0x01},
					Mask:  []byte{0xFF},
				}
			case ofp4.OXM_OF_ARP_OP,
				ofp4.OXM_OF_ARP_SPA, ofp4.OXM_OF_ARP_TPA,
				ofp4.OXM_OF_ARP_SHA, ofp4.OXM_OF_ARP_THA:
				req[OxmKeyBasic(ofp4.OXM_OF_ETH_TYPE)] = OxmValueMask{
					Value: []byte{0x08, 0x06},
					Mask:  []byte{0xFF, 0xFF},
				}
			case ofp4.OXM_OF_IPV6_SRC, ofp4.OXM_OF_IPV6_DST, ofp4.OXM_OF_IPV6_FLABEL:
				req[OxmKeyBasic(ofp4.OXM_OF_ETH_TYPE)] = OxmValueMask{
					Value: []byte{0x86, 0xDD},
					Mask:  []byte{0xFF, 0xFF},
				}
			case ofp4.OXM_OF_ICMPV6_TYPE, ofp4.OXM_OF_ICMPV6_CODE:
				req[OxmKeyBasic(ofp4.OXM_OF_IP_PROTO)] = OxmValueMask{
					Value: []byte{0x3A},
					Mask:  []byte{0xFF},
				}
			case ofp4.OXM_OF_IPV6_ND_SLL:
				req[OxmKeyBasic(ofp4.OXM_OF_ICMPV6_TYPE)] = OxmValueMask{
					Value: []byte{135},
					Mask:  []byte{0xFF},
				}
			case ofp4.OXM_OF_IPV6_ND_TLL:
				req[OxmKeyBasic(ofp4.OXM_OF_ICMPV6_TYPE)] = OxmValueMask{
					Value: []byte{136},
					Mask:  []byte{0xFF},
				}
			case ofp4.OXM_OF_PBB_ISID:
				req[OxmKeyBasic(ofp4.OXM_OF_ETH_TYPE)] = OxmValueMask{
					Value: []byte{0x88, 0xE7},
					Mask:  []byte{0xFF, 0xFF},
				}
			case ofp4.OXM_OF_IPV6_EXTHDR:
				req[OxmKeyBasic(ofp4.OXM_OF_ETH_TYPE)] = OxmValueMask{
					Value: []byte{0x86, 0xDD},
					Mask:  []byte{0xFF, 0xFF},
				}
			}
		}
	}
	for k, v := range req {
		if e, ok := info[k]; ok {
			if !e.(OxmValueMask).Equal(v.(OxmValueMask)) {
				return fmt.Errorf("prerequisite error")
			}
		} else {
			info[k] = v
		}
	}
	return nil
}

var oxmOfbAll []uint32 = []uint32{
	ofp4.OXM_OF_IN_PORT,
	ofp4.OXM_OF_IN_PHY_PORT,
	ofp4.OXM_OF_METADATA,
	ofp4.OXM_OF_ETH_DST,
	ofp4.OXM_OF_ETH_SRC,
	ofp4.OXM_OF_ETH_TYPE,
	ofp4.OXM_OF_VLAN_VID,
	ofp4.OXM_OF_VLAN_PCP,
	ofp4.OXM_OF_IP_DSCP,
	ofp4.OXM_OF_IP_ECN,
	ofp4.OXM_OF_IP_PROTO,
	ofp4.OXM_OF_IPV4_SRC,
	ofp4.OXM_OF_IPV4_DST,
	ofp4.OXM_OF_TCP_SRC,
	ofp4.OXM_OF_TCP_DST,
	ofp4.OXM_OF_UDP_SRC,
	ofp4.OXM_OF_UDP_DST,
	ofp4.OXM_OF_SCTP_SRC,
	ofp4.OXM_OF_SCTP_DST,
	ofp4.OXM_OF_ICMPV4_TYPE,
	ofp4.OXM_OF_ICMPV4_CODE,
	ofp4.OXM_OF_ARP_OP,
	ofp4.OXM_OF_ARP_SPA,
	ofp4.OXM_OF_ARP_TPA,
	ofp4.OXM_OF_ARP_SHA,
	ofp4.OXM_OF_ARP_THA,
	ofp4.OXM_OF_IPV6_SRC,
	ofp4.OXM_OF_IPV6_DST,
	ofp4.OXM_OF_IPV6_FLABEL,
	ofp4.OXM_OF_ICMPV6_TYPE,
	ofp4.OXM_OF_ICMPV6_CODE,
	ofp4.OXM_OF_IPV6_ND_TARGET,
	ofp4.OXM_OF_IPV6_ND_SLL,
	ofp4.OXM_OF_IPV6_ND_TLL,
	ofp4.OXM_OF_MPLS_LABEL,
	ofp4.OXM_OF_MPLS_TC,
	ofp4.OXM_OF_MPLS_BOS,
	ofp4.OXM_OF_PBB_ISID,
	ofp4.OXM_OF_TUNNEL_ID,
	ofp4.OXM_OF_IPV6_EXTHDR,
}
