package ofp4sw

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/hkwi/gopenflow/oxm"
	layers2 "github.com/hkwi/suppl/gopacket/layers"
	"hash/fnv"
	"log"
	"net"
	"sort"
)

// frame for cloning in multiple output, which trigger different processing.
type Frame struct {
	// serialized or layers may be 0 length(or nil), not both at a time.
	// If both are 0, then it is INVALID packet, which case may happen on TTL decrement.
	serialized []byte
	layers     []gopacket.Layer // Not a gopacket.Packet, because Data() returns original packet bytes even when layers were modified.
	// out-of-band data
	Oob map[OxmKey]OxmPayload // only experimenter out-of-band will be stored here.
	// pipeline match fields
	inPort    uint32
	inPhyPort uint32
	metadata  uint64
	tunnelId  uint64
	// queue id is pipeline processing specific data, but put in Frame because:
	// 1. queue id is set by action
	// 2. action may be put in action-set
	// 3. group may have action-set
	// 4. group processing acts on cloned Frame
	queueId uint32
}

func (self Frame) isInvalid() bool {
	return len(self.serialized) == 0 && len(self.layers) == 0
}

func (self Frame) clone() Frame {
	oob := make(map[OxmKey]OxmPayload)
	for k, v := range self.Oob {
		oob[k] = v
	}
	if serialized, err := self.Serialized(); err != nil {
		log.Print(err)
		return Frame{} // INVALID
	} else {
		return Frame{
			serialized: serialized,
			Oob:        oob,
			inPort:     self.inPort,
			inPhyPort:  self.inPhyPort,
			metadata:   self.metadata,
			tunnelId:   self.tunnelId,
		}
	}
}

// Layers returns gopacket layer representation of this frame. layers contents are all pointer to struct,
// so you can modify the frame information simply setting values to the slice contents directly.
func (self *Frame) Layers() []gopacket.Layer {
	if len(self.serialized) != 0 {
		self.layers = gopacket.NewPacket(self.serialized, layers.LinkTypeEthernet, gopacket.NoCopy).Layers()
		self.serialized = self.serialized[:0]
	}
	return self.layers
}

// Serialised returns []byte representation of this frame. You should treat this as frozen data and
// should not modify the contents of returned slice.
func (self *Frame) Serialized() ([]byte, error) {
	if len(self.layers) != 0 {
		ls := make([]gopacket.SerializableLayer, len(self.layers))
		var network gopacket.NetworkLayer
		for i, layer := range self.layers {
			switch l := layer.(type) {
			case *layers.IPv4:
				network = l
			case *layers.IPv6:
				network = l
			case *layers.TCP:
				l.SetNetworkLayerForChecksum(network)
			case *layers.UDP:
				l.SetNetworkLayerForChecksum(network)
			case *layers.ICMPv6:
				l.SetNetworkLayerForChecksum(network)
			}
			if t, ok := layer.(gopacket.SerializableLayer); ok {
				ls[i] = t
			} else {
				// XXX: gopacket known issues:
				// XXX:  IPv6 with hop-by-hop header
				return nil, fmt.Errorf("non serializableLayer %v", layer)
			}
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ls...); err != nil {
			return nil, err
		}
		self.layers = self.layers[:0]
		self.serialized = buf.Bytes()
	}
	return self.serialized, nil
}

// hash calculates packet characteric specific hash code.
func (self *Frame) hash() uint32 {
	hashKeys := [...]uint32{
		oxm.OXM_OF_ETH_DST,
		oxm.OXM_OF_ETH_SRC,
		oxm.OXM_OF_ETH_TYPE,
		oxm.OXM_OF_VLAN_VID,
		oxm.OXM_OF_VLAN_PCP,
		oxm.OXM_OF_IP_DSCP,
		oxm.OXM_OF_IP_ECN,
		oxm.OXM_OF_IP_PROTO,
		oxm.OXM_OF_IPV4_SRC,
		oxm.OXM_OF_IPV4_DST,
		oxm.OXM_OF_TCP_SRC,
		oxm.OXM_OF_TCP_DST,
		oxm.OXM_OF_UDP_SRC,
		oxm.OXM_OF_UDP_DST,
		oxm.OXM_OF_SCTP_SRC,
		oxm.OXM_OF_SCTP_DST,
		oxm.OXM_OF_ICMPV4_TYPE,
		oxm.OXM_OF_ICMPV4_CODE,
		oxm.OXM_OF_ARP_OP,
		oxm.OXM_OF_ARP_SPA,
		oxm.OXM_OF_ARP_TPA,
		oxm.OXM_OF_ARP_SHA,
		oxm.OXM_OF_ARP_THA,
		oxm.OXM_OF_IPV6_SRC,
		oxm.OXM_OF_IPV6_DST,
		oxm.OXM_OF_IPV6_FLABEL,
		oxm.OXM_OF_ICMPV6_TYPE,
		oxm.OXM_OF_ICMPV6_CODE,
		oxm.OXM_OF_MPLS_LABEL,
		oxm.OXM_OF_MPLS_TC,
		oxm.OXM_OF_MPLS_BOS,
		oxm.OXM_OF_PBB_ISID,
	}
	hasher := fnv.New32()
	for _, k := range hashKeys {
		if buf, err := self.getValue(k); err == nil {
			hasher.Write(buf)
		}
	}
	return hasher.Sum32()
}

func toMatchBytes(value interface{}) (data []byte, err error) {
	switch v := value.(type) {
	case net.IP:
		value = []byte(v)
	case net.HardwareAddr:
		value = []byte(v)
	case layers.TCPPort:
		value = uint16(v)
	case layers.UDPPort:
		value = uint16(v)
	case layers.SCTPPort:
		value = uint16(v)
	case layers.ICMPv4TypeCode:
		value = uint16(v)
	case layers.ICMPv6TypeCode:
		value = uint16(v)
	case layers.EthernetType:
		value = uint16(v)
	case layers.IPProtocol:
		value = uint8(v)
	}

	switch v := value.(type) {
	default:
		err = fmt.Errorf("hogehoge Unexpected type %s", v)
		panic(err)
	case uint8:
		data = make([]byte, 1)
		data[0] = v
	case uint16:
		data = make([]byte, 2)
		binary.BigEndian.PutUint16(data, uint16(v))
	case uint32:
		data = make([]byte, 4)
		binary.BigEndian.PutUint32(data, uint32(v))
	case uint64:
		data = make([]byte, 8)
		binary.BigEndian.PutUint64(data, uint64(v))
	case []byte:
		data = make([]byte, len(v))
		for i, c := range v {
			data[i] = c
		}
	}
	return
}

func (self *Frame) getValue(oxmType uint32) ([]byte, error) {
	switch oxm.Header(oxmType).Type() {
	default:
		return nil, fmt.Errorf("unknown oxm field %x", oxmType)
	case oxm.OXM_OF_IN_PORT:
		return toMatchBytes(self.inPort)
	case oxm.OXM_OF_IN_PHY_PORT:
		return toMatchBytes(self.inPhyPort)
	case oxm.OXM_OF_METADATA:
		return toMatchBytes(self.metadata)
	case oxm.OXM_OF_ETH_DST:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.Ethernet); ok {
				return toMatchBytes(t.DstMAC)
			}
		}
	case oxm.OXM_OF_ETH_SRC:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.Ethernet); ok {
				return toMatchBytes(t.SrcMAC)
			}
		}
	case oxm.OXM_OF_ETH_TYPE:
		do_break := false
		var ret []byte
		for _, layer := range self.Layers() {
			switch t := layer.(type) {
			case *layers.Ethernet:
				if buf, err := toMatchBytes(t.EthernetType); err != nil {
					return nil, err
				} else {
					ret = buf
				}
			case *layers.Dot1Q:
				if buf, err := toMatchBytes(t.Type); err != nil {
					return nil, err
				} else {
					ret = buf
				}
			default:
				do_break = true
			}
			if do_break {
				break
			}
		}
		if ret != nil {
			return ret, nil
		}
	case oxm.OXM_OF_VLAN_VID:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.Dot1Q); ok {
				return toMatchBytes(t.VLANIdentifier | 0x1000)
			}
		}
		return toMatchBytes(uint16(0x0000))
	case oxm.OXM_OF_VLAN_PCP:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.Dot1Q); ok {
				return toMatchBytes(t.Priority)
			}
		}
	case oxm.OXM_OF_IP_DSCP:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.TOS >> 2)
			}
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.TrafficClass >> 2)
			}
		}
	case oxm.OXM_OF_IP_ECN:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.TOS & 0x03)
			}
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.TrafficClass & 0x03)
			}
		}
	case oxm.OXM_OF_IP_PROTO:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.Protocol)
			}
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.NextHeader)
			}
		}
	case oxm.OXM_OF_IPV4_SRC:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.SrcIP)
			}
		}
	case oxm.OXM_OF_IPV4_DST:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.DstIP)
			}
		}
	case oxm.OXM_OF_TCP_SRC:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.TCP); ok {
				return toMatchBytes(t.SrcPort)
			}
		}
	case oxm.OXM_OF_TCP_DST:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.TCP); ok {
				return toMatchBytes(t.DstPort)
			}
		}
	case oxm.OXM_OF_UDP_SRC:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.UDP); ok {
				return toMatchBytes(t.SrcPort)
			}
		}
	case oxm.OXM_OF_UDP_DST:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.UDP); ok {
				return toMatchBytes(t.DstPort)
			}
		}
	case oxm.OXM_OF_SCTP_SRC:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.SCTP); ok {
				return toMatchBytes(t.SrcPort)
			}
		}
	case oxm.OXM_OF_SCTP_DST:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.SCTP); ok {
				return toMatchBytes(t.DstPort)
			}
		}
	case oxm.OXM_OF_ICMPV4_TYPE:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ICMPv4); ok {
				if buf, err := toMatchBytes(t.TypeCode); err != nil {
					return nil, err
				} else {
					return buf[:1], nil
				}
			}
		}
	case oxm.OXM_OF_ICMPV4_CODE:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ICMPv4); ok {
				if buf, err := toMatchBytes(t.TypeCode); err != nil {
					return nil, err
				} else {
					return buf[1:], nil
				}
			}
		}
	case oxm.OXM_OF_ARP_OP:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.Operation)
			}
		}
	case oxm.OXM_OF_ARP_SPA:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.SourceProtAddress)
			}
		}
	case oxm.OXM_OF_ARP_TPA:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.DstProtAddress)
			}
		}
	case oxm.OXM_OF_ARP_SHA:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.SourceHwAddress)
			}
		}
	case oxm.OXM_OF_ARP_THA:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.DstHwAddress)
			}
		}
	case oxm.OXM_OF_IPV6_SRC:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.SrcIP)
			}
		}
	case oxm.OXM_OF_IPV6_DST:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.DstIP)
			}
		}
	case oxm.OXM_OF_IPV6_FLABEL:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.FlowLabel)
			}
		}
	case oxm.OXM_OF_ICMPV6_TYPE:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				if buf, err := toMatchBytes(t.TypeCode); err != nil {
					return nil, err
				} else {
					return buf[:1], nil
				}
			}
		}
	case oxm.OXM_OF_ICMPV6_CODE:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				if buf, err := toMatchBytes(t.TypeCode); err != nil {
					return nil, err
				} else {
					return buf[1:], nil
				}
			}
		}
	case oxm.OXM_OF_IPV6_ND_TARGET:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborSolicitation || typ == layers.ICMPv6TypeNeighborAdvertisement {
					return t.Payload[:16], nil
				}
			}
		}
	case oxm.OXM_OF_IPV6_ND_SLL:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborSolicitation {
					for cur := 16; cur < len(t.Payload); {
						length := int(t.Payload[cur+1]) * 8
						if t.Payload[cur] == 1 { // source link-layer address (RFC 2461 4.6)
							return t.Payload[cur+2 : cur+length], nil
						}
						cur += length
					}
				}
			}
		}
	case oxm.OXM_OF_IPV6_ND_TLL:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborAdvertisement {
					for cur := 16; cur < len(t.Payload); {
						length := int(t.Payload[cur+1]) * 8
						if t.Payload[cur] == 2 { // target link-layer address (RFC 2461 4.6)
							return t.Payload[cur+2 : cur+length], nil
						}
						cur += length
					}
				}
			}
		}
	case oxm.OXM_OF_MPLS_LABEL:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.MPLS); ok {
				return toMatchBytes(t.Label)
			}
		}
	case oxm.OXM_OF_MPLS_TC:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.MPLS); ok {
				return toMatchBytes(t.TrafficClass)
			}
		}
	case oxm.OXM_OF_MPLS_BOS:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers.MPLS); ok {
				var bos uint8
				if t.StackBottom {
					bos = uint8(1)
				}
				return toMatchBytes(bos)
			}
		}
	case oxm.OXM_OF_PBB_ISID:
		for _, layer := range self.Layers() {
			if t, ok := layer.(*layers2.PBB); ok {
				ext := make([]byte, 4)
				binary.BigEndian.PutUint32(ext, t.ServiceIdentifier)
				return ext[1:], nil
			}
		}
	case oxm.OXM_OF_TUNNEL_ID:
		return toMatchBytes(self.tunnelId)
	case oxm.OXM_OF_IPV6_EXTHDR:
		exthdr := uint16(0)
		for _, layer := range self.Layers() {
			switch p := layer.(type) {
			case *layers.IPv6:
				if p.NextHeader == layers.IPProtocolNoNextHeader {
					exthdr |= ofp4.OFPIEH_NONEXT
				}
			case *layers.IPSecESP:
				if exthdr&^(ofp4.OFPIEH_HOP|ofp4.OFPIEH_DEST|ofp4.OFPIEH_ROUTER|ofp4.OFPIEH_FRAG|ofp4.OFPIEH_AUTH) != 0 {
					exthdr |= ofp4.OFPIEH_UNSEQ
				}
				if exthdr&ofp4.OFPIEH_ESP != 0 {
					exthdr |= ofp4.OFPIEH_UNREP
				}
				exthdr |= ofp4.OFPIEH_ESP
				//				if p.NextHeader == layers.IPProtocolNoNextHeader {
				//					exthdr |= ofp4.OFPIEH_NONEXT
				//				}
			case *layers.IPSecAH:
				if exthdr&^(ofp4.OFPIEH_HOP|ofp4.OFPIEH_DEST|ofp4.OFPIEH_ROUTER|ofp4.OFPIEH_FRAG) != 0 {
					exthdr |= ofp4.OFPIEH_UNSEQ
				}
				if exthdr&ofp4.OFPIEH_AUTH != 0 {
					exthdr |= ofp4.OFPIEH_UNREP
				}
				exthdr |= ofp4.OFPIEH_AUTH
				if p.NextHeader == layers.IPProtocolNoNextHeader {
					exthdr |= ofp4.OFPIEH_NONEXT
				}
			case *layers.IPv6Destination:
				exthdr |= ofp4.OFPIEH_DEST
				if p.NextHeader == layers.IPProtocolNoNextHeader {
					exthdr |= ofp4.OFPIEH_NONEXT
				}
			case *layers.IPv6Fragment:
				if exthdr&^(ofp4.OFPIEH_HOP|ofp4.OFPIEH_DEST|ofp4.OFPIEH_ROUTER) != 0 {
					exthdr |= ofp4.OFPIEH_UNSEQ
				}
				if exthdr&ofp4.OFPIEH_FRAG != 0 {
					exthdr |= ofp4.OFPIEH_UNREP
				}
				exthdr |= ofp4.OFPIEH_FRAG
				if p.NextHeader == layers.IPProtocolNoNextHeader {
					exthdr |= ofp4.OFPIEH_NONEXT
				}
			case *layers.IPv6Routing:
				if exthdr&^(ofp4.OFPIEH_HOP|ofp4.OFPIEH_DEST) != 0 {
					exthdr |= ofp4.OFPIEH_UNSEQ
				}
				if exthdr&ofp4.OFPIEH_ROUTER != 0 {
					exthdr |= ofp4.OFPIEH_UNREP
				}
				exthdr |= ofp4.OFPIEH_ROUTER
				if p.NextHeader == layers.IPProtocolNoNextHeader {
					exthdr |= ofp4.OFPIEH_NONEXT
				}
			case *layers.IPv6HopByHop:
				if exthdr != 0 {
					exthdr |= ofp4.OFPIEH_UNSEQ
				}
				if exthdr&ofp4.OFPIEH_HOP != 0 {
					exthdr |= ofp4.OFPIEH_UNREP
				}
				exthdr |= ofp4.OFPIEH_HOP
				if p.NextHeader == layers.IPProtocolNoNextHeader {
					exthdr |= ofp4.OFPIEH_NONEXT
				}
			}
		}
		return toMatchBytes(exthdr)
	}
	return nil, fmt.Errorf("oxm value not found for %d", oxmType)
}

func (self *Frame) getFrozen() (gopenflow.Frame, error) {
	if _, err := self.Serialized(); err != nil {
		return gopenflow.Frame{}, err
	}
	var oob []byte
	if self.inPort != 0 {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, self.inPort)
		oob = append(oob, OxmKeyBasic(oxm.OXM_OF_IN_PORT).Bytes(OxmValueMask{
			Value: buf,
		})...)
	}
	if self.inPhyPort != 0 {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, self.inPhyPort)
		oob = append(oob, OxmKeyBasic(oxm.OXM_OF_IN_PHY_PORT).Bytes(OxmValueMask{
			Value: buf,
		})...)
	}
	if self.metadata != 0 {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, self.metadata)
		mask := make([]byte, 8)
		for i, _ := range mask {
			mask[i] = 0xff
		}
		oob = append(oob, OxmKeyBasic(oxm.OXM_OF_METADATA).Bytes(OxmValueMask{
			Value: buf,
			Mask:  mask,
		})...)
	}
	if self.tunnelId != 0 {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, self.tunnelId)
		mask := make([]byte, 8)
		for i, _ := range mask {
			mask[i] = 0xff
		}
		oob = append(oob, OxmKeyBasic(oxm.OXM_OF_TUNNEL_ID).Bytes(OxmValueMask{
			Value: buf,
			Mask:  mask,
		})...)
	}
	var sorter []string
	for k, v := range self.Oob {
		sorter = append(sorter, string(k.Bytes(v)))
	}
	sort.Strings(sorter)
	for _, s := range sorter {
		oob = append(oob, []byte(s)...)
	}
	return gopenflow.Frame{
		Data: self.serialized,
		Oob:  oob,
	}, nil
}
