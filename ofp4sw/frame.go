package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"hash/fnv"
	"log"
	"net"
	"time"
)

// data associated with a packet, which is
// alive while the packet travels the pipeline
type frame struct {
	// serialized or layers may be 0 length(or nil), not both at a time.
	// If both are 0, then it is INVALID packet, this may happen on TTL decrement.
	serialized []byte
	layers     []gopacket.Layer // Not a gopacket.Packet, because Data() returns original packet bytes even when layers were modified.
	inPort     uint32
	phyInPort  uint32
	metadata   uint64
	tunnelId   uint64
	queueId    uint32
	actionSet  map[uint16]action
}

func (self frame) isInvalid() bool {
	return len(self.serialized) == 0 && len(self.layers) == 0
}

// useLayers makes sure that layers are available, and invalidate serialized buffer for future layer modification.
func (self *frame) useLayers() {
	if len(self.layers) == 0 {
		self.layers = gopacket.NewPacket(self.serialized, layers.LayerTypeEthernet, gopacket.NoCopy).Layers()
	}
	self.serialized = self.serialized[:0]
}

func (self *frame) data() ([]byte, error) {
	if len(self.serialized) == 0 {
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
				return nil, errors.New(fmt.Sprint("non serializableLayer", layer))
			}
		}

		buf := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ls...)
		if err != nil {
			return nil, err
		}
		self.serialized = buf.Bytes()
	}
	return self.serialized, nil
}

func (self frame) clone() *frame {
	frameBytes, err := self.data()
	if err != nil {
		log.Println(err)
		// in this case, returned data will be not nil but isInvalid().
	}
	var actionSet map[uint16]action
	if self.actionSet != nil {
		actionSet = make(map[uint16]action)
		for k, v := range self.actionSet {
			actionSet[k] = v
		}
	}
	return &frame{
		serialized: frameBytes,
		inPort:     self.inPort,
		phyInPort:  self.phyInPort,
		metadata:   self.metadata,
		tunnelId:   self.tunnelId,
		queueId:    self.queueId,
		actionSet:  actionSet,
	}
}

func (f frame) hash() uint32 {
	hashKeys := [...]uint64{ofp4.OFPXMT_OFB_ETH_DST,
		ofp4.OFPXMT_OFB_ETH_SRC,
		ofp4.OFPXMT_OFB_ETH_TYPE,
		ofp4.OFPXMT_OFB_VLAN_VID,
		ofp4.OFPXMT_OFB_VLAN_PCP,
		ofp4.OFPXMT_OFB_IP_DSCP,
		ofp4.OFPXMT_OFB_IP_ECN,
		ofp4.OFPXMT_OFB_IP_PROTO,
		ofp4.OFPXMT_OFB_IPV4_SRC,
		ofp4.OFPXMT_OFB_IPV4_DST,
		ofp4.OFPXMT_OFB_TCP_SRC,
		ofp4.OFPXMT_OFB_TCP_DST,
		ofp4.OFPXMT_OFB_UDP_SRC,
		ofp4.OFPXMT_OFB_UDP_DST,
		ofp4.OFPXMT_OFB_SCTP_SRC,
		ofp4.OFPXMT_OFB_SCTP_DST,
		ofp4.OFPXMT_OFB_ICMPV4_TYPE,
		ofp4.OFPXMT_OFB_ICMPV4_CODE,
		ofp4.OFPXMT_OFB_ARP_OP,
		ofp4.OFPXMT_OFB_ARP_SPA,
		ofp4.OFPXMT_OFB_ARP_TPA,
		ofp4.OFPXMT_OFB_ARP_SHA,
		ofp4.OFPXMT_OFB_ARP_THA,
		ofp4.OFPXMT_OFB_IPV6_SRC,
		ofp4.OFPXMT_OFB_IPV6_DST,
		ofp4.OFPXMT_OFB_IPV6_FLABEL,
		ofp4.OFPXMT_OFB_ICMPV6_TYPE,
		ofp4.OFPXMT_OFB_ICMPV6_CODE,
		ofp4.OFPXMT_OFB_MPLS_LABEL,
		ofp4.OFPXMT_OFB_MPLS_TC,
		ofp4.OFPXMT_OFB_MPLS_BOS,
		ofp4.OFPXMT_OFB_PBB_ISID}
	hasher := fnv.New32()
	for _, k := range hashKeys {
		if buf, err := f.getValue(match{field: k}); err == nil {
			hasher.Write(buf)
		}
	}
	return hasher.Sum32()
}

func (data frame) getValue(m match) ([]byte, error) {
	data.useLayers()

	switch m.field {
	default:
		return nil, errors.New("unknown oxm field")
	case ofp4.OFPXMT_OFB_IN_PORT:
		return toMatchBytes(data.inPort)
	case ofp4.OFPXMT_OFB_IN_PHY_PORT:
		return toMatchBytes(data.phyInPort)
	case ofp4.OFPXMT_OFB_METADATA:
		return toMatchBytes(data.metadata)
	case ofp4.OFPXMT_OFB_ETH_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.Ethernet); ok {
				return toMatchBytes(t.DstMAC)
			}
		}
	case ofp4.OFPXMT_OFB_ETH_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.Ethernet); ok {
				return toMatchBytes(t.SrcMAC)
			}
		}
	case ofp4.OFPXMT_OFB_ETH_TYPE:
		do_break := false
		var ret []byte
		for _, layer := range data.layers {
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
	case ofp4.OFPXMT_OFB_VLAN_VID:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.Dot1Q); ok {
				return toMatchBytes(t.VLANIdentifier | 0x1000)
			}
		}
		return toMatchBytes(uint16(0x0000))
	case ofp4.OFPXMT_OFB_VLAN_PCP:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.Dot1Q); ok {
				return toMatchBytes(t.Priority)
			}
		}
	case ofp4.OFPXMT_OFB_IP_DSCP:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.TOS >> 2)
			}
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.TrafficClass >> 2)
			}
		}
	case ofp4.OFPXMT_OFB_IP_ECN:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.TOS & 0x03)
			}
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.TrafficClass & 0x03)
			}
		}
	case ofp4.OFPXMT_OFB_IP_PROTO:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.Protocol)
			}
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.NextHeader)
			}
		}
	case ofp4.OFPXMT_OFB_IPV4_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.SrcIP)
			}
		}
	case ofp4.OFPXMT_OFB_IPV4_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				return toMatchBytes(t.DstIP)
			}
		}
	case ofp4.OFPXMT_OFB_TCP_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.TCP); ok {
				return toMatchBytes(t.SrcPort)
			}
		}
	case ofp4.OFPXMT_OFB_TCP_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.TCP); ok {
				return toMatchBytes(t.DstPort)
			}
		}
	case ofp4.OFPXMT_OFB_UDP_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.UDP); ok {
				return toMatchBytes(t.SrcPort)
			}
		}
	case ofp4.OFPXMT_OFB_UDP_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.UDP); ok {
				return toMatchBytes(t.DstPort)
			}
		}
	case ofp4.OFPXMT_OFB_SCTP_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.SCTP); ok {
				return toMatchBytes(t.SrcPort)
			}
		}
	case ofp4.OFPXMT_OFB_SCTP_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.SCTP); ok {
				return toMatchBytes(t.DstPort)
			}
		}
	case ofp4.OFPXMT_OFB_ICMPV4_TYPE:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv4); ok {
				if buf, err := toMatchBytes(t.TypeCode); err != nil {
					return nil, err
				} else {
					return buf[:1], nil
				}
			}
		}
	case ofp4.OFPXMT_OFB_ICMPV4_CODE:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv4); ok {
				if buf, err := toMatchBytes(t.TypeCode); err != nil {
					return nil, err
				} else {
					return buf[1:], nil
				}
			}
		}
	case ofp4.OFPXMT_OFB_ARP_OP:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.Operation)
			}
		}
	case ofp4.OFPXMT_OFB_ARP_SPA:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.SourceProtAddress)
			}
		}
	case ofp4.OFPXMT_OFB_ARP_TPA:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.DstProtAddress)
			}
		}
	case ofp4.OFPXMT_OFB_ARP_SHA:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.SourceHwAddress)
			}
		}
	case ofp4.OFPXMT_OFB_ARP_THA:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				return toMatchBytes(t.DstHwAddress)
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.SrcIP)
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.DstIP)
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_FLABEL:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv6); ok {
				return toMatchBytes(t.FlowLabel)
			}
		}
	case ofp4.OFPXMT_OFB_ICMPV6_TYPE:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv6); ok {
				if buf, err := toMatchBytes(t.TypeCode); err != nil {
					return nil, err
				} else {
					return buf[:1], nil
				}
			}
		}
	case ofp4.OFPXMT_OFB_ICMPV6_CODE:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv6); ok {
				if buf, err := toMatchBytes(t.TypeCode); err != nil {
					return nil, err
				} else {
					return buf[1:], nil
				}
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_ND_TARGET:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborSolicitation || typ == layers.ICMPv6TypeNeighborAdvertisement {
					return t.Payload[:16], nil
				}
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_ND_SLL:
		for _, layer := range data.layers {
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
	case ofp4.OFPXMT_OFB_IPV6_ND_TLL:
		for _, layer := range data.layers {
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
	case ofp4.OFPXMT_OFB_MPLS_LABEL:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.MPLS); ok {
				return toMatchBytes(t.Label)
			}
		}
	case ofp4.OFPXMT_OFB_MPLS_TC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.MPLS); ok {
				return toMatchBytes(t.TrafficClass)
			}
		}
	case ofp4.OFPXMT_OFB_MPLS_BOS:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.MPLS); ok {
				var bos uint8
				if t.StackBottom {
					bos = uint8(1)
				}
				return toMatchBytes(bos)
			}
		}
	case ofp4.OFPXMT_OFB_PBB_ISID:
		for _, layer := range data.layers {
			if t, ok := layer.(*PBB); ok {
				ext := make([]byte, 4)
				binary.BigEndian.PutUint32(ext, t.ServiceIdentifier)
				return ext[1:], nil
			}
		}
	case ofp4.OFPXMT_OFB_TUNNEL_ID:
		return toMatchBytes(data.tunnelId)
	case ofp4.OFPXMT_OFB_IPV6_EXTHDR:
		exthdr := uint16(0)
		for _, layer := range data.layers {
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
	return nil, errors.New(fmt.Sprint("layer not found", m.field))
}

func (data *frame) setValue(m match) error {
	data.useLayers()

	switch m.field {
	default:
		return errors.New("unknown oxm field")
	case ofp4.OFPXMT_OFB_IN_PORT:
		data.inPort = binary.BigEndian.Uint32(m.value)
		return nil
	case ofp4.OFPXMT_OFB_IN_PHY_PORT:
		data.phyInPort = binary.BigEndian.Uint32(m.value)
		return nil
	case ofp4.OFPXMT_OFB_METADATA:
		data.metadata = binary.BigEndian.Uint64(m.value)
		return nil
	case ofp4.OFPXMT_OFB_ETH_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.Ethernet); ok {
				t.DstMAC = net.HardwareAddr(m.value)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ETH_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.Ethernet); ok {
				t.SrcMAC = net.HardwareAddr(m.value)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ETH_TYPE:
		var lastLayer gopacket.Layer
		for _, layer := range data.layers {
			switch t := layer.(type) {
			case *layers.Ethernet:
				lastLayer = t
			case *layers.Dot1Q:
				lastLayer = t
			}
		}
		if t, ok := lastLayer.(*layers.Ethernet); ok {
			t.EthernetType = layers.EthernetType(binary.BigEndian.Uint16(m.value))
			return nil
		}
		if t, ok := lastLayer.(*layers.Dot1Q); ok {
			t.Type = layers.EthernetType(binary.BigEndian.Uint16(m.value))
			return nil
		}
	case ofp4.OFPXMT_OFB_VLAN_VID:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.Dot1Q); ok {
				t.VLANIdentifier = binary.BigEndian.Uint16(m.value) & 0x0fff
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_VLAN_PCP:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.Dot1Q); ok {
				t.Priority = m.value[0]
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_IP_DSCP:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				t.TOS = t.TOS&0x03 | m.value[0]<<2
				return nil
			}
			if t, ok := layer.(*layers.IPv6); ok {
				t.TrafficClass = t.TrafficClass&0x03 | m.value[0]<<2
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_IP_ECN:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				t.TOS = t.TOS&0xFC | m.value[0]&0x03
				return nil
			}
			if t, ok := layer.(*layers.IPv6); ok {
				t.TrafficClass = t.TrafficClass&0xFC | m.value[0]&0x03
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_IP_PROTO:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				t.Protocol = layers.IPProtocol(m.value[0])
				return nil
			}
			if t, ok := layer.(*layers.IPv6); ok {
				t.NextHeader = layers.IPProtocol(m.value[0])
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_IPV4_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				t.SrcIP = net.IP(m.value)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_IPV4_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv4); ok {
				t.DstIP = net.IP(m.value)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_TCP_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.TCP); ok {
				t.SrcPort = layers.TCPPort(binary.BigEndian.Uint16(m.value))
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_TCP_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.TCP); ok {
				t.DstPort = layers.TCPPort(binary.BigEndian.Uint16(m.value))
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_UDP_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.UDP); ok {
				t.SrcPort = layers.UDPPort(binary.BigEndian.Uint16(m.value))
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_UDP_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.UDP); ok {
				t.DstPort = layers.UDPPort(binary.BigEndian.Uint16(m.value))
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_SCTP_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.SCTP); ok {
				t.SrcPort = layers.SCTPPort(binary.BigEndian.Uint16(m.value))
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_SCTP_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.SCTP); ok {
				t.DstPort = layers.SCTPPort(binary.BigEndian.Uint16(m.value))
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ICMPV4_TYPE:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv4); ok {
				t.TypeCode = layers.ICMPv4TypeCode(uint16(t.TypeCode)&0x00FF | uint16(m.value[0])<<8)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ICMPV4_CODE:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv4); ok {
				t.TypeCode = layers.ICMPv4TypeCode(uint16(t.TypeCode)&0xFF00 | uint16(m.value[0]))
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ARP_OP:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				t.Operation = binary.BigEndian.Uint16(m.value)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ARP_SPA:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				t.SourceProtAddress = m.value
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ARP_TPA:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				t.DstProtAddress = m.value
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ARP_SHA:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				t.SourceHwAddress = m.value
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ARP_THA:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ARP); ok {
				t.DstHwAddress = m.value
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_SRC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv6); ok {
				t.SrcIP = net.IP(m.value)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_DST:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv6); ok {
				t.DstIP = net.IP(m.value)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_FLABEL:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.IPv6); ok {
				t.FlowLabel = binary.BigEndian.Uint32(m.value)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ICMPV6_TYPE:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv6); ok {
				t.TypeCode = layers.ICMPv6TypeCode(uint16(t.TypeCode)&0x00FF | uint16(m.value[0])<<8)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_ICMPV6_CODE:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv6); ok {
				t.TypeCode = layers.ICMPv6TypeCode(uint16(t.TypeCode)&0xFF00 | uint16(m.value[0]))
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_ND_TARGET:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborSolicitation || typ == layers.ICMPv6TypeNeighborAdvertisement {
					copy(t.Payload[:16], m.value)
					return nil
				}
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_ND_SLL:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborSolicitation {
					for cur := 16; cur < len(t.Payload); {
						length := int(t.Payload[cur+1]) * 8
						if t.Payload[cur] == 1 { // source link-layer address (RFC 2461 4.6)
							copy(t.Payload[cur+2:], m.value)
							return nil
						}
						cur += length
					}
					buf := make([]byte, 8)
					buf[0] = 2
					buf[1] = 1
					copy(buf[2:], m.value)
					t.Payload = append(t.Payload, buf...)
					return nil
				}
			}
		}
	case ofp4.OFPXMT_OFB_IPV6_ND_TLL:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.ICMPv6); ok {
				typ := uint8(t.TypeCode >> 8)
				if typ == layers.ICMPv6TypeNeighborAdvertisement {
					for cur := 16; cur < len(t.Payload); {
						length := int(t.Payload[cur+1]) * 8
						if t.Payload[cur] == 2 { // target link-layer address (RFC 2461 4.6)
							copy(t.Payload[cur+2:], m.value)
							return nil
						}
						cur += length
					}
					buf := make([]byte, 8)
					buf[0] = 2
					buf[1] = 1
					copy(buf[2:], m.value)
					t.Payload = append(t.Payload, buf...)
					return nil
				}
			}
		}
	case ofp4.OFPXMT_OFB_MPLS_LABEL:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.MPLS); ok {
				t.Label = binary.BigEndian.Uint32(m.value)
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_MPLS_TC:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.MPLS); ok {
				t.TrafficClass = m.value[0]
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_MPLS_BOS:
		for _, layer := range data.layers {
			if t, ok := layer.(*layers.MPLS); ok {
				if m.value[0] == 0 {
					t.StackBottom = false
				} else {
					t.StackBottom = true
				}
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_PBB_ISID:
		for _, layer := range data.layers {
			if t, ok := layer.(*PBB); ok {
				t.ServiceIdentifier = binary.BigEndian.Uint32(append(make([]byte, 1), m.value...))
				return nil
			}
		}
	case ofp4.OFPXMT_OFB_TUNNEL_ID:
		data.tunnelId = binary.BigEndian.Uint64(m.value)
		return nil
	case ofp4.OFPXMT_OFB_IPV6_EXTHDR:
		return errors.New("OFPXMT_OFB_IPV6_EXTHDR setter is unsupported")
	}
	return errors.New(fmt.Sprint("layer not found", m.field))
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
		err = errors.New(fmt.Sprintf("hogehoge Unexpected type %s", v))
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

func expandMatch(obj []match) []match {
	x := make(map[uint64]*match)
	for _, m := range obj {
		for h := &m; h != nil; h = matchImplied(h.field) {
			x[h.field] = h
		}
	}
	u := make([]match, 0, len(x))
	for _, m := range x {
		u = append(u, *m)
	}
	return u
}

func matchImplied(field uint64) *match {
	var ext *match
	switch field {
	case ofp4.OFPXMT_OFB_IPV4_SRC, ofp4.OFPXMT_OFB_IPV4_DST:
		ext = &match{
			ofp4.OFPXMT_OFB_ETH_TYPE,
			[]byte{0x80, 0x00},
			[]byte{0xFF, 0xFF},
		}
	case ofp4.OFPXMT_OFB_TCP_SRC, ofp4.OFPXMT_OFB_TCP_DST:
		ext = &match{
			ofp4.OFPXMT_OFB_IP_PROTO,
			[]byte{0x06},
			[]byte{0xFF},
		}
	case ofp4.OFPXMT_OFB_UDP_SRC, ofp4.OFPXMT_OFB_UDP_DST:
		ext = &match{
			ofp4.OFPXMT_OFB_IP_PROTO,
			[]byte{0x11},
			[]byte{0xFF},
		}
	case ofp4.OFPXMT_OFB_SCTP_SRC, ofp4.OFPXMT_OFB_SCTP_DST:
		ext = &match{
			ofp4.OFPXMT_OFB_IP_PROTO,
			[]byte{0x84},
			[]byte{0xFF},
		}
	case ofp4.OFPXMT_OFB_ICMPV4_TYPE, ofp4.OFPXMT_OFB_ICMPV4_CODE:
		ext = &match{
			ofp4.OFPXMT_OFB_IP_PROTO,
			[]byte{0x01},
			[]byte{0xFF},
		}
	case ofp4.OFPXMT_OFB_ARP_OP,
		ofp4.OFPXMT_OFB_ARP_SPA, ofp4.OFPXMT_OFB_ARP_TPA,
		ofp4.OFPXMT_OFB_ARP_SHA, ofp4.OFPXMT_OFB_ARP_THA:
		ext = &match{
			ofp4.OFPXMT_OFB_ETH_TYPE,
			[]byte{0x08, 0x06},
			[]byte{0xFF, 0xFF},
		}
	case ofp4.OFPXMT_OFB_IPV6_SRC, ofp4.OFPXMT_OFB_IPV6_DST, ofp4.OFPXMT_OFB_IPV6_FLABEL:
		ext = &match{
			ofp4.OFPXMT_OFB_ETH_TYPE,
			[]byte{0x86, 0xDD},
			[]byte{0xFF, 0xFF},
		}
	case ofp4.OFPXMT_OFB_ICMPV6_TYPE, ofp4.OFPXMT_OFB_ICMPV6_CODE:
		ext = &match{
			ofp4.OFPXMT_OFB_IP_PROTO,
			[]byte{0x3A},
			[]byte{0xFF},
		}
	case ofp4.OFPXMT_OFB_IPV6_ND_SLL:
		ext = &match{
			ofp4.OFPXMT_OFB_ICMPV6_TYPE,
			[]byte{135},
			[]byte{0xFF},
		}
	case ofp4.OFPXMT_OFB_IPV6_ND_TLL:
		ext = &match{
			ofp4.OFPXMT_OFB_ICMPV6_TYPE,
			[]byte{136},
			[]byte{0xFF},
		}
	case ofp4.OFPXMT_OFB_PBB_ISID:
		ext = &match{
			ofp4.OFPXMT_OFB_ETH_TYPE,
			[]byte{0x88, 0xE7},
			[]byte{0xFF, 0xFF},
		}
	case ofp4.OFPXMT_OFB_IPV6_EXTHDR:
		ext = &match{
			ofp4.OFPXMT_OFB_ETH_TYPE,
			[]byte{0x86, 0xDD},
			[]byte{0xFF, 0xFF},
		}
	}
	return ext
}

type flowTableWork struct {
	data *frame
	// ref
	pipe    *Pipeline
	tableId uint8
	// results
	outputs   []*outputToPort
	nextTable uint8
}

func (self *flowTableWork) Map() Reducable {
	// clear
	self.outputs = self.outputs[:0]
	self.nextTable = 0

	// lookup phase
	var entry *flowEntry
	var priority uint16
	table := self.pipe.getFlowTable(self.tableId)

	if table == nil {
		return self
	}
	func() {
		table.lock.Lock()
		defer table.lock.Unlock()
		table.lookupCount++
	}()
	func() {
		table.lock.RLock()
		defer table.lock.RUnlock()
		for _, prio := range table.priorities {
			entry, priority = func() (*flowEntry, uint16) {
				hasher := fnv.New32()
				prio.lock.RLock()
				defer prio.lock.RUnlock()
				for _, cap := range prio.caps {
					if buf, err := self.data.getValue(cap); err != nil {
						log.Println(err)
						return nil, 0
					} else {
						hasher.Write(maskBytes(buf, cap.mask))
					}
				}
				if flows, ok := prio.flows[hasher.Sum32()]; ok {
					for _, flow := range flows {
						hit := true
						for _, field := range flow.fields {
							if !field.match(*self.data) {
								hit = false
								break
							}
						}
						if hit {
							return flow, prio.priority
						}
					}
				}
				return nil, 0
			}()
			if entry != nil {
				return
			}
		}
		return
	}()
	// execution
	var groups []*outputToGroup
	if entry != nil {
		func() {
			table.lock.Lock()
			defer table.lock.Unlock()
			table.matchCount++
		}()
		func() {
			entry.lock.Lock()
			defer entry.lock.Unlock()
			if entry.flags&ofp4.OFPFF_NO_PKT_COUNTS == 0 {
				entry.packetCount++
			}
			if entry.flags&ofp4.OFPFF_NO_BYT_COUNTS == 0 {
				if eth, err := self.data.data(); err != nil {
					log.Print(err)
				} else {
					entry.byteCount += uint64(len(eth))
				}
			}
			entry.touched = time.Now()
		}()

		pipe := self.pipe
		if entry.instMeter != 0 {
			if meter := pipe.getMeter(entry.instMeter); meter != nil {
				if err := meter.process(self.data); err != nil {
					if _, ok := err.(*packetDrop); ok {
						// no log
					} else {
						log.Println(err)
					}
					return self
				}
			}
		}

		for _, act := range entry.instApply {
			if pout, gout, err := act.process(self.data); err != nil {
				log.Print(err)
			} else {
				if pout != nil {
					pout.tableId = self.tableId
					if priority == 0 && len(entry.fields) == 0 && !self.data.isInvalid() {
						pout.reason = ofp4.OFPR_NO_MATCH
					}
					self.outputs = append(self.outputs, pout)
				}
				if gout != nil {
					groups = append(groups, gout)
				}
			}
			if self.data.isInvalid() {
				return self
			}
		}
		if entry.instClear {
			self.data.actionSet = make(map[uint16]action)
		}
		if entry.instWrite != nil {
			for k, v := range entry.instWrite {
				self.data.actionSet[k] = v
			}
		}
		if entry.instMetadata != nil {
			self.data.metadata = entry.instMetadata.apply(self.data.metadata)
		}
		if entry.instGoto != 0 {
			self.nextTable = entry.instGoto
		} else {
			pouts, gouts := actionSet(self.data.actionSet).process(self.data)
			self.outputs = append(self.outputs, pouts...)
			groups = append(groups, gouts...)
		}
	}
	// process groups if any
	if len(groups) > 0 {
		self.outputs = append(self.outputs, self.pipe.groupToOutput(groups, nil)...)
	}
	return self
}

/* groupToOutput is for recursive call */
func (self Pipeline) groupToOutput(groups []*outputToGroup, processed []uint32) []*outputToPort {
	var result []*outputToPort
	for _, gout := range groups {
		for _, gid := range processed {
			if gid == gout.groupId {
				log.Printf("group loop detected")
				return nil
			}
		}
		if group := self.getGroup(gout.groupId); group != nil {
			p, g := group.process(gout.data, self)
			processed := append(processed, gout.groupId)
			result = append(result, p...)
			result = append(result, self.groupToOutput(g, processed)...)
		}
	}
	return result
}

func (self *flowTableWork) Reduce() {
	// packet out for a specific table execution should be in-order.
	for _, output := range self.outputs {
		if output.outPort == ofp4.OFPP_CONTROLLER {
			inPort := self.pipe.getPort(output.data.inPort)
			if inPort != nil {
				config := inPort.GetConfig()
				if config&(ofp4.OFPPC_NO_PACKET_IN) != 0 {
					continue
				}
			}
		}
		for _, port := range self.pipe.getPorts(output.outPort) {
			port.Outlet(output)
		}
	}
	if self.nextTable != 0 {
		self.tableId = self.nextTable
		defer func() {
			self.pipe.datapath <- self
		}()
	} else {
		// atexit
	}
}
