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
)

type matchResult struct {
	tableId  uint8
	priority uint16
	rule     *flowEntry
}

// data associated with a packet, which is
// alive while the packet travels the pipeline
type frame struct {
	layers     []gopacket.Layer
	serialized []byte // cache
	length     int    // cache
	inPort     uint32
	phyInPort  uint32
	metadata   uint64
	tunnelId   uint64
	queueId    uint32
	actionSet  map[uint16]action
	match      *matchResult
}

func (f *frame) process(p Pipeline) []packetOut {
	// Multiple packet_out may happen and multiple errors may happen. That's why this func does not return an error.
	// errors will be stored in frame.errors
	ret := f.processTable(0, p)
	return ret
}

func (f *frame) processTable(tableId uint8, pipe Pipeline) []packetOut {
	var result []packetOut
	for _, table := range pipe.getFlowTables(tableId) {
		if entry, priority := table.lookup(*f); entry != nil {
			f.match = &matchResult{
				tableId:  tableId,
				priority: priority,
				rule:     entry,
			}
			ret := entry.process(f, pipe)
			result = append(result, ret.outputs...)
			result = append(result, f.processGroups(ret.groups, pipe, nil)...)
			if ret.tableId != 0 {
				result = append(result, f.processTable(ret.tableId, pipe)...)
			}
		} else {
			// really table-miss, drop
		}
	}
	return result
}

func (f *frame) processGroups(groups []groupOut, pipe Pipeline, processed []uint32) []packetOut {
	var result []packetOut
	for _, gout := range groups {
		for _, gid := range processed {
			if gid == gout.groupId {
				log.Printf("group loop detected")
				return nil
			}
		}
		for _, group := range pipe.getGroups(gout.groupId) {
			gf := f.clone()
			ret := group.process(gf, pipe)
			result = append(result, ret.outputs...)
			result = append(result, gf.processGroups(ret.groups, pipe, append(processed, gout.groupId))...)
		}
	}
	return result
}

func (f frame) data() ([]byte, error) {
	if f.serialized == nil {
		buf := gopacket.NewSerializeBuffer()
		ls := make([]gopacket.SerializableLayer, len(f.layers))

		var network gopacket.NetworkLayer
		for i, layer := range f.layers {
			switch l := layer.(type) {
			case *layers.IPv4:
				if network == nil {
					network = l
				}
			case *layers.IPv6:
				if network == nil {
					network = l
				}
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
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ls...); err != nil {
			return nil, err
		} else {
			f.serialized = buf.Bytes()
			if len(f.serialized) != f.length {
				log.Println("frame length shortcut may be broken")
			}
		}
	}
	return f.serialized, nil
}

func (f frame) clone() *frame {
	var eth []byte
	if f.serialized != nil {
		eth = f.serialized
	} else {
		if frameBytes, err := f.data(); err != nil {
			log.Println(err)
		} else {
			eth = frameBytes
		}
	}
	return &frame{
		inPort:     f.inPort,
		phyInPort:  f.phyInPort,
		length:     len(eth),
		serialized: eth,
		layers:     gopacket.NewPacket(eth, layers.LayerTypeEthernet, gopacket.DecodeOptions{}).Layers(),
		actionSet:  make(map[uint16]action),
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
	data.serialized = nil

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
