package ofp4sw

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"hash/fnv"
	"net"
)

type frame struct {
	layers    []gopacket.Layer
	inPort    uint32
	phyInPort uint32
	metadata  uint64
	tunnelId  uint64
	queueId   uint32
	actionSet map[uint16]action
	tableId   uint8
	cookie    uint64
	fields    []match
	reason    uint8
	errors    []error
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
			f.tableId = tableId
			f.cookie = entry.cookie
			f.fields = entry.fields
			if priority == 0 && len(entry.fields) == 0 {
				f.reason = ofp4.OFPR_NO_MATCH
			} else {
				f.reason = ofp4.OFPR_ACTION
			}
			ret := entry.process(f, pipe)
			result = append(result, ret.outputs...)
			result = append(result, f.processGroups(ret.groups, pipe, nil)...)
			if ret.tableId != 0 {
				result = append(result, f.processTable(ret.tableId, pipe)...)
			}
		}
	}
	return result
}

func (f *frame) processGroups(groups []groupOut, pipe Pipeline, processed []uint32) []packetOut {
	var result []packetOut
	for _, gout := range groups {
		for _, gid := range processed {
			if gid == gout.groupId {
				f.errors = append(f.errors, errors.New("group loop detected"))
				return nil
			}
		}
		for _, group := range pipe.getGroups(gout.groupId) {
			gf := f.clone()
			ret := group.process(gf, pipe)
			result = append(result, ret.outputs...)
			result = append(result, gf.processGroups(ret.groups, pipe, append(processed, gout.groupId))...)
			f.errors = append(f.errors, gf.errors...)
		}
	}
	return result
}

func (f frame) data() ([]byte, error) {
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
			return nil, errors.New(fmt.Sprint("non serializableLayer", layer))
		}
	}
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true}, ls...); err != nil {

		panic(err)

		return nil, err
	} else {
		r := buf.Bytes()
		return r, nil
	}
}

func (f frame) clone() *frame {
	if frameBytes, err := f.data(); err == nil {
		var d frame
		d = f
		d.layers = gopacket.NewPacket(frameBytes, layers.LayerTypeEthernet, gopacket.DecodeOptions{}).Layers()
		d.actionSet = make(map[uint16]action)
		d.errors = nil
		return &d
	}
	return nil
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
		return nil, errors.New("Unspported")
	case ofp4.OFPXMT_OFB_IPV6_ND_SLL:
		return nil, errors.New("Unsupported OFPXMT_OFB_IPV6_ND_SLL now")
	case ofp4.OFPXMT_OFB_IPV6_ND_TLL:
		return nil, errors.New("Unsupported OFPXMT_OFB_IPV6_ND_TLL now")
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
		return nil, errors.New("Unsupported OFPXMT_OFB_PBB_ISID now")
	case ofp4.OFPXMT_OFB_TUNNEL_ID:
		return toMatchBytes(data.tunnelId)
	case ofp4.OFPXMT_OFB_IPV6_EXTHDR:
		return nil, errors.New("Unsupported OFPXMT_OFB_IPV6_EXTHDR now")
	}
	return nil, errors.New("layer not found")
}

func (data *frame) setValue(m match) error {
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
		return errors.New("Unspported")
	case ofp4.OFPXMT_OFB_IPV6_ND_SLL:
		return errors.New("Unsupported OFPXMT_OFB_IPV6_ND_SLL now")
	case ofp4.OFPXMT_OFB_IPV6_ND_TLL:
		return errors.New("Unsupported OFPXMT_OFB_IPV6_ND_TLL now")
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
		return errors.New("Unsupported OFPXMT_OFB_PBB_ISID now")
	case ofp4.OFPXMT_OFB_TUNNEL_ID:
		data.tunnelId = binary.BigEndian.Uint64(m.value)
		return nil
	case ofp4.OFPXMT_OFB_IPV6_EXTHDR:
		return errors.New("Unsupported OFPXMT_OFB_IPV6_EXTHDR now")
	}
	return errors.New("layer not found")
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
