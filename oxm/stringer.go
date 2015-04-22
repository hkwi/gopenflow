package oxm

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type OxmStringer interface {
	FromOxm([]byte) string
	ToOxm(string) ([]byte, int, error)
}

var stringers = map[uint32]OxmStringer{
	STRATOS_EXPERIMENTER_ID: stratosStringer,
}

func (self Oxm) String() string {
	var ret []string
	for _, s := range self.Iter() {
		ret = append(ret, single(s).String())
	}
	return strings.Join(ret, ",")
}

type single []byte

func (oxm single) String() string {
	s := "?"
	hdr := Oxm(oxm).Header()
	switch hdr.Class() {
	case OFPXMC_OPENFLOW_BASIC:
		p := oxm[4:]

		switch hdr.Field() {
		case OFPXMT_OFB_IN_PORT:
			s = fmt.Sprintf("in_port=%v", Port(binary.BigEndian.Uint32(p)))
		case OFPXMT_OFB_IN_PHY_PORT:
			s = fmt.Sprintf("in_phy_port=%v", Port(binary.BigEndian.Uint32(p)))
		case OFPXMT_OFB_METADATA:
			if hdr.HasMask() {
				s = fmt.Sprintf("metadata=0x%x/0x%x",
					binary.BigEndian.Uint64(p),
					binary.BigEndian.Uint64(p[8:]))
			} else {
				s = fmt.Sprintf("metadata=0x%x",
					binary.BigEndian.Uint64(p))
			}
		case OFPXMT_OFB_ETH_DST:
			if hdr.HasMask() {
				s = fmt.Sprintf("eth_dst=%v/%v", net.HardwareAddr(p[:6]), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("eth_dst=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_ETH_SRC:
			if hdr.HasMask() {
				s = fmt.Sprintf("eth_src=%v/%v", net.HardwareAddr(p[:6]), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("eth_src=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_ETH_TYPE:
			s = fmt.Sprintf("eth_type=0x%04x", binary.BigEndian.Uint16(p))
		case OFPXMT_OFB_VLAN_VID:
			if hdr.HasMask() {
				s = fmt.Sprintf("vlan_vid=0x%x/0x%x",
					binary.BigEndian.Uint16(p),
					binary.BigEndian.Uint16(p[2:]))
			} else {
				s = fmt.Sprintf("vlan_vid=0x%x",
					binary.BigEndian.Uint16(p))
			}
		case OFPXMT_OFB_VLAN_PCP:
			s = fmt.Sprintf("vlan_pcp=%d", p[0])
		case OFPXMT_OFB_IP_DSCP:
			s = fmt.Sprintf("ip_dscp=0x%x", p[0])
		case OFPXMT_OFB_IP_ECN:
			s = fmt.Sprintf("ip_ecn=0x%x", p[0])
		case OFPXMT_OFB_IP_PROTO:
			s = fmt.Sprintf("ip_proto=%d", p[0])
		case OFPXMT_OFB_IPV4_SRC:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv4_src=%v/%v", net.IP(p[0:4]), net.IP(p[4:8]))
			} else {
				s = fmt.Sprintf("ipv4_src=%v", net.IP(p))
			}
		case OFPXMT_OFB_IPV4_DST:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv4_dst=%v/%v", net.IP(p[0:4]), net.IP(p[4:8]))
			} else {
				s = fmt.Sprintf("ipv4_dst=%v", net.IP(p))
			}
		case OFPXMT_OFB_TCP_SRC:
			s = fmt.Sprintf("tcp_src=%d", binary.BigEndian.Uint16(p))
		case OFPXMT_OFB_TCP_DST:
			s = fmt.Sprintf("tcp_dst=%d", binary.BigEndian.Uint16(p))
		case OFPXMT_OFB_UDP_SRC:
			s = fmt.Sprintf("udp_src=%d", binary.BigEndian.Uint16(p))
		case OFPXMT_OFB_UDP_DST:
			s = fmt.Sprintf("udp_dst=%d", binary.BigEndian.Uint16(p))
		case OFPXMT_OFB_SCTP_SRC:
			s = fmt.Sprintf("sctp_src=%d", binary.BigEndian.Uint16(p))
		case OFPXMT_OFB_SCTP_DST:
			s = fmt.Sprintf("sctp_dst=%d", binary.BigEndian.Uint16(p))
		case OFPXMT_OFB_ICMPV4_TYPE:
			s = fmt.Sprintf("icmpv4_type=%d", p[0])
		case OFPXMT_OFB_ICMPV4_CODE:
			s = fmt.Sprintf("icmpv4_code=%d", p[0])
		case OFPXMT_OFB_ARP_OP:
			s = fmt.Sprintf("arp_op=%d", binary.BigEndian.Uint16(p))
		case OFPXMT_OFB_ARP_SPA:
			if hdr.HasMask() {
				s = fmt.Sprintf("arp_spa=%v/%v", net.IP(p[:4]), net.IP(p[4:]))
			} else {
				s = fmt.Sprintf("arp_spa=%v", net.IP(p))
			}
		case OFPXMT_OFB_ARP_TPA:
			if hdr.HasMask() {
				s = fmt.Sprintf("arp_tpa=%v/%v", net.IP(p[:4]), net.IP(p[4:]))
			} else {
				s = fmt.Sprintf("arp_tpa=%v", net.IP(p))
			}
		case OFPXMT_OFB_ARP_SHA:
			if hdr.HasMask() {
				s = fmt.Sprintf("arp_sha=%v/%v", net.HardwareAddr(p[:6]), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("arp_sha=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_ARP_THA:
			if hdr.HasMask() {
				s = fmt.Sprintf("arp_tha=%v/%v", net.HardwareAddr(p[:6]), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("arp_tha=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_IPV6_SRC:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_src=%v/%v", net.IP(p[:16]), net.IP(p[16:]))
			} else {
				s = fmt.Sprintf("ipv6_src=%v", net.IP(p))
			}
		case OFPXMT_OFB_IPV6_DST:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_dst=%v/%v", net.IP(p[:16]), net.IP(p[16:]))
			} else {
				s = fmt.Sprintf("ipv6_dst=%v", net.IP(p))
			}
		case OFPXMT_OFB_IPV6_FLABEL:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_flabel=0x%x/0x%x",
					binary.BigEndian.Uint32(p),
					binary.BigEndian.Uint32(p[4:]))
			} else {
				s = fmt.Sprintf("ipv6_flabel=0x%x",
					binary.BigEndian.Uint32(p))
			}
		case OFPXMT_OFB_ICMPV6_TYPE:
			s = fmt.Sprintf("icmpv6_type=%d", p[0])
		case OFPXMT_OFB_ICMPV6_CODE:
			s = fmt.Sprintf("icmpv6_code=%d", p[0])
		case OFPXMT_OFB_IPV6_ND_TARGET:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_nd_target=%v/%v", net.IP(p[:16]), net.IP(p[16:]))
			} else {
				s = fmt.Sprintf("ipv6_nd_target=%v", net.IP(p))
			}
		case OFPXMT_OFB_IPV6_ND_SLL:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_nd_sll=%v/%v", net.HardwareAddr(p[:6]), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("ipv6_nd_sll=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_IPV6_ND_TLL:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_nd_tll=%v/%v", net.HardwareAddr(p[:6]), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("ipv6_nd_tll=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_MPLS_LABEL:
			if hdr.HasMask() {
				s = fmt.Sprintf("mpls_label=0x%x/0x%x",
					binary.BigEndian.Uint32(p),
					binary.BigEndian.Uint32(p[4:]))
			} else {
				s = fmt.Sprintf("mpls_label=0x%x",
					binary.BigEndian.Uint32(p))
			}
		case OFPXMT_OFB_MPLS_TC:
			s = fmt.Sprintf("mpls_tc=%d", p[0])
		case OFPXMT_OFB_MPLS_BOS:
			s = fmt.Sprintf("mpls_bos=%d", p[0])
		case OFPXMT_OFB_PBB_ISID:
			s = fmt.Sprintf("pbb_isid=0x%x",
				uint32(p[0])<<16|uint32(p[1])<<8|uint32(p[2]))
		case OFPXMT_OFB_TUNNEL_ID:
			if hdr.HasMask() {
				s = fmt.Sprintf("tunnel_id=0x%x/0x%x",
					binary.BigEndian.Uint64(p),
					binary.BigEndian.Uint64(p[8:]))
			} else {
				s = fmt.Sprintf("tunnel_id=0x%x",
					binary.BigEndian.Uint64(p))
			}
		case OFPXMT_OFB_IPV6_EXTHDR:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_exthdr=0x%x/0x%x",
					binary.BigEndian.Uint16(p),
					binary.BigEndian.Uint16(p[2:]))
			} else {
				s = fmt.Sprintf("ipv6_exthdr=0x%x",
					binary.BigEndian.Uint16(p))
			}
		case OFPXMT_OFB_PBB_UCA:
			s = fmt.Sprintf("pbb_uca=%d", p[0])
		case OFPXMT_OFB_TCP_FLAGS:
			if hdr.HasMask() {
				s = fmt.Sprintf("tcp_flags=0x%04x/0x%04x",
					binary.BigEndian.Uint16(p),
					binary.BigEndian.Uint16(p[2:]))
			} else {
				s = fmt.Sprintf("tcp_flags=0x%04x",
					binary.BigEndian.Uint16(p))
			}
		case OFPXMT_OFB_ACTSET_OUTPUT:
			s = fmt.Sprintf("actset_output=%d",
				binary.BigEndian.Uint32(p))
		case OFPXMT_OFB_PACKET_TYPE:
			s = fmt.Sprintf("packet_type=0x%x:0x%x",
				binary.BigEndian.Uint16(p),
				binary.BigEndian.Uint16(p[2:]))
		}
	case OFPXMC_EXPERIMENTER:
		if handler, ok := stringers[binary.BigEndian.Uint32(oxm[4:])]; ok {
			s = handler.FromOxm(oxm)
		}
	}
	return s
}

func (self *Oxm) Parse(text string) error {
	// xxx
	return nil
}

func parsePair(txt string) (string, string, int) {
	if sep := strings.IndexRune(txt, ','); sep > 0 {
		txt = txt[:sep]
	}
	if split := strings.IndexRune(txt, '/'); split > 0 {
		return txt[:split], txt[split+1:], len(txt)
	} else {
		return txt, "", len(txt)
	}
}

func parseInt(txt string, ptr interface{}) error {
	if n, err := fmt.Sscanf(txt, "0x%x", ptr); err == nil && n == 1 {
		return nil
	} else if n, err := fmt.Sscanf(txt, "%d", ptr); err == nil && n == 1 {
		return nil
	} else {
		return fmt.Errorf("integer capture failed %s", txt)
	}
}

func ParseOne(txt string) (buf []byte, eatLen int, err error) {
	labelIdx := strings.IndexRune(txt, '=')
	if labelIdx > 0 {
		label := txt[:labelIdx]
		args := txt[labelIdx+1:]
		value, mask, baseN := parsePair(args)
		var hdr Header
		nomask := false

		switch label {
		case "vlan_pcp", "ip_dscp", "ip_ecn", "ip_proto",
			"icmpv4_type", "icmpv4_code",
			"mpls_tc", "mpls_bos",
			"pbb_uca":
			switch label {
			case "vlan_pcp":
				hdr = OXM_OF_VLAN_PCP
				nomask = true
			case "ip_dscp":
				hdr = OXM_OF_IP_DSCP
				nomask = true
			case "ip_ecn":
				hdr = OXM_OF_IP_ECN
				nomask = true
			case "ip_proto":
				hdr = OXM_OF_IP_PROTO
				nomask = true
			case "icmpv4_type":
				hdr = OXM_OF_ICMPV4_TYPE
				nomask = true
			case "icmpv4_code":
				hdr = OXM_OF_ICMPV4_CODE
				nomask = true
			case "icmpv6_type":
				hdr = OXM_OF_ICMPV6_TYPE
				nomask = true
			case "icmpv6_code":
				hdr = OXM_OF_ICMPV6_CODE
				nomask = true
			case "mpls_tc":
				hdr = OXM_OF_MPLS_TC
				nomask = true
			case "mpls_bos":
				hdr = OXM_OF_MPLS_BOS
				nomask = true
			case "pbb_uca":
				hdr = OXM_OF_PBB_UCA
				nomask = true
			}
			var v, m uint8
			if err = parseInt(value, &v); err != nil {
				return
			} else if len(mask) == 0 {
				buf = make([]byte, 5)
				buf[4] = v
			} else if err = parseInt(mask, &m); err != nil {
				return
			} else {
				buf = make([]byte, 6)
				buf[4] = v
				buf[5] = m
			}
		case "eth_type", "vlan_vid", "ipv6_exthdr", "tcp_flags",
			"tcp_src", "tcp_dst", "udp_src", "udp_dst", "sctp_src", "sctp_dst", "arp_op":
			switch label {
			case "eth_type":
				hdr = OXM_OF_ETH_TYPE
				nomask = true
			case "vlan_vid":
				hdr = OXM_OF_VLAN_VID
			case "ipv6_exthdr":
				hdr = OXM_OF_IPV6_EXTHDR
			case "tcp_flags":
				hdr = OXM_OF_TCP_FLAGS
			case "tcp_src":
				hdr = OXM_OF_TCP_SRC
				nomask = true
			case "tcp_dst":
				hdr = OXM_OF_TCP_DST
				nomask = true
			case "udp_src":
				hdr = OXM_OF_UDP_SRC
				nomask = true
			case "udp_dst":
				hdr = OXM_OF_UDP_DST
				nomask = true
			case "sctp_src":
				hdr = OXM_OF_SCTP_SRC
				nomask = true
			case "sctp_dst":
				hdr = OXM_OF_SCTP_DST
				nomask = true
			case "arp_op":
				hdr = OXM_OF_ARP_OP
				nomask = true
			}
			var v, m uint16
			if err = parseInt(value, &v); err != nil {
				return
			} else if len(mask) == 0 {
				buf = make([]byte, 6)
				binary.BigEndian.PutUint16(buf[4:], v)
			} else if err = parseInt(mask, &m); err != nil {
				return
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 8)
				binary.BigEndian.PutUint16(buf[4:], v)
				binary.BigEndian.PutUint16(buf[6:], m)
			}
		case "pbb_isid":
			hdr = OXM_OF_PBB_ISID
			var v, m uint32
			if err = parseInt(value, &v); err != nil {
				return
			} else if len(mask) == 0 {
				buf = make([]byte, 7)
				binary.BigEndian.PutUint32(buf[3:], v)
			} else if err = parseInt(mask, &m); err != nil {
				return
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 10)
				binary.BigEndian.PutUint32(buf[6:], m)
				binary.BigEndian.PutUint32(buf[3:], v)
			}
		case "in_port", "in_phy_port":
			switch label {
			case "in_port":
				hdr = OXM_OF_IN_PORT
			case "in_phy_port":
				hdr = OXM_OF_IN_PHY_PORT
			}
			nomask = true
			var port uint32
			switch value {
			case "max":
				port = OFPP_MAX
			case "unset":
				port = OFPP_UNSET
			case "in_port":
				port = OFPP_IN_PORT
			case "table":
				port = OFPP_TABLE
			case "normal":
				port = OFPP_NORMAL
			case "flood":
				port = OFPP_FLOOD
			case "all":
				port = OFPP_ALL
			case "controller":
				port = OFPP_CONTROLLER
			case "local":
				port = OFPP_LOCAL
			case "any":
				port = OFPP_ANY
			default:
				if err = parseInt(value, &port); err != nil {
					return
				}
			}
			buf = make([]byte, 8)
			binary.BigEndian.PutUint32(buf[4:], port)
		case "ipv6_flabel", "mpls_label", "actset_output":
			switch label {
			case "ipv6_flabel":
				hdr = OXM_OF_IPV6_FLABEL
			case "mpls_label":
				hdr = OXM_OF_MPLS_LABEL
			case "actset_output":
				hdr = OXM_OF_ACTSET_OUTPUT
				nomask = true
			}
			var v, m uint32
			if err = parseInt(value, &v); err != nil {
				return
			} else if len(mask) == 0 {
				buf = make([]byte, 8)
				binary.BigEndian.PutUint32(buf[4:], v)
			} else if err = parseInt(mask, &m); err != nil {
				return
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 12)
				binary.BigEndian.PutUint32(buf[4:], v)
				binary.BigEndian.PutUint32(buf[8:], m)
			}
		case "packet_type":
			hdr = OXM_OF_PACKET_TYPE
			nomask = true
			var v [2]uint16
			for i, vs := range strings.SplitN(value, ":", 2) {
				if err = parseInt(vs, &v[i]); err != nil {
					return
				}
			}
			buf = make([]byte, 8)
			binary.BigEndian.PutUint16(buf[4:], v[0])
			binary.BigEndian.PutUint16(buf[6:], v[1])
		case "metadata", "tunnel_id":
			switch label {
			case "metadata":
				hdr = OXM_OF_METADATA
			case "tunnel_id":
				hdr = OXM_OF_TUNNEL_ID
			}
			var v, m uint64
			if err = parseInt(value, &v); err != nil {
				return
			} else if len(mask) == 0 {
				buf = make([]byte, 12)
				binary.BigEndian.PutUint64(buf[4:], v)
			} else if err = parseInt(mask, &m); err != nil {
				return
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 20)
				binary.BigEndian.PutUint64(buf[4:], v)
				binary.BigEndian.PutUint64(buf[12:], m)
			}
		case "eth_dst", "eth_src", "arp_sha", "arp_tha", "ipv6_nd_sll", "ipv6_nd_tll":
			switch label {
			case "eth_dst":
				hdr = OXM_OF_ETH_DST
			case "eth_src":
				hdr = OXM_OF_ETH_SRC
			case "arp_sha":
				hdr = OXM_OF_ARP_SHA
			case "arp_tha":
				hdr = OXM_OF_ARP_THA
			case "ipv6_nd_sll":
				hdr = OXM_OF_IPV6_ND_SLL
			case "ipv6_nd_tll":
				hdr = OXM_OF_IPV6_ND_TLL
			}
			var hw, ma []byte
			if hw, err = net.ParseMAC(value); err != nil {
				return
			} else if len(mask) == 0 {
				buf = make([]byte, 10)
				copy(buf[4:], hw)
			} else if ma, err = net.ParseMAC(mask); err != nil {
				return
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 16)
				copy(buf[4:], hw)
				copy(buf[10:], ma)
			}
		case "ipv4_src", "ipv4_dst", "arp_spa", "arp_tpa":
			switch label {
			case "ipv4_src":
				hdr = OXM_OF_IPV4_SRC
			case "ipv4_dst":
				hdr = OXM_OF_IPV4_DST
			case "arp_spa":
				hdr = OXM_OF_ARP_SPA
			case "arp_tpa":
				hdr = OXM_OF_ARP_TPA
			}
			var hw, nm net.IP
			var nw *net.IPNet
			if hw, nw, err = net.ParseCIDR(args[:baseN]); err == nil {
				hdr.SetMask(true)
				buf = make([]byte, 12)
				copy(buf[4:], hw.To4())

				ones, width := nw.Mask.Size()
				m := make([]byte, width/8)
				for i := 0; i < ones; i++ {
					m[i/8] |= 1 << uint8(7-i%8)
				}
				copy(buf[8:], m)
			} else if hw = net.ParseIP(value); hw == nil {
				err = fmt.Errorf("IP parse error %s %s", args[:baseN], err)
				return
			} else if len(mask) == 0 {
				buf = make([]byte, 8)
				copy(buf[4:], hw.To4())
			} else if nm = net.ParseIP(mask); nm == nil {
				err = fmt.Errorf("ipv4 mask parse error %s", mask)
				return
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 12)
				copy(buf[4:], hw.To4())
				copy(buf[8:], nm.To4())
			}
		case "ipv6_src", "ipv6_dst":
			switch label {
			case "ipv6_src":
				hdr = OXM_OF_IPV6_SRC
			case "ipv6_dst":
				hdr = OXM_OF_IPV6_DST
			case "ipv6_nd_target":
				hdr = OXM_OF_IPV6_ND_TARGET
			}
			var hw, nm net.IP
			var nw *net.IPNet
			if hw, nw, err = net.ParseCIDR(args[:baseN]); err == nil {
				hdr.SetMask(true)
				buf = make([]byte, 36)
				copy(buf[4:], hw.To16())

				ones, width := nw.Mask.Size()
				m := make([]byte, width/8)
				for i := 0; i < ones; i++ {
					m[i/8] |= 1 << uint8(7-i%8)
				}
				copy(buf[20:], m)
			} else if hw = net.ParseIP(value); hw == nil {
				err = fmt.Errorf("IP parse error %s %s", args[:baseN], err)
				return
			} else if len(mask) == 0 {
				buf = make([]byte, 20)
				copy(buf[4:], hw.To16())
			} else if nm = net.ParseIP(mask); nm == nil {
				err = fmt.Errorf("ipv6 mask parse error %s", mask)
				return
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 36)
				copy(buf[4:], hw.To16())
				copy(buf[20:], nm.To16())
			}
		}
		if len(mask) > 0 && nomask {
			err = fmt.Errorf("%s is not maskable", label)
			return
		}
		if len(buf) > 0 {
			hdr.SetLength(len(buf) - 4)
			binary.BigEndian.PutUint32(buf, uint32(hdr))
			return buf, labelIdx + 1 + baseN, nil
		}
	}
	for _, handler := range stringers {
		if buf, eatLen, err = handler.ToOxm(txt); err == nil {
			return
		}
	}
	err = fmt.Errorf("parse failed %s", txt)
	return
}

type Port uint32

func (self Port) String() string {
	switch self {
	case OFPP_MAX:
		return "max"
	case OFPP_UNSET:
		return "unset"
	case OFPP_IN_PORT:
		return "in_port"
	case OFPP_TABLE:
		return "table"
	case OFPP_NORMAL:
		return "normal"
	case OFPP_FLOOD:
		return "flood"
	case OFPP_ALL:
		return "all"
	case OFPP_CONTROLLER:
		return "controller"
	case OFPP_LOCAL:
		return "local"
	case OFPP_ANY:
		return "any"
	default:
		return fmt.Sprintf("%d", uint32(self))
	}
}
