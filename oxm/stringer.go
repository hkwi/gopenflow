package oxm

import (
	"encoding/binary"
	"fmt"
	"log"
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
			s = fmt.Sprintf("in_port=%d", binary.BigEndian.Uint32(p))
		case OFPXMT_OFB_IN_PHY_PORT:
			s = fmt.Sprintf("in_phy_port=%d", binary.BigEndian.Uint32(p))
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
				s = fmt.Sprintf("eth_dst=%v/%v", net.HardwareAddr(p), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("eth_dst=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_ETH_SRC:
			if hdr.HasMask() {
				s = fmt.Sprintf("eth_src=%v/%v", net.HardwareAddr(p), net.HardwareAddr(p[6:]))
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
				s = fmt.Sprintf("ipv4_src=%v", net.IP(p[0:4]))
			}
		case OFPXMT_OFB_IPV4_DST:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv4_dst=%v/%v", net.IP(p[0:4]), net.IP(p[4:8]))
			} else {
				s = fmt.Sprintf("ipv4_dst=%v", net.IP(p[0:4]))
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
				s = fmt.Sprintf("arp_spa=%v/%v", net.IP(p), net.IP(p[4:]))
			} else {
				s = fmt.Sprintf("arp_spa=%v", net.IP(p))
			}
		case OFPXMT_OFB_ARP_TPA:
			if hdr.HasMask() {
				s = fmt.Sprintf("arp_tpa=%v/%v", net.IP(p), net.IP(p[4:]))
			} else {
				s = fmt.Sprintf("arp_tpa=%v", net.IP(p))
			}
		case OFPXMT_OFB_ARP_SHA:
			if hdr.HasMask() {
				s = fmt.Sprintf("arp_sha=%v/%v", net.HardwareAddr(p), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("arp_sha=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_ARP_THA:
			if hdr.HasMask() {
				s = fmt.Sprintf("arp_tha=%v/%v", net.HardwareAddr(p), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("arp_tha=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_IPV6_SRC:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_src=%v/%v", net.IP(p), net.IP(p[16:]))
			} else {
				s = fmt.Sprintf("ipv6_src=%v", net.IP(p))
			}
		case OFPXMT_OFB_IPV6_DST:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_dst=%v/%v", net.IP(p), net.IP(p[16:]))
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
				s = fmt.Sprintf("ipv6_nd_target=%v/%v", net.IP(p), net.IP(p[16:]))
			} else {
				s = fmt.Sprintf("ipv6_nd_target=%v", net.IP(p))
			}
		case OFPXMT_OFB_IPV6_ND_SLL:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_nd_sll=%v/%v", net.HardwareAddr(p), net.HardwareAddr(p[6:]))
			} else {
				s = fmt.Sprintf("ipv6_nd_sll=%v", net.HardwareAddr(p))
			}
		case OFPXMT_OFB_IPV6_ND_TLL:
			if hdr.HasMask() {
				s = fmt.Sprintf("ipv6_nd_tll=%v/%v", net.HardwareAddr(p), net.HardwareAddr(p[6:]))
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
				binary.BigEndian.Uint32(p))
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
		return fmt.Errorf("integer capture failed")
	}
}

func ParseOne(txt string) ([]byte, int, error) {
	labelIdx := strings.IndexRune(txt, '=')
	if labelIdx > 0 {
		label := txt[:labelIdx]
		args := txt[labelIdx+1:]
		value, mask, baseN := parsePair(args)

		var hdr Header
		var buf []byte

		switch label {
		case "in_port", "in_phy_port":
			switch label {
			case "in_port":
				hdr = OXM_OF_IN_PORT
			case "in_phy_port":
				hdr = OXM_OF_IN_PHY_PORT
			}
			if len(mask) != 0 {
				return nil, 0, fmt.Errorf("in_port/in_phy_port not maskable")
			}
			var port uint32
			if err := parseInt(value, &port); err != nil {
				return nil, 0, err
			} else {
				buf = make([]byte, 8)
				binary.BigEndian.PutUint32(buf[4:], port)
			}
		case "metadata", "tunnel_id":
			switch label {
			case "metadata":
				hdr = OXM_OF_METADATA
			case "tunnel_id":
				hdr = OXM_OF_TUNNEL_ID
			}
			var v, m uint64
			if err := parseInt(value, &v); err != nil {
				return nil, 0, err
			} else if len(mask) == 0 {
				buf = make([]byte, 12)
				binary.BigEndian.PutUint64(buf[4:], v)
			} else if err := parseInt(mask, &m); err != nil {
				return nil, 0, err
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 20)
				binary.BigEndian.PutUint64(buf[4:], v)
				binary.BigEndian.PutUint64(buf[12:], m)
				log.Print(v, m)
			}
			log.Print(buf)
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
			if hw, err := net.ParseMAC(value); err != nil {
				return nil, 0, err
			} else if len(mask) == 0 {
				buf = make([]byte, 10)
				copy(buf[4:], hw)
			} else if ma, err := net.ParseMAC(mask); err != nil {
				return nil, 0, err
			} else {
				buf = make([]byte, 16)
				copy(buf[4:], hw)
				copy(buf[10:], ma)
			}
		case "eth_type":
			if len(mask) > 0 {
				return nil, 0, fmt.Errorf("eth_type not maskable")
			}
			var v uint16
			if err := parseInt(value, &v); err != nil {
				return nil, 0, err
			} else {
				buf = make([]byte, 6)
				binary.BigEndian.PutUint16(buf[4:], v)
			}
		case "vlan_vid", "ipv6_exthdr":
			switch label {
			case "vlan_vid":
				hdr = OXM_OF_VLAN_VID
			case "ipv6_exthdr":
				hdr = OXM_OF_IPV6_EXTHDR
			}
			var v, m uint16
			if err := parseInt(value, &v); err != nil {
				return nil, 0, err
			} else if len(mask) == 0 {
				buf = make([]byte, 6)
				binary.BigEndian.PutUint16(buf[4:], v)
			} else if err := parseInt(mask, &m); err != nil {
				return nil, 0, err
			} else {
				buf = make([]byte, 8)
				binary.BigEndian.PutUint16(buf[4:], v)
				binary.BigEndian.PutUint16(buf[6:], m)
			}
		case "vlan_pcp", "ip_dscp", "ip_ecn", "ip_proto", "icmpv4_type", "icmpv4_code", "mpls_tc", "mpls_bos":
			switch label {
			case "vlan_pcp":
				hdr = OXM_OF_VLAN_PCP
			case "ip_dscp":
				hdr = OXM_OF_IP_DSCP
			case "ip_ecn":
				hdr = OXM_OF_IP_ECN
			case "ip_proto":
				hdr = OXM_OF_IP_PROTO
			case "icmpv4_type":
				hdr = OXM_OF_ICMPV4_TYPE
			case "icmpv4_code":
				hdr = OXM_OF_ICMPV4_CODE
			case "icmpv6_type":
				hdr = OXM_OF_ICMPV6_TYPE
			case "icmpv6_code":
				hdr = OXM_OF_ICMPV6_CODE
			case "mpls_tc":
				hdr = OXM_OF_MPLS_TC
			case "mpls_bos":
				hdr = OXM_OF_MPLS_BOS
			}
			if len(mask) > 0 {
				return nil, 0, fmt.Errorf("not maskable")
			}
			var v uint8
			if err := parseInt(value, &v); err != nil {
				return nil, 0, err
			} else {
				buf = make([]byte, 5)
				buf[4] = v
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
			if hw, nw, err := net.ParseCIDR(args[:baseN]); err == nil {
				hdr.SetMask(true)
				buf = make([]byte, 12)
				copy(buf[4:], hw.To4())

				ones, width := nw.Mask.Size()
				m := make([]byte, width/8)
				for i := 0; i < ones; i++ {
					m[i/8] |= 1 << uint8(7-i%8)
				}
				copy(buf[8:], m)
			} else if hw := net.ParseIP(value); hw == nil {
				return nil, 0, fmt.Errorf("IP parse error %s %s", args[:baseN], err)
			} else if len(mask) == 0 {
				buf = make([]byte, 8)
				copy(buf[4:], hw.To4())
			} else if nw := net.ParseIP(mask); nw == nil {
				return nil, 0, fmt.Errorf("mask parse error %s", mask)
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 12)
				copy(buf[4:], hw.To4())
				copy(buf[8:], nw.To4())
			}
		case "tcp_src", "tcp_dst", "udp_src", "udp_dst", "sctp_src", "sctp_dst", "arp_op":
			if len(mask) > 0 {
				return nil, 0, fmt.Errorf("%s not maskable", label)
			}
			switch label {
			case "tcp_src":
				hdr = OXM_OF_TCP_SRC
			case "tcp_dst":
				hdr = OXM_OF_TCP_DST
			case "udp_src":
				hdr = OXM_OF_UDP_SRC
			case "udp_dst":
				hdr = OXM_OF_UDP_DST
			case "sctp_src":
				hdr = OXM_OF_SCTP_SRC
			case "sctp_dst":
				hdr = OXM_OF_SCTP_DST
			case "arp_op":
				hdr = OXM_OF_ARP_OP
			}
			var v uint16
			if err := parseInt(value, &v); err != nil {
				return nil, 0, err
			} else {
				buf = make([]byte, 6)
				binary.BigEndian.PutUint16(buf[4:], v)
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
			if hw, nw, err := net.ParseCIDR(args[:baseN]); err == nil {
				hdr.SetMask(true)
				buf = make([]byte, 36)
				copy(buf[4:], hw.To16())

				ones, width := nw.Mask.Size()
				m := make([]byte, width/8)
				for i := 0; i < ones; i++ {
					m[i/8] |= 1 << uint8(7-i%8)
				}
				copy(buf[20:], m)
			} else if hw := net.ParseIP(value); hw == nil {
				return nil, 0, fmt.Errorf("IP parse error %s %s", args[:baseN], err)
			} else if len(mask) == 0 {
				buf = make([]byte, 20)
				copy(buf[4:], hw.To16())
			} else if nw := net.ParseIP(mask); nw == nil {
				return nil, 0, fmt.Errorf("mask parse error %s", mask)
			} else {
				hdr.SetMask(true)
				buf = make([]byte, 36)
				copy(buf[4:], hw.To16())
				copy(buf[20:], nw.To16())
			}
		case "ipv6_flabel", "mpls_label":
			switch label {
			case "ipv6_flabel":
				hdr = OXM_OF_IPV6_FLABEL
			case "mpls_label":
				hdr = OXM_OF_MPLS_LABEL
			}

			var v, m uint32
			if err := parseInt(value, &v); err != nil {
				return nil, 0, err
			} else if len(mask) == 0 {
				buf = make([]byte, 8)
				binary.BigEndian.PutUint32(buf[4:], v)
			} else if err := parseInt(mask, &m); err != nil {
				return nil, 0, err
			} else {
				buf = make([]byte, 12)
				binary.BigEndian.PutUint32(buf[4:], v)
				binary.BigEndian.PutUint32(buf[8:], m)
			}
		case "pbb_isid":
			hdr = OXM_OF_PBB_ISID

			var v, m uint32
			if err := parseInt(value, &v); err != nil {
				return nil, 0, err
			} else if len(mask) == 0 {
				buf = make([]byte, 7)
				binary.BigEndian.PutUint32(buf[3:], v)
			} else if err := parseInt(mask, &m); err != nil {
				return nil, 0, err
			} else {
				buf = make([]byte, 10)
				binary.BigEndian.PutUint32(buf[6:], m)
				binary.BigEndian.PutUint32(buf[3:], v)
			}
		}
		if len(buf) > 0 {
			hdr.SetLength(len(buf) - 4)
			binary.BigEndian.PutUint32(buf, uint32(hdr))
			return buf, labelIdx + 1 + baseN, nil
		}
	}
	for _, handler := range stringers {
		if buf, n, err := handler.ToOxm(txt); err == nil {
			return buf, n, nil
		}
	}
	return nil, 0, fmt.Errorf("parse failed %s", txt)
}
