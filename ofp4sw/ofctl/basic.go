package main

import (
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"strconv"
	"strings"
	"encoding/binary"
)

func buildBasic(field uint32, vm ValueMask) []byte {
	length := len(vm.Value)+len(vm.Mask)
	
	hdr:=ofp4.OxmHeader(field)
	hdr.SetLength(length)
	if len(vm.Mask) > 0 {
		hdr.SetMask(true)
	}
	buf := make([]byte, 4+length)
	binary.BigEndian.PutUint32(buf, uint32(hdr))
	copy(buf[4:], vm.Value)
	copy(buf[4+len(vm.Value):], vm.Mask)
	return buf
}

var BasicW2M = map[string]func(string) ([]byte,error) {
	"in_port": func(arg string) ([]byte, error) {
		vm := ValueMask{}
		if v, ok := portNames[strings.ToUpper(arg)]; ok {
			vm.Value = intBytes(v)
		} else if v, err := strconv.ParseUint(arg, 0, 32); err != nil {
			return nil, err
		} else {
			vm.Value = intBytes(uint32(v))
		}
		return buildBasic(ofp4.OXM_OF_IN_PORT, vm), nil
	},
	"in_phy_port": func(arg string) ([]byte,error) {
		if v, err := strconv.ParseUint(arg, 0, 32); err != nil {
			return nil,err
		} else {
			return buildBasic(ofp4.OXM_OF_IN_PHY_PORT, ValueMask{
				Value: intBytes(uint32(v)),
			}), nil
		}
	},
	"metadata": func(arg string) ([]byte,error) {
		vm := ValueMask{}
		pair := strings.SplitN(arg, "/", 2)
		if v, err := strconv.ParseUint(pair[0], 0, 64); err != nil {
			return nil, err
		} else {
			vm.Value = intBytes(uint64(v))
		}

		if len(pair) == 2 {
			if v, err := strconv.ParseUint(pair[1], 0, 64); err != nil {
				return nil, err
			} else {
				vm.Mask = intBytes(uint64(v))
			}
		}
		return buildBasic(ofp4.OXM_OF_METADATA, vm), nil
	},
	"eth_dst": gen_mac_oxm(ofp4.OXM_OF_ETH_DST),
	"eth_src": gen_mac_oxm(ofp4.OXM_OF_ETH_SRC),
	"eth_type": func(arg string) ([]byte,error) {
		if v, err := strconv.ParseUint(arg, 0, 16); err != nil {
			return nil, err
		} else {
			return buildBasic(ofp4.OXM_OF_ETH_TYPE, ValueMask{
				Value: intBytes(uint16(v)),
			}), nil
		}
	},
	"vlan_vid": func(arg string) ([]byte,error) {
		pair := strings.SplitN(arg, "/", 2)
		vm := ValueMask{}
		if v, err := strconv.ParseUint(pair[0], 0, 16); err != nil {
			return nil, err
		} else {
			vm.Value = intBytes(uint16(v))
		}
		if len(pair) == 2 {
			if v, err := strconv.ParseUint(pair[1], 0, 16); err != nil {
				return nil,err
			} else {
				vm.Mask = intBytes(uint16(v))
			}
		}
		return buildBasic(ofp4.OXM_OF_VLAN_VID, vm), nil
	},
	"vlan_pcp": func(arg string) ([]byte,error) {
		if v, err := strconv.ParseUint(arg, 0, 8); err != nil {
			return nil, err
		} else {
			return buildBasic(ofp4.OXM_OF_VLAN_PCP, ValueMask{
				Value: intBytes(uint8(v)),
			}), nil
		}
	},
	"ip_dscp": func(arg string) ([]byte, error) {
		if v, err := strconv.ParseUint(arg, 0, 8); err != nil {
			return nil, err
		} else if v < 64 {
			return buildBasic(ofp4.OXM_OF_IP_DSCP, ValueMask{
				Value: intBytes(uint8(v)),
			}), nil
		} else {
			return nil, fmt.Errorf("ip_dscp 0-63")
		}
	},
	"ip_ecn": func(arg string) ([]byte,error) {
		if v, err := strconv.ParseUint(arg, 0, 8); err != nil {
			return nil, err
		} else if v < 4 {
			return buildBasic(ofp4.OXM_OF_IP_ECN, ValueMask{
				Value: intBytes(uint8(v & 0x3)),
			}), nil
		} else {
			return nil, fmt.Errorf("nw_ecn(ip_ecn) 0-3")
		}
	},
	"ip_proto": func(arg string) ([]byte,error) {
		if v, err := strconv.ParseUint(arg, 0, 8); err != nil {
			return nil,err
		} else {
			return buildBasic(ofp4.OXM_OF_IP_PROTO, ValueMask{
				Value: intBytes(uint8(v)),
			}), nil
		}
	},
	"ipv4_src":       gen_v4_oxm(ofp4.OXM_OF_IPV4_SRC),
	"ipv4_dst":       gen_v4_oxm(ofp4.OXM_OF_IPV4_DST),
	"tcp_src":        portFunc(ofp4.OXM_OF_TCP_SRC),
	"tcp_dst":        portFunc(ofp4.OXM_OF_TCP_DST),
	"udp_src":        portFunc(ofp4.OXM_OF_UDP_SRC),
	"udp_dst":        portFunc(ofp4.OXM_OF_UDP_DST),
	"sctp_src":       portFunc(ofp4.OXM_OF_SCTP_SRC),
	"sctp_dst":       portFunc(ofp4.OXM_OF_SCTP_DST),
	"icmp_type":      unsupported,
	"icmp_code":      unsupported,
	"arp_op":         unsupported,
	"arp_spa":        unsupported,
	"arp_tpa":        unsupported,
	"arp_sha":        unsupported,
	"arp_tha":        unsupported,
	"ipv6_src":       unsupported,
	"ipv6_dst":       unsupported,
	"ipv6_flabel":    unsupported,
	"icmpv6_type":    unsupported,
	"icmpv6_code":    unsupported,
	"ipv6_nd_target": unsupported,
	"ipv6_nd_sll":    unsupported,
	"ipv6_nd_tll":    unsupported,
	"mpls_label":     unsupported,
	"mpls_tc":        unsupported,
	"mpls_bos":       unsupported,
	"pbb_isid":       unsupported,
	"ipv6_exthdr":    unsupported,
}

func unsupported(arg string) ([]byte,error) {
	return nil,fmt.Errorf("unsupported")
}

func gen_mac_oxm(field uint32) func(string) ([]byte,error) {
	mac2bytes := func(arg string) ([]byte, error) {
		buf := make([]byte, 6)
		for i, c := range strings.SplitN(arg, ":", 6) {
			if n, err := strconv.ParseUint(c, 16, 8); err != nil {
				return nil, err
			} else {
				buf[i] = uint8(n)
			}
		}
		return buf, nil
	}
	return func(arg string) ([]byte,error) {
		pair := strings.SplitN(arg, "/", 2)

		vm := ValueMask{}
		if v, err := mac2bytes(pair[0]); err != nil {
			return nil,err
		} else {
			vm.Value = v
		}
		if len(pair) == 2 {
			if v, err := mac2bytes(pair[1]); err != nil {
				return nil,err
			} else {
				vm.Mask = v
			}
		}
		return buildBasic(field, vm), nil
	}
}

func gen_v4_oxm(field uint32) func(string) ([]byte,error) {
	dot2bytes := func(arg string) ([]byte, error) {
		buf := make([]byte, 4)
		comp := strings.SplitN(arg, ".", 4)
		if len(comp) != 4 {
			return nil, fmt.Errorf("not dot seq")
		}
		for i, c := range comp {
			if n, err := strconv.ParseUint(c, 10, 8); err != nil {
				return nil, err
			} else {
				buf[i] = uint8(n)
			}
		}
		return buf, nil
	}
	return func(arg string) ([]byte,error) {
		pair := strings.SplitN(arg, "/", 2)
		vm := ValueMask{}

		if v, err := dot2bytes(pair[0]); err != nil {
			return nil,err
		} else {
			vm.Value = v
		}
		if len(pair) == 2 {
			if v, err := dot2bytes(pair[1]); err == nil {
				vm.Mask = v
			} else if n, err := strconv.ParseUint(pair[1], 10, 8); err != nil {
				return nil,err
			} else if n <= 32 {
				vm.Mask = intBytes(uint32(0xffffffff << uint8(32-n)))
			} else {
				return nil,fmt.Errorf("invalid mask %s", arg)
			}
		}
		return buildBasic(field, vm), nil
	}
}

func portFunc(field uint32) func(string) ([]byte,error) {
	return func(arg string) ([]byte,error) {
		vm := ValueMask{}
		pair := strings.SplitN(arg, "/", 2)
		if v, err := strconv.ParseUint(pair[0], 0, 16); err != nil {
			return nil, err
		} else {
			vm.Value = intBytes(uint16(v))
		}

		if len(pair) == 2 {
			if v, err := strconv.ParseUint(pair[0], 0, 16); err != nil {
				return nil,err
			} else {
				vm.Mask = intBytes(uint16(v))
			}
		}
		return buildBasic(field, vm), nil
	}
}

func mac2str(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5])
}
