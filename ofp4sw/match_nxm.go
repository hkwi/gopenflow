package ofp4sw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/hkwi/gopenflow/oxm"
	layers2 "github.com/hkwi/suppl/gopacket/layers"
	"net"
)

type oxmNxm struct{}

func (self oxmNxm) Parse(buf []byte) map[OxmKey]OxmPayload {
	ret := make(map[OxmKey]OxmPayload)
	for _, oxm := range ofp4.Oxm(buf).Iter() {
		hdr := oxm.Header()
		length := hdr.Length()
		if hdr.HasMask() {
			length = length / 2
		}
		switch hdr.Class() {
		case ofp4.OFPXMC_NXM_0, ofp4.OFPXMC_NXM_1:
			ret[OxmKeyBasic(hdr.Type())] = OxmValueMask{
				Value: oxm[4 : 4+length],
				Mask:  oxm[4+length:],
			}
		}
	}
	return ret
}

func nxmDefs(hdr uint32) (length int, mayMask bool) {
	switch oxm.Header(hdr).Type() {
	case NXM_OF_IN_PORT:
		return 2, false
	case NXM_OF_ETH_DST:
		return 6, false
	case NXM_OF_ETH_SRC:
		return 6, false
	case NXM_OF_ETH_TYPE:
		return 2, false
	case NXM_OF_VLAN_TCI:
		return 4, false
	case NXM_OF_IP_TOS:
		return 1, false
	case NXM_OF_IP_PROTO:
		return 1, false
	case NXM_OF_IP_SRC:
		return 4, false
	case NXM_OF_IP_DST:
		return 4, false
	case NXM_OF_TCP_SRC:
		return 2, false
	case NXM_OF_TCP_DST:
		return 2, false
	case NXM_OF_UDP_SRC:
		return 2, false
	case NXM_OF_UDP_DST:
		return 2, false
	case NXM_OF_ICMP_TYPE:
		return 1, false
	case NXM_OF_ICMP_CODE:
		return 1, false
	case NXM_OF_ARP_OP:
		return 2, false
	case NXM_OF_ARP_SPA:
		return 4, false
	case NXM_OF_ARP_TPA:
		return 4, false
	case NXM_NX_REG0:
		return 4, true
	case NXM_NX_REG1:
		return 4, true
	case NXM_NX_REG2:
		return 4, true
	case NXM_NX_REG3:
		return 4, true
	case NXM_NX_REG4:
		return 4, true
	case NXM_NX_REG5:
		return 4, true
	case NXM_NX_REG6:
		return 4, true
	case NXM_NX_REG7:
		return 4, true
	case NXM_NX_TUN_ID:
		return 8, true
	case NXM_NX_ARP_SHA:
		return 6, true
	case NXM_NX_ARP_THA:
		return 6, true
	case NXM_NX_IPV6_SRC:
		return 16, true
	case NXM_NX_IPV6_DST:
		return 16, true
	case NXM_NX_ICMPV6_TYPE:
		return 1, true
	case NXM_NX_ICMPV6_CODE:
		return 1, true
	case NXM_NX_ND_TARGET:
		return 16, true
	case NXM_NX_ND_SLL:
		return 6, true
	case NXM_NX_ND_TLL:
		return 6, true
	case NXM_NX_IP_FRAG:
		return 1, true
	case NXM_NX_IPV6_LABEL:
		return 4, true
	case NXM_NX_IP_ECN:
		return 1, true
	case NXM_NX_IP_TTL:
		return 1, true
	case NXM_NX_TUN_IPV4_SRC:
		return 4, true
	case NXM_NX_TUN_IPV4_DST:
		return 4, true
	case NXM_NX_PKT_MARK:
		return 4, true
	case NXM_NX_TCP_FLAGS:
		return 2, true
	case NXM_NX_DP_HASH:
		return 4, true
	case NXM_NX_RECIRC_ID:
		return 4, true
	case NXM_NX_CONJ_ID:
		return 4, true
	case NXM_NX_TUN_GBP_ID:
		return 2, true
	case NXM_NX_TUN_GBP_FLAGS:
		return 1, true
	default:
		return 0, false
	}
}


func (self oxmNxm) OxmId(id uint32) uint32 {
	length, mask := nxmDefs(id)
	hdr := oxm.Header(id)
	hdr.SetMask(mask)
	if mask {
		hdr.SetLength(length * 2)
	} else {
		hdr.SetLength(length)
	}
	return uint32(hdr)
}

func (self oxmNxm) Match(data Frame, key OxmKey, payload OxmPayload) (bool, error) {
	val := payload.(OxmValueMask)
	switch key {
	case oxm.NXM_NX_TUN_ID:
		if value, err := data.getValue(oxm.OXM_OF_TUNNEL_ID); err!=nil{
			return false, err
		} else {
			return bytes.Equal(maskBytes(value, val.Mask), val.Value), nil
		}
	case oxm.NXM_NX_TUN_IPV4_SRC, oxm.NXM_NX_TUN_IPV4_DST:
		if val, ok := data.Oob[key]; ok && val != nil {
			if v, ok := val.(ofp4sw.OxmValueMask); ok && len(v.Value) > 0 {
				if len(p.Mask) > 0 {
					return bytes.Equal(p.Value, bytes2.And(v.Value, p.Mask)), nil
				} else {
					return bytes.Equal(p.Value, v.Value), nil
				}
			}
		}
	}
	return false, fmt.Errorf("unsupported oxm key")
}

func (self oxmNxm) SetField(data *Frame, key OxmKey, payload OxmPayload) error {
	vm := payload.(OxmValueMask)
	switch key {
	case oxm.NXM_NX_TUN_ID:
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, data.tunnelId)
		if err := vm.Set(buf); err != nil {
			return err
		} else {
			data.tunnelId = binary.BigEndian.Uint64(buf)
		}
		return nil
	case oxm.NXM_NX_TUN_IPV4_SRC, oxm.NXM_NX_TUN_IPV4_DST:
		if val, ok := data.Oob[key]; ok && val != nil {
			if v, ok := val.(OxmValueMask); ok && len(v.Value) > 0 {
				if err := vm.Set(v.Value); err != nil {
					return err
				} else {
					data.Oob[key] = v
				}
			}
		} else {
			data.Oob[key] = OxmValueMask {
				Value: vm.Value,
			}
		}
	}
	return fmt.Errorf("layer not found: %v", m)
}

func (self oxmNxm) Fit(k OxmKey, narrow, wide OxmPayload) (bool, error) {
	n := narrow.(OxmValueMask)
	w := wide.(OxmValueMask)
	return bytes.Equal(maskBytes(n.Value, w.Mask), w.Value), nil
}

func (self oxmNxm) Conflict(k OxmKey, a, b OxmPayload) (bool, error) {
	x := a.(OxmValueMask)
	y := b.(OxmValueMask)
	mask := maskBytes(x.Mask, y.Mask)
	return !bytes.Equal(maskBytes(x.Value, mask), maskBytes(y.Value, mask)), nil
}

func (self oxmNxm) Expand(info map[OxmKey]OxmPayload) error {
	return nil
}

