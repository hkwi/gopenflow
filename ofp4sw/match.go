package ofp4sw

import (
	"bytes"
	"encoding/binary"
	"github.com/hkwi/gopenflow/ofp4"
	"hash/fnv"
	"log"
)

type match struct {
	field uint64
	mask  []byte
	value []byte
}

func (m match) match(data frame) bool {
	if value, err := data.getValue(m); err == nil {
		if bytes.Compare(maskBytes(value, m.mask), m.value) == 0 {
			return true
		}
	}
	return false
}

func maskBytes(value, mask []byte) []byte {
	ret := make([]byte, len(value))
	for i, _ := range ret {
		ret[i] = value[i] & mask[i]
	}
	return ret
}

func (m match) matchMatch(wide []match) bool {
	for _, w := range wide {
		if w.field == m.field {
			if bytes.Compare(maskBytes(m.value, w.mask), maskBytes(w.value, w.mask)) == 0 {
				return true
			} else {
				return false
			}
		}
	}
	return true
}

func overlap(f1, f2 []match) bool {
	mask := capMask(f1, f2)
	for _, m := range mask {
		for _, m1 := range f1 {
			if m1.field == m.field {
				for _, m2 := range f2 {
					if m2.field == m.field {
						if bytes.Compare(maskBytes(m1.value, m.mask), maskBytes(m2.value, m.mask)) != 0 {
							return false
						}
					}
				}
			}
		}
	}
	return true
}

func capMask(f1, f2 []match) []match {
	var ret []match
	for _, m1 := range f1 {
		for _, m2 := range f2 {
			if m1.field == m2.field {
				maskFull := true
				mask := make([]byte, len(m1.mask))
				value := make([]byte, len(m1.mask))
				for i, _ := range mask {
					mask[i] = m1.mask[i] & m2.mask[i]
					e1 := m1.value[i] & mask[i]
					e2 := m2.value[i] & mask[i]
					if e1 != e2 {
						mask[i] ^= e1 ^ e2
						value[i] = (e1 & e2) &^ (e1 ^ e2)
					}
					if mask[i] != 0 {
						maskFull = false
					}
				}
				if !maskFull {
					ret = append(ret, match{
						field: m1.field,
						mask:  mask,
						value: value,
					})
				}
			}
		}
	}
	return ret
}

func capKey(cap []match, f []match) uint32 {
	var buf []byte
	for _, m1 := range cap {
		for _, m2 := range f {
			if m1.field == m2.field {
				value := make([]byte, len(m2.value))
				for i, _ := range value {
					value[i] = m2.value[i] & (m1.mask[i] & m2.mask[i])
				}
				buf = append(buf, value...)
			}
		}
	}
	hasher := fnv.New32()
	if _, err := hasher.Write(buf); err != nil {
		return 0
	}
	return hasher.Sum32()
}

type matchList []match

func (ms matchList) MarshalBinary() ([]byte, error) {
	var ret []byte
	for _, m := range []match(ms) {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], 0x8000)
		if ofp4.OxmHaveMask(uint16(m.field)) {
			hdr[2] = uint8(m.field)<<1 | uint8(1)
			hdr[3] = uint8(len(m.value) + len(m.mask))
			ret = append(ret, hdr...)
			ret = append(ret, m.value...)
			ret = append(ret, m.mask...)
		} else {
			hdr[2] = uint8(m.field<<1) | uint8(0)
			hdr[3] = uint8(len(m.value))
			ret = append(ret, hdr...)
			ret = append(ret, m.value...)
		}
	}
	return ret, nil
}

func (ms *matchList) UnmarshalBinary(s []byte) error {
	var ret []match
	for cur := 0; cur+4 < len(s); {
		length := int(s[cur+3])
		if length == 0 { // OFPAT_SET_FIELD has padding
			break
		}
		if binary.BigEndian.Uint16(s[cur:cur+2]) == 0x8000 {
			m := match{}
			m.field = uint64(s[cur+2] >> 1)
			if s[cur+2]&0x01 == 0 {
				m.value = s[cur+4 : cur+4+length]
				m.mask = make([]byte, length)
				for i, _ := range m.mask {
					m.mask[i] = 0xFF
				}
			} else {
				m.value = s[cur+4 : cur+4+length/2]
				m.mask = s[cur+4+length/2 : cur+4+length]
			}
			ret = append(ret, m)
		} else {
			log.Print("oxm_class", s[cur:])
		}
		cur += 4 + length
	}
	*ms = matchList(ret)
	return nil
}
