package ofp4sw

import (
	"bytes"
	"encoding/binary"
	"github.com/hkwi/gopenflow/ofp4"
	"hash/fnv"
)

type match struct {
	Type  uint32
	Value []byte
	// 0 means don't care
	Mask []byte // nil if has_mask==0
}

func (self match) valid() bool {
	m := ofp4.MatchType(self.Type)
	if m.Length() != 0 || m.HasMask() {
		// self.Type must not have lower 9 bits
		return false
	}
	if m.WillMask() {
		if self.Mask == nil {
			return false
		}
		if len(self.Value) != len(self.Mask) {
			return false
		}
	}
	return true
}

func (self match) match(data frame) bool {
	if value, err := data.getValue(self.Type); err == nil {
		if ofp4.MatchType(self.Type).HasMask() {
			if len(value) != len(self.Mask) {
				return false
			}
			value = maskBytes(value, self.Mask)
		}
		return bytes.Equal(value, self.Value)
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

func (self match) matchMatch(wide []match) bool {
	// 'wide' means 'more masked', or 'more wildcarded'
	for _, w := range wide {
		if w.Type == self.Type {
			return bytes.Equal(maskBytes(self.Value, w.Mask), w.Value)
		}
	}
	return true
}

// XXX:
func overlap(f1, f2 []match) bool {
	mask := capMask(f1, f2)
	for _, m := range mask {
		for _, m1 := range f1 {
			if m1.Type == m.Type {
				for _, m2 := range f2 {
					if m2.Type == m.Type {
						return bytes.Equal(maskBytes(m1.Value, m.Mask), maskBytes(m2.Value, m.Mask))
					}
				}
			}
		}
	}
	return true
}

// capMask creates a common match union parameter.
func capMask(f1, f2 []match) []match {
	var ret []match
	for _, m1 := range f1 {
		for _, m2 := range f2 {
			if m1.Type == m2.Type {
				length := len(m1.Value)
				if length > len(m2.Value) {
					length = len(m2.Value)
				}

				value := make([]byte, length)
				mask := make([]byte, length)

				maskFull := true
				for i, _ := range mask {
					mask[i] = 0xFF // exact value
					if m1.Mask != nil && m2.Mask != nil {
						mask[i] = m1.Mask[i] & m2.Mask[i]
					}
					e1 := m1.Value[i] & mask[i]
					e2 := m2.Value[i] & mask[i]
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
						Type:  m1.Type,
						Mask:  mask,
						Value: value,
					})
				}
			}
		}
	}
	return ret
}

func capKey(cap []match, f []match) uint32 {
	hasher := fnv.New32()
	for _, m1 := range cap {
		for _, m2 := range f {
			if m1.Type == m2.Type {
				length := len(m1.Value)
				if length > len(m2.Value) {
					length = len(m2.Value)
				}

				value := make([]byte, length)
				copy(value, m2.Value)
				for i, _ := range value {
					if m1.Mask != nil {
						value[i] &= m1.Mask[i]
					}
					if m2.Mask != nil {
						value[i] &= m2.Mask[i]
					}
				}
				for cur := 0; cur < len(value); {
					n, err := hasher.Write(value[cur:])
					if err != nil {
						panic(err)
					}
					if n == 0 {
						break
					}
					cur += n
				}
			}
		}
	}
	return hasher.Sum32()
}

type matchList []match

func (ms matchList) MarshalBinary() ([]byte, error) {
	var ret []byte
	for _, m := range []match(ms) {
		mt := ofp4.MatchType(m.Type)
		// XXX: may check for OFPXMC_OPENFLOW_BASIC defs.
		length := len(m.Value)
		if m.Mask != nil {
			if length > len(m.Mask) {
				length = len(m.Mask)
			}
			ret = make([]byte, 4+length*2)
			binary.BigEndian.PutUint32(ret, mt.Build(length*2))
			copy(ret[4:], m.Value)
			copy(ret[4+length:], m.Mask)
		} else {
			ret = make([]byte, 4+length)
			binary.BigEndian.PutUint32(ret, mt.Build(length))
			copy(ret[4:], m.Value)
		}
	}
	return ret, nil
}

func (ms *matchList) UnmarshalBinary(s []byte) error {
	var ret []match
	for cur := 0; cur+4 < len(s); {
		mt := ofp4.MatchType(binary.BigEndian.Uint32(s[cur:]))
		length := mt.Length()
		if length == 0 { // this happens at OFPAT_SET_FIELD padding
			break
		} else {
			cur += 4 + length
		}
		m := match{Type: mt.Type()}
		if mt.HasMask() {
			length = length / 2
			m.Value = s[4 : 4+length]
			m.Mask = s[4+length : 4+length*2]
		} else {
			m.Value = s[4 : 4+length]
		}
		ret = append(ret, m)
	}
	*ms = matchList(ret)
	return nil
}

func (self matchList) Len() int {
	return len([]match(self))
}

func (self matchList) Less(i, j int) bool {
	inner := []match(self)
	if inner[i].Type != inner[j].Type {
		return inner[i].Type < inner[j].Type
	}
	if len(inner[i].Value) != len(inner[j].Value) { // should not happen
		return len(inner[i].Value) < len(inner[i].Value)
	}
	if len(inner[i].Mask) != len(inner[j].Mask) {
		return len(inner[i].Mask) < len(inner[i].Mask)
	}
	for k, _ := range inner[i].Value {
		mask := uint8(0xFF)
		if inner[i].Mask != nil {
			mask &= inner[i].Mask[k]
		}
		if inner[j].Mask != nil {
			mask &= inner[j].Mask[k]
		}
		vi := inner[i].Value[k] & mask
		vj := inner[j].Value[k] & mask
		if vi != vj {
			return vi < vj
		}
	}
	if inner[i].Mask != nil && inner[j].Mask != nil {
		for k, _ := range inner[i].Mask {
			if inner[i].Mask[k] != inner[j].Mask[k] {
				return inner[i].Mask[k] > inner[j].Mask[k]
			}
		}
	}
	for k, _ := range inner[i].Value {
		if inner[i].Value[k] != inner[j].Value[k] {
			return inner[i].Value[k] < inner[j].Value[k]
		}
	}
	return false
}

func (self matchList) Swap(i, j int) {
	inner := []match(self)
	inner[i], inner[j] = inner[j], inner[i]
	return
}

func (self matchList) Equal(target matchList) bool {
	a := []match(self)
	b := []match(target)
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		hit := func() bool {
			for _, y := range b {
				if x.Type == x.Type &&
					bytes.Equal(x.Value, y.Value) &&
					bytes.Equal(x.Mask, y.Mask) {
					return true
				}
			}
			return false
		}()
		if !hit {
			return false
		}
	}
	return true
}
