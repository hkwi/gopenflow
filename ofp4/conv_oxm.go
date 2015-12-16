package ofp4

import (
	"encoding/binary"
	"github.com/hkwi/gopenflow/oxm"
)

type Oxm []byte

func (self Oxm) Header() oxm.Header {
	return oxm.Header(binary.BigEndian.Uint32(self))
}

func (self Oxm) Value() []byte {
	hdr := self.Header()
	length := hdr.Length()
	if hdr.HasMask() {
		return self[4 : 4+length/2]
	} else {
		return self[4 : 4+length]
	}
}

func (self Oxm) Mask() []byte {
	hdr := self.Header()
	if hdr.HasMask() {
		length := hdr.Length()
		return self[4+length/2 : 4+length]
	} else {
		return nil
	}
}

func (self Oxm) Body() []byte {
	return self[4 : 4+self.Header().Length()]
}

func (self Oxm) Iter() []Oxm {
	var seq []Oxm
	for cur := 0; cur < len(self)-4; {
		h := Oxm(self[cur:])
		length := h.Header().Length() + 4
		seq = append(seq, h[:length])
		cur += length
	}
	return seq
}

func (self Oxm) SetValue(value, mask []byte) Oxm {
	length := 4 + len(value) + len(mask)
	ret := make([]byte, length)
	copy(ret[:4], self[:4])
	copy(ret[4:], value)
	if len(mask) > 0 {
		copy(ret[4+len(value):], mask)
		ret[2] |= 1
	}
	ret[3] = uint8(length)
	return ret
}

func (self Oxm) Id() uint32 {
	return self.Header().Type()
}

func MakeOxm(oxmType uint32) Oxm {
	self := make([]byte, 4)
	binary.BigEndian.PutUint32(self, oxmType)
	return self
}

type OxmExperimenterHeader []byte

func (self OxmExperimenterHeader) Ok() bool {
	if len(self) >= 8 && Oxm(self).Header().Class() == OFPXMC_EXPERIMENTER {
		return true
	}
	return false
}

func (self OxmExperimenterHeader) Experimenter() uint32 {
	return binary.BigEndian.Uint32([]byte(self)[4:])
}

func (self OxmExperimenterHeader) Body() []byte {
	return self[8 : 4+Oxm(self).Header().Length()]
}

// Id returns oxm_id for experimenter oxm.
//
// From ofp_table_feature_prop_oxm description:
// ...The elements of that list are 32-bit OXM headers or 64-bit OXM headers for experimenter OXM fields.
func (self OxmExperimenterHeader) Id() [2]uint32 {
	return [...]uint32{Oxm(self).Id(), self.Experimenter()}
}

func MakeOxmExperimenterHeader(oxmId [2]uint32) Oxm {
	self := make([]byte, 8)
	copy(self[:4], MakeOxm(oxmId[0]))
	binary.BigEndian.PutUint32(self[4:], oxmId[1])
	return self
}
