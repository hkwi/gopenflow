package ofp4

import (
	"encoding/binary"
)

type Oxm []byte

func (self Oxm) Header() OxmHeader {
	return OxmHeader(binary.BigEndian.Uint32(self))
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
	for cur := 0; cur < len(self); {
		h := Oxm(self[cur:])
		length := h.Header().Length()
		if length > 0 {
			seq = append(seq, h[:length])
			cur += length
		} else {
			break
		}
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

// Generic experimenter oxm.
//
// See also openflow 1.3 extension EXT-256.
type OxmGeneric []byte

func (self OxmGeneric) Ok() bool {
	if len([]byte(self)) >= 10 && OxmExperimenterHeader(self).Ok() {
		return true
	}
	return false
}

func (self OxmGeneric) ExpType() uint16 {
	return binary.BigEndian.Uint16([]byte(self)[8:])
}

func (self OxmGeneric) Value() []byte {
	hdr := Oxm(self).Header()
	length := hdr.Length() - 6
	if hdr.HasMask() {
		return self[10 : 10+length/2]
	} else {
		return self[10 : 10+length]
	}
}

func (self OxmGeneric) Mask() []byte {
	hdr := Oxm(self).Header()
	length := hdr.Length() - 6
	if hdr.HasMask() {
		return self[10+length/2 : 10+length]
	} else {
		return nil
	}
}

func (self OxmGeneric) Body() []byte {
	return self[10 : 4+Oxm(self).Header().Length()]
}

func (self OxmGeneric) Id() [10]byte {
	var ret [10]byte
	binary.BigEndian.PutUint32(ret[:], Oxm(self).Header().Type())
	binary.BigEndian.PutUint32(ret[4:], OxmExperimenterHeader(self).Experimenter())
	binary.BigEndian.PutUint16(ret[8:], self.ExpType())
	return ret
}
