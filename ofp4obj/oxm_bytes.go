package ofp4obj

import (
	"encoding/binary"
)

type OxmBytes []byte

func (self OxmBytes) Header() OxmHeader {
	return OxmHeader(binary.BigEndian.Uint32([]byte(self)))
}

func (self OxmBytes) Iter() <-chan OxmBytes {
	feed := make(chan OxmBytes)
	go func() {
		msg := []byte(self)
		for len(msg) > 4 {
			hdr := OxmHeader(binary.BigEndian.Uint32(msg))
			if hdr == 0 {
				break
			}
			length := hdr.Length()
			if len(msg) < 4+length {
				break
			}
			feed <- OxmBytes(msg[:4+length])
			msg = msg[4+length:]
		}
		close(feed)
	}()
	return feed
}

func (self OxmBytes) Append(params ...OxmBytes) OxmBytes {
	length := len([]byte(self))
	for _, f := range params {
		length += len([]byte(f))
	}
	buf := make([]byte, 0, length)
	for f := range self.Iter() {
		buf = append(buf, []byte(f)...)
	}
	for _, f := range params {
		buf = append(buf, []byte(f)...)
	}
	return OxmBytes(buf)
}

func (self OxmBytes) maskHead() int {
	header := self.Header()
	length := header.Length()
	if header.HasMask() {
		return 4 + length/2
	} else {
		return 4 + length
	}
}

func (self OxmBytes) end() int {
	return 4 + self.Header().Length()
}

func (self OxmBytes) Value() []byte {
	return []byte(self)[4:self.maskHead()]
}

func (self OxmBytes) Mask() []byte {
	return []byte(self)[self.maskHead():self.end()]
}

func (self OxmBytes) Body() []byte {
	return []byte(self)[4:self.end()]
}

func (self OxmBytes) Id() uint32 {
	return self.Header().Type()
}

type OxmExperimenterBytes []byte

func (self OxmExperimenterBytes) Ok() bool {
	if len([]byte(self)) >= 8 && OxmBytes(self).Header().Class() == OFPXMC_EXPERIMENTER {
		return true
	}
	return false
}

func (self OxmExperimenterBytes) Experimenter() uint32 {
	return binary.BigEndian.Uint32([]byte(self)[4:])
}

func (self OxmExperimenterBytes) Body() []byte {
	return []byte(self)[8:OxmBytes(self).end()]
}

// Id returns oxm_id for experimenter oxm.
//
// From ofp_table_feature_prop_oxm description:
// ...The elements of that list are 32-bit OXM headers or 64-bit OXM headers for experimenter OXM fields.
func (self OxmExperimenterBytes) Id() uint64 {
	return uint64(OxmBytes(self).Id())<<32 | uint64(self.Experimenter())
}

// Generic experimenter oxm.
//
// See also openflow 1.3 extension EXT-256.
type OxmGenericBytes []byte

func (self OxmGenericBytes) Ok() bool {
	if len([]byte(self)) >= 10 && OxmExperimenterBytes(self).Ok() {
		return true
	}
	return false
}

func (self OxmGenericBytes) ExpType() uint16 {
	return binary.BigEndian.Uint16([]byte(self)[8:])
}

func (self OxmGenericBytes) maskHead() int {
	header := OxmBytes(self).Header()
	length := header.Length() - 6
	if header.HasMask() {
		return 10 + length/2
	} else {
		return 10 + length
	}
}

func (self OxmGenericBytes) Value() []byte {
	return []byte(self)[10:self.maskHead()]
}

func (self OxmGenericBytes) Mask() []byte {
	return []byte(self)[self.maskHead():OxmBytes(self).end()]
}

func (self OxmGenericBytes) Body() []byte {
	return []byte(self)[10:OxmBytes(self).end()]
}

func (self OxmGenericBytes) Id() [10]byte {
	var ret [10]byte
	binary.BigEndian.PutUint32(ret[:], OxmBytes(self).Header().Type())
	binary.BigEndian.PutUint32(ret[4:], OxmExperimenterBytes(self).Experimenter())
	binary.BigEndian.PutUint16(ret[8:], self.ExpType())
	return ret
}
