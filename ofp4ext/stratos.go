package ofp4ext

import (
	"bytes"
	"code.google.com/p/gopacket/layers"
	"encoding/binary"
	"fmt"
	"github.com/hkwi/gopenflow"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/hkwi/gopenflow/ofp4sw"
	bytes2 "github.com/hkwi/suppl/bytes"
)

type StratosOxm struct{}

var _ = ofp4sw.OxmHandler(StratosOxm{})

func (self StratosOxm) Parse(buf []byte) map[ofp4sw.OxmKey]ofp4sw.OxmPayload {
	ret := make(map[ofp4sw.OxmKey]ofp4sw.OxmPayload)
	for _,oxm := range ofp4.Oxm(buf).Iter() {
		hdr := oxm.Header()
		if hdr.Class() == ofp4.OFPXMC_EXPERIMENTER {
			exp := ofp4.OxmExperimenterHeader(oxm)
			if exp.Experimenter() == gopenflow.STRATOS_EXPERIMENTER_ID {
				key := OxmKeyStratos{
					Type: binary.BigEndian.Uint16(exp[8:]),
					Field: hdr.Field(),
				}
				length := hdr.Length() - 6
				if hdr.HasMask() {
					ret[key] = ofp4sw.OxmValueMask {
						Value: oxm[6:6+length/2],
						Mask: oxm[6+length/2:],
					}
				} else {
					ret[key] = ofp4sw.OxmValueMask {
						Value: oxm[6:6+length],
					}
				}
			}
		}
	}
	return ret
}

func (self StratosOxm) OxmId(field uint32) uint32 {
	// xxx: will fix up the mask, length field
	return field
}

func (self StratosOxm) Match(data ofp4sw.Frame, key ofp4sw.OxmKey, payload ofp4sw.OxmPayload) (bool, error) {
	switch k:=key.(type){
	case OxmKeyStratos:
		switch k.Field {
		case gopenflow.STRATOS_OXM_FIELD_BASIC:
			p := payload.(ofp4sw.OxmValueMask)
			
			fetch11 := func() *layers.Dot11 {
				for _,layer := range data.Layers() {
					switch l:=layer.(type) {
					case *layers.Dot11:
						return l
					}
				}
				return nil
			}
			
			fetchIeS := func() (ret []Dot11InformationElement) {
				if m := fetch11(); m != nil && m.Type.MainType()==layers.Dot11TypeMgmt {
					ret := Dot11InformationElementList{}
					if err:=ret.UnmarshalBinary(m.Contents); err!=nil {
						return nil
					} else {
						return []Dot11InformationElement(ret)
					}
				}
				return nil
			}
			
			switch k.Type {
			case gopenflow.STROXM_BASIC_DOT11:
				var want uint8
				if len(p.Value) > 0 {
					want = p.Value[0]
				}
				var have uint8
				if v := data.Oob[key].(ofp4sw.OxmValueMask); len(v.Value) > 0 {
					have = v.Value[0]
				}
				return want == have, nil
			case gopenflow.STROXM_BASIC_DOT11_FRAME_CTRL:
				if m := fetch11(); m == nil {
					return false, fmt.Errorf("dot11 missing")
				} else {
					v := []byte{
						uint8(m.Type << 2) | m.Proto,
						uint8(m.Flags),
					}
					if len(p.Mask) > 0 {
						return bytes.Equal(p.Value, bytes2.And(v, p.Mask)), nil
					} else {
						return bytes.Equal(p.Value, v), nil
					}
				}
			case gopenflow.STROXM_BASIC_DOT11_ADDR1:
				if m := fetch11(); m == nil {
					return false, fmt.Errorf("dot11 missing")
				} else {
					if len(p.Mask) > 0 {
						return bytes.Equal(p.Value, bytes2.And([]byte(m.Address1), p.Mask)), nil
					} else {
						return bytes.Equal(p.Value, []byte(m.Address1)), nil
					}
				}
			case gopenflow.STROXM_BASIC_DOT11_ADDR2:
				if m := fetch11(); m == nil {
					return false, fmt.Errorf("dot11 missing")
				} else {
					if len(p.Mask) > 0 {
						return bytes.Equal(p.Value, bytes2.And([]byte(m.Address2), p.Mask)), nil
					} else {
						return bytes.Equal(p.Value, []byte(m.Address2)), nil
					}
				}
			case gopenflow.STROXM_BASIC_DOT11_ADDR3:
				if m := fetch11(); m == nil {
					return false, fmt.Errorf("dot11 missing")
				} else {
					if len(p.Mask) > 0 {
						return bytes.Equal(p.Value, bytes2.And([]byte(m.Address3), p.Mask)), nil
					} else {
						return bytes.Equal(p.Value, []byte(m.Address3)), nil
					}
				}
			case gopenflow.STROXM_BASIC_DOT11_ADDR4:
				if m := fetch11(); m == nil {
					return false, fmt.Errorf("dot11 missing")
				} else {
					if len(p.Mask) > 0 {
						return bytes.Equal(p.Value, bytes2.And([]byte(m.Address4), p.Mask)), nil
					} else {
						return bytes.Equal(p.Value, []byte(m.Address4)), nil
					}
				}
			case gopenflow.STROXM_BASIC_DOT11_TAG:
				for _,l := range fetchIeS() {
					if buf,err:=l.MarshalBinary(); err!=nil {
						continue
					} else if bytes.HasPrefix(buf, p.Value) {
						return true, nil
					}
				}
				return false, nil
			case gopenflow.STROXM_BASIC_DOT11_SSID:
				for _,l := range fetchIeS() {
					if l.Id == 0 {
						if len(p.Mask) > 0 {
							return bytes.Equal(p.Value, bytes2.And(l.Info, p.Mask)), nil
						} else {
							return bytes.Equal(p.Value, l.Info), nil
						}
					}
				}
				return false, nil
			case gopenflow.STROXM_BASIC_DOT11_ACTION_CATEGORY:
				// XXX: HT field handling is missing in gopacket
				if m := fetch11(); m == nil {
					return false, fmt.Errorf("dot11 missing")
				} else if m.Type.MainType() != layers.Dot11TypeMgmt {
					return false, fmt.Errorf("non-management frame")
				} else {
					v := m.Payload[0]
					if len(p.Mask) > 0 {
						v &= p.Mask[0]
					}
					return v == p.Value[0], nil
				}
			case gopenflow.STROXM_BASIC_DOT11_PUBLIC_ACTION:
				if m := fetch11(); m == nil {
					return false, fmt.Errorf("dot11 missing")
				} else if m.Type.MainType() != layers.Dot11TypeMgmt {
					return false, fmt.Errorf("non-management frame")
				} else if m.Payload[0] == 4 { // Public Action
					v := m.Payload[1] // Public Action field value
					if len(p.Mask) > 0 {
						v &= p.Mask[0]
					}
					return v == p.Value[0], nil
				}
			default:
				return false, fmt.Errorf("unsupported oxm experimenter type")
			}
		case gopenflow.STRATOS_OXM_FIELD_RADIOTAP:
			p := payload.(ofp4sw.OxmValueMask)
			
			if v := data.Oob[key].(ofp4sw.OxmValueMask); len(v.Value) > 0 {
				if len(p.Mask) > 0 {
					return bytes.Equal(p.Value, bytes2.And(v.Value, p.Mask)), nil
				} else {
					return bytes.Equal(p.Value, v.Value), nil
				}
			}
		default:
			return false, fmt.Errorf("unsupported oxm experimenter field")
		}
	default:
		return false, fmt.Errorf("unknown oxm key")
	}
	return false, nil
}

func (self StratosOxm) SetField(data *ofp4sw.Frame, key ofp4sw.OxmKey, payload ofp4sw.OxmPayload) error {
	switch k:=key.(type){
	case OxmKeyStratos:
		switch k.Field {
		case gopenflow.STRATOS_OXM_FIELD_BASIC:
			p := payload.(ofp4sw.OxmValueMask)
			
			fetch11 := func() *layers.Dot11 {
				for _,layer := range data.Layers() {
					switch l:=layer.(type) {
					case *layers.Dot11:
						return l
					}
				}
				return nil
			}
			
			fetchIeS := func() (ret []Dot11InformationElement) {
				if m := fetch11(); m != nil && m.Type.MainType()==layers.Dot11TypeMgmt {
					ret := Dot11InformationElementList{}
					if err:=ret.UnmarshalBinary(m.Contents); err!=nil {
						return nil
					} else {
						return []Dot11InformationElement(ret)
					}
				}
				return nil
			}
			
			switch k.Type {
			case gopenflow.STROXM_BASIC_DOT11:
				data.Oob[key] = ofp4sw.OxmValueMask{
					Value: p.Value,
				}
			case gopenflow.STROXM_BASIC_DOT11_FRAME_CTRL:
				if m := fetch11(); m == nil {
					return fmt.Errorf("dot11 missing")
				} else {
					v := []byte{
						uint8(m.Type << 2) | m.Proto,
						uint8(m.Flags),
					}
					v = bytes2.Or(p.Value, bytes2.And(v, p.Mask))
					m.Proto = v[0] & 0x03
					m.Type = layers.Dot11Type(v[0]>>2)
					m.Flags = layers.Dot11Flags(v[1])
				}
			case gopenflow.STROXM_BASIC_DOT11_ADDR1:
				if m := fetch11(); m == nil {
					return fmt.Errorf("dot11 missing")
				} else {
					if len(p.Mask) > 0 {
						m.Address1 = bytes2.Or(p.Value, bytes2.And([]byte(m.Address1), p.Mask))
					} else {
						m.Address1 = p.Value
					}
				}
			case gopenflow.STROXM_BASIC_DOT11_ADDR2:
				if m := fetch11(); m == nil {
					return fmt.Errorf("dot11 missing")
				} else {
					if len(p.Mask) > 0 {
						m.Address2 = bytes2.Or(p.Value, bytes2.And([]byte(m.Address2), p.Mask))
					} else {
						m.Address2 = p.Value
					}
				}
			case gopenflow.STROXM_BASIC_DOT11_ADDR3:
				if m := fetch11(); m == nil {
					return fmt.Errorf("dot11 missing")
				} else {
					if len(p.Mask) > 0 {
						m.Address3 = bytes2.Or(p.Value, bytes2.And([]byte(m.Address3), p.Mask))
					} else {
						m.Address3 = p.Value
					}
				}
			case gopenflow.STROXM_BASIC_DOT11_ADDR4:
				if m := fetch11(); m == nil {
					return fmt.Errorf("dot11 missing")
				} else {
					if len(p.Mask) > 0 {
						m.Address4 = bytes2.Or(p.Value, bytes2.And([]byte(m.Address4), p.Mask))
					} else {
						m.Address4 = p.Value
					}
				}
			case gopenflow.STROXM_BASIC_DOT11_SSID:
				var ret []Dot11InformationElement
				for _,l := range fetchIeS() {
					if l.Id == 0 {
						if len(p.Mask) > 0 {
							l.Info = bytes2.Or(p.Value, bytes2.And(l.Info, p.Mask))
						} else {
							l.Info = p.Value
						}
					}
					ret = append(ret, l)
				}
				if buf, err:=Dot11InformationElementList(ret).MarshalBinary(); err!=nil {
					return err
				} else if m := fetch11(); m == nil {
					return fmt.Errorf("dot11 missing")
				} else {
					m.Contents = buf
				}
			default:
				return fmt.Errorf("unsupported oxm experimenter type")
			}
		case gopenflow.STRATOS_OXM_FIELD_RADIOTAP:
			p := payload.(ofp4sw.OxmValueMask)
			
			if v,ok := data.Oob[key].(ofp4sw.OxmValueMask); !ok {
				data.Oob[key] = payload
			} else if len(p.Mask) > 0{
				v.Value = bytes2.Or(p.Value, bytes2.And(v.Value, p.Mask))
				data.Oob[key] = v
			} else {
				data.Oob[key] = ofp4sw.OxmValueMask{
					Value: p.Value,
				}
			}
		default:
			return fmt.Errorf("unsupported oxm experimenter field")
		}
	default:
		return fmt.Errorf("unknown oxm key")
	}
	return nil
}

func (self StratosOxm) Fit(key ofp4sw.OxmKey, narrow, wide ofp4sw.OxmPayload) (bool, error) {
	n := narrow.(ofp4sw.OxmValueMask)
	w := wide.(ofp4sw.OxmValueMask)
	return bytes.Equal(bytes2.And(n.Value, w.Mask), w.Value), nil
}

func (self StratosOxm) Conflict(key ofp4sw.OxmKey, a, b ofp4sw.OxmPayload) (bool, error) {
	x := a.(ofp4sw.OxmValueMask)
	y := b.(ofp4sw.OxmValueMask)
	mask := bytes2.And(x.Mask, y.Mask)
	return bytes.Equal(bytes2.And(x.Value, mask), bytes2.And(y.Value, mask)), nil
}

func (self StratosOxm) Expand(fields map[ofp4sw.OxmKey]ofp4sw.OxmPayload) error {
	// XXX:
	return nil
}

type OxmKeyStratos struct {
	Type         uint16 // exp_type
	Field        uint8
}

func (self OxmKeyStratos) Bytes(payload ofp4sw.OxmPayload) []byte {
	hdr := ofp4.OxmHeader(ofp4.OFPXMC_EXPERIMENTER<<ofp4.OXM_CLASS_SHIFT | uint32(self.Field)<<ofp4.OXM_FIELD_SHIFT)
	var buf []byte
	setCommon := func(payloadLength int) {
		buf = make([]byte, 10+payloadLength)
		hdr.SetLength(6+payloadLength)
		binary.BigEndian.PutUint32(buf, uint32(hdr))
		binary.BigEndian.PutUint32(buf[4:], uint32(gopenflow.STRATOS_EXPERIMENTER_ID))
		binary.BigEndian.PutUint16(buf[8:], self.Type)
	}
	switch p:=payload.(type){
	case ofp4sw.OxmValueMask:
		setCommon(len(p.Value) + len(p.Mask))
		copy(buf[10:], p.Value)
		copy(buf[10 + len(p.Value):], p.Mask)
	}
	return buf
}
