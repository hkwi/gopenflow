package ofp4ext

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/hkwi/gopenflow/ofp4sw"
	"github.com/hkwi/gopenflow/oxm"
	bytes2 "github.com/hkwi/suppl/bytes"
)

type StratosOxm struct{}

var _ = ofp4sw.OxmHandler(StratosOxm{})

func useOxmMultiValue(key ofp4sw.OxmKey) bool {
	if k, ok := key.(OxmKeyStratos); ok {
		switch k {
		case oxm.STROXM_BASIC_DOT11_TAG, oxm.STROXM_BASIC_DOT11_TAG_VENDOR:
			return true
		}
	}
	return false
}

func (self StratosOxm) Parse(buf []byte) map[ofp4sw.OxmKey]ofp4sw.OxmPayload {
	ret := make(map[ofp4sw.OxmKey]ofp4sw.OxmPayload)
	for _, oxmbuf := range oxm.Oxm(buf).Iter() {
		hdr := oxmbuf.Header()
		if hdr.Class() == ofp4.OFPXMC_EXPERIMENTER {
			exp := ofp4.OxmExperimenterHeader(oxmbuf)
			if exp.Experimenter() == oxm.STRATOS_EXPERIMENTER_ID {
				key := OxmKeyStratos(hdr.Field())
				length := hdr.Length() - 4
				if useOxmMultiValue(key) {
					payload := OxmMultiValue{}
					if p, ok := ret[key]; ok {
						payload = p.(OxmMultiValue)
					}
					payload.Values = append(payload.Values, oxmbuf[8:8+length])
					ret[key] = payload
				} else {
					if hdr.HasMask() {
						ret[key] = ofp4sw.OxmValueMask{
							Value: oxmbuf[8 : 8+length/2],
							Mask:  oxmbuf[8+length/2:],
						}
					} else {
						ret[key] = ofp4sw.OxmValueMask{
							Value: oxmbuf[8 : 8+length],
						}
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
	switch k := key.(type) {
	case OxmKeyStratos:
		fetch11 := func() *layers.Dot11 {
			for _, layer := range data.Layers() {
				switch l := layer.(type) {
				case *layers.Dot11:
					return l
				}
			}
			return nil
		}

		fetchIeList := func() (ret []*layers.Dot11InformationElement) {
			for _, layer := range data.Layers() {
				switch l := layer.(type) {
				case *layers.Dot11InformationElement:
					ret = append(ret, l)
				}
			}
			return
		}

		switch k {
		case oxm.STROXM_BASIC_DOT11:
			p := payload.(ofp4sw.OxmValueMask)
			var want uint8
			if len(p.Value) > 0 {
				want = p.Value[0]
			}
			var have uint8
			if val, ok := data.Oob[key]; ok && val != nil {
				if v, ok := val.(ofp4sw.OxmValueMask); ok && len(v.Value) > 0 {
					have = v.Value[0]
				}
			}
			switch want {
			case 1:
				return have == 1, nil
			case 2:
				return have != 1, nil
			default:
				return true, nil
			}
		case oxm.STROXM_BASIC_DOT11_FRAME_CTRL:
			if m := fetch11(); m != nil {
				p := payload.(ofp4sw.OxmValueMask)
				v := []byte{
					uint8(m.Type<<2) | m.Proto,
					uint8(m.Flags),
				}
				if len(p.Mask) > 0 {
					return bytes.Equal(p.Value, bytes2.And(v, p.Mask)), nil
				} else {
					return bytes.Equal(p.Value, v), nil
				}
			}
		case oxm.STROXM_BASIC_DOT11_ADDR1:
			if m := fetch11(); m != nil {
				p := payload.(ofp4sw.OxmValueMask)
				if len(p.Mask) > 0 {
					return bytes.Equal(p.Value, bytes2.And([]byte(m.Address1), p.Mask)), nil
				} else {
					return bytes.Equal(p.Value, []byte(m.Address1)), nil
				}
			}
		case oxm.STROXM_BASIC_DOT11_ADDR2:
			if m := fetch11(); m != nil {
				p := payload.(ofp4sw.OxmValueMask)
				if len(p.Mask) > 0 {
					return bytes.Equal(p.Value, bytes2.And([]byte(m.Address2), p.Mask)), nil
				} else {
					return bytes.Equal(p.Value, []byte(m.Address2)), nil
				}
			}
		case oxm.STROXM_BASIC_DOT11_ADDR3:
			if m := fetch11(); m != nil {
				p := payload.(ofp4sw.OxmValueMask)
				if len(p.Mask) > 0 {
					return bytes.Equal(p.Value, bytes2.And([]byte(m.Address3), p.Mask)), nil
				} else {
					return bytes.Equal(p.Value, []byte(m.Address3)), nil
				}
			}
		case oxm.STROXM_BASIC_DOT11_ADDR4:
			if m := fetch11(); m != nil {
				p := payload.(ofp4sw.OxmValueMask)
				if len(p.Mask) > 0 {
					return bytes.Equal(p.Value, bytes2.And([]byte(m.Address4), p.Mask)), nil
				} else {
					return bytes.Equal(p.Value, []byte(m.Address4)), nil
				}
			}
		case oxm.STROXM_BASIC_DOT11_SSID:
			for _, l := range fetchIeList() {
				if l.ID == 0 {
					p := payload.(ofp4sw.OxmValueMask)
					if len(p.Mask) > 0 {
						return bytes.Equal(p.Value, bytes2.And(l.Info, p.Mask)), nil
					} else {
						return bytes.Equal(p.Value, l.Info), nil
					}
				}
			}
			return false, nil
		case oxm.STROXM_BASIC_DOT11_ACTION_CATEGORY:
			// XXX: HT field handling is missing in gopacket
			if m := fetch11(); m != nil && m.Type.MainType() == layers.Dot11TypeMgmt {
				p := payload.(ofp4sw.OxmValueMask)
				return bytes.HasPrefix(m.Payload, p.Value), nil
			}
		case oxm.STROXM_BASIC_DOT11_PUBLIC_ACTION:
			if m := fetch11(); m != nil && m.Type.MainType() == layers.Dot11TypeMgmt && m.Payload[0] == 4 { // Public Action
				p := payload.(ofp4sw.OxmValueMask)
				v := m.Payload[1] // Public Action field value
				if len(p.Mask) > 0 {
					v &= p.Mask[0]
				}
				return v == p.Value[0], nil
			}
		case oxm.STROXM_BASIC_DOT11_TAG:
			ies := fetchIeList()
			for _, v := range payload.(OxmMultiValue).Values {
				for _, ie := range ies {
					if v[0] == uint8(ie.ID) {
						return true, nil
					}
				}
			}
			return false, nil
		case oxm.STROXM_BASIC_DOT11_TAG_VENDOR:
			ies := fetchIeList()
			for _, v := range payload.(OxmMultiValue).Values {
				for _, ie := range ies {
					if ie.ID == 221 && bytes.HasPrefix(ie.OUI, v) {
						return true, nil
					}
				}
			}
			return false, nil
		default:
			p := payload.(ofp4sw.OxmValueMask)
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
	default:
		return false, fmt.Errorf("unknown oxm key")
	}
	return false, nil
}

func (self StratosOxm) SetField(data *ofp4sw.Frame, key ofp4sw.OxmKey, payload ofp4sw.OxmPayload) error {
	switch k := key.(type) {
	case OxmKeyStratos:
		p := payload.(ofp4sw.OxmValueMask)

		fetch11 := func() *layers.Dot11 {
			for _, layer := range data.Layers() {
				switch l := layer.(type) {
				case *layers.Dot11:
					return l
				}
			}
			return nil
		}

		fetchIeList := func() (ret []*layers.Dot11InformationElement) {
			for _, layer := range data.Layers() {
				switch l := layer.(type) {
				case *layers.Dot11InformationElement:
					ret = append(ret, l)
				}
			}
			return
		}

		switch k {
		case oxm.STROXM_BASIC_DOT11:
			data.Oob[key] = ofp4sw.OxmValueMask{
				Value: p.Value,
			}
		case oxm.STROXM_BASIC_DOT11_FRAME_CTRL:
			if m := fetch11(); m != nil {
				v := []byte{
					uint8(m.Type<<2) | m.Proto,
					uint8(m.Flags),
				}
				v = bytes2.Or(p.Value, bytes2.And(v, p.Mask))
				m.Proto = v[0] & 0x03
				m.Type = layers.Dot11Type(v[0] >> 2)
				m.Flags = layers.Dot11Flags(v[1])
			}
		case oxm.STROXM_BASIC_DOT11_ADDR1:
			if m := fetch11(); m != nil {
				if len(p.Mask) > 0 {
					m.Address1 = bytes2.Or(p.Value, bytes2.And([]byte(m.Address1), p.Mask))
				} else {
					m.Address1 = p.Value
				}
			}
		case oxm.STROXM_BASIC_DOT11_ADDR2:
			if m := fetch11(); m != nil {
				if len(p.Mask) > 0 {
					m.Address2 = bytes2.Or(p.Value, bytes2.And([]byte(m.Address2), p.Mask))
				} else {
					m.Address2 = p.Value
				}
			}
		case oxm.STROXM_BASIC_DOT11_ADDR3:
			if m := fetch11(); m != nil {
				if len(p.Mask) > 0 {
					m.Address3 = bytes2.Or(p.Value, bytes2.And([]byte(m.Address3), p.Mask))
				} else {
					m.Address3 = p.Value
				}
			}
		case oxm.STROXM_BASIC_DOT11_ADDR4:
			if m := fetch11(); m != nil {
				if len(p.Mask) > 0 {
					m.Address4 = bytes2.Or(p.Value, bytes2.And([]byte(m.Address4), p.Mask))
				} else {
					m.Address4 = p.Value
				}
			}
		case oxm.STROXM_BASIC_DOT11_SSID:
			for _, l := range fetchIeList() {
				if l.ID == 0 {
					if len(p.Mask) > 0 {
						l.Info = bytes2.Or(p.Value, bytes2.And(l.Info, p.Mask))
					} else {
						l.Info = p.Value
					}
				}
			}
		default: // should be STROXM_RADIOTAP_*
			p := payload.(ofp4sw.OxmValueMask)

			if v, ok := data.Oob[key].(ofp4sw.OxmValueMask); !ok {
				data.Oob[key] = payload
			} else if len(p.Mask) > 0 {
				v.Value = bytes2.Or(p.Value, bytes2.And(v.Value, p.Mask))
				data.Oob[key] = v
			} else {
				data.Oob[key] = ofp4sw.OxmValueMask{
					Value: p.Value,
				}
			}
		}
	default:
		return fmt.Errorf("unknown oxm key")
	}
	return nil
}

func (self StratosOxm) Fit(key ofp4sw.OxmKey, narrow, wide ofp4sw.OxmPayload) (bool, error) {
	if useOxmMultiValue(key) {
		n := narrow.(OxmMultiValue)
		w := wide.(OxmMultiValue)
		for _, wv := range w.Values {
			if missing := func() bool {
				for _, nv := range n.Values {
					if bytes.HasPrefix(nv, wv) {
						return false
					}
				}
				return true
			}(); missing {
				return false, nil
			}
		}
		return true, nil
	} else {
		n := narrow.(ofp4sw.OxmValueMask)
		w := wide.(ofp4sw.OxmValueMask)

		if skey, ok := key.(OxmKeyStratos); ok && skey == oxm.STROXM_BASIC_DOT11 {
			var nval, wval uint8
			if len(n.Value) > 0 {
				nval = n.Value[0]
			}
			if len(w.Value) > 0 {
				wval = w.Value[0]
			}
			switch wval {
			default:
				return true, nil
			case 1:
				return nval == 1, nil
			case 2:
				return nval != 1, nil
			}
		}

		mask := make([]byte, len(w.Value))
		for i, _ := range mask {
			mask[i] = 0xFF
		}
		if len(w.Mask) > 0 {
			mask = bytes2.And(mask, w.Mask)
		}
		if len(n.Mask) > 0 {
			mask = bytes2.And(mask, n.Mask)
		}
		return bytes.Equal(bytes2.And(n.Value, mask), w.Value), nil
	}
}

func (self StratosOxm) Conflict(key ofp4sw.OxmKey, a, b ofp4sw.OxmPayload) (bool, error) {
	if useOxmMultiValue(key) {
		// does not conflict by syntax
		return false, nil
	} else {
		x := a.(ofp4sw.OxmValueMask)
		y := b.(ofp4sw.OxmValueMask)

		if skey, ok := key.(OxmKeyStratos); ok && skey == oxm.STROXM_BASIC_DOT11 {
			var xval, yval uint8
			if len(x.Value) > 0 {
				xval = x.Value[0]
			}
			if len(y.Value) > 0 {
				yval = y.Value[0]
			}
			switch {
			case xval == 1 && yval == 2:
				return true, nil
			case xval == 2 && yval == 1:
				return true, nil
			default:
				return false, nil
			}
		}

		mask := bytes2.And(x.Mask, y.Mask)
		return bytes.Equal(bytes2.And(x.Value, mask), bytes2.And(y.Value, mask)), nil
	}
}

func (self StratosOxm) Expand(fields map[ofp4sw.OxmKey]ofp4sw.OxmPayload) error {
	for key, _ := range fields {
		switch k := key.(type) {
		case OxmKeyStratos:
			eth := ofp4sw.OxmKeyBasic(oxm.OXM_OF_ETH_TYPE)
			ethtype := ofp4sw.OxmValueMask{
				Value: []byte{0x88, 0xbb},
				Mask:  []byte{0xff, 0xff},
			}
			if v, ok := fields[eth]; ok {
				if err := ethtype.Merge(v.(ofp4sw.OxmValueMask)); err != nil {
					return err
				}
			}
			fields[eth] = ethtype

			keyFrameCtrl := OxmKeyStratos(oxm.STROXM_BASIC_DOT11_FRAME_CTRL)
			keyTag := OxmKeyStratos(oxm.STROXM_BASIC_DOT11_TAG)

			switch k {
			case oxm.STROXM_BASIC_DOT11_SSID:
				payload := ofp4sw.OxmValueMask{ // Management frame type
					Value: []byte{0x00, 0x00},
					Mask:  []byte{0x0F, 0x00},
				}
				if v, ok := fields[keyFrameCtrl]; ok {
					if err := payload.Merge(v.(ofp4sw.OxmValueMask)); err != nil {
						return err
					}
				}
				fields[keyFrameCtrl] = payload
			case oxm.STROXM_BASIC_DOT11_ACTION_CATEGORY:
				payload := ofp4sw.OxmValueMask{ // Action, ActionNAK common
					Value: []byte{0xC0, 0x00},
					Mask:  []byte{0xCF, 0x00},
				}
				if v, ok := fields[keyFrameCtrl]; ok {
					if err := payload.Merge(v.(ofp4sw.OxmValueMask)); err != nil {
						return err
					}
				}
				fields[keyFrameCtrl] = payload
			case oxm.STROXM_BASIC_DOT11_PUBLIC_ACTION:
				payload := ofp4sw.OxmValueMask{ // Action, ActionNAK common
					Value: []byte{0xC0, 0x00},
					Mask:  []byte{0xCF, 0x00},
				}
				if v, ok := fields[keyFrameCtrl]; ok {
					if err := payload.Merge(v.(ofp4sw.OxmValueMask)); err != nil {
						return err
					}
				}
				fields[keyFrameCtrl] = payload

				fields[OxmKeyStratos(oxm.STROXM_BASIC_DOT11_ACTION_CATEGORY)] = ofp4sw.OxmValueMask{
					Value: []byte{4},
				}
			case oxm.STROXM_BASIC_DOT11_TAG_VENDOR:
				if missing := func() bool {
					if v, ok := fields[keyTag]; ok {
						for _, v := range v.(OxmMultiValue).Values {
							if v[0] == 221 {
								return false
							}
						}
					}
					return true
				}(); missing {
					v := OxmMultiValue{}
					v.Values = append(v.Values, []byte{221})
					fields[keyTag] = v
				}
			}
		}
	}
	return nil
}

type OxmKeyStratos uint8

type OxmMultiValue struct {
	Values [][]byte
}

func (self OxmKeyStratos) Bytes(payload ofp4sw.OxmPayload) []byte {
	hdr := oxm.Header(oxm.OFPXMC_EXPERIMENTER<<oxm.OXM_CLASS_SHIFT | uint32(self)<<oxm.OXM_FIELD_SHIFT)
	makeCommon := func(payloadLength int) []byte {
		buf := make([]byte, 8+payloadLength)
		hdr.SetLength(4 + payloadLength)
		binary.BigEndian.PutUint32(buf, uint32(hdr))
		binary.BigEndian.PutUint32(buf[4:], uint32(oxm.STRATOS_EXPERIMENTER_ID))
		return buf
	}
	switch p := payload.(type) {
	case ofp4sw.OxmValueMask:
		if len(p.Mask) > 0 {
			hdr.SetMask(true)
		}
		buf := makeCommon(len(p.Value) + len(p.Mask))
		copy(buf[8:], p.Value)
		copy(buf[8+len(p.Value):], p.Mask)
		return buf
	case OxmMultiValue:
		var ret []byte
		for _, v := range p.Values {
			buf := makeCommon(len(v))
			copy(buf[8:], v)
			ret = append(ret, buf...)
		}
		return ret
	}
	return nil
}

func (self OxmKeyStratos) IsEmpty(payload ofp4sw.OxmPayload) bool {
	if self == oxm.STROXM_BASIC_DOT11 {
		if v, ok := payload.(ofp4sw.OxmValueMask); ok && len(v.Value) > 0 && v.Value[0] == 0 {
			return true
		}
	}
	return false
}
