package ofp4sw

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"encoding/binary"
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
)

const (
	STRATOS_EXPERIMENTER_ID = 0xFF00E04D
)

const (
	STRATOS_OXM_FIELD_BASIC = 0
)

var StratosOxmBasicId oxmExperimenterKey = [...]uint32{
	ofp4.OFPXMC_EXPERIMENTER<<ofp4.OXM_CLASS_SHIFT | STRATOS_OXM_FIELD_BASIC<<ofp4.OXM_FIELD_SHIFT,
	STRATOS_EXPERIMENTER_ID,
}

const (
	STRATOS_BASIC_LINKTYPE         = 1
	STRATOS_BASIC_DOT11_FRAME_CTRL = 2
	STRATOS_BASIC_BSSID            = 3
	STRATOS_BASIC_SSID             = 4
)

func getLinkType(data Frame) uint8 {
	for _, oxm := range ofp4.Oxm(data.Match).Iter() {
		g := ofp4.OxmGeneric(oxm)
		if g.Ok() && ofp4.OxmExperimenterHeader(oxm).Id() == StratosOxmBasicId && g.ExpType() == STRATOS_BASIC_LINKTYPE {
			return g.Value()[0]
		}
	}
	return 1
}

func getPacket(data Frame) gopacket.Packet {
	hwmap := map[uint8]gopacket.Decoder{
		0x01: layers.LayerTypeEthernet,
		0x69: layers.LayerTypeDot11,
		0x7f: layers.LayerTypeRadioTap,
	}
	if dec, ok := hwmap[getLinkType(data)]; ok {
		return gopacket.NewPacket(data.Data, dec, gopacket.Lazy)
	}
	return nil
}

type StratosOxm struct{}

func (self StratosOxm) Match(data Frame, oxms []byte) (bool, error) {
	var pkt gopacket.Packet
	linkType := getLinkType(data)
	for _, m := range ofp4.Oxm(oxms).Iter() {
		matchFail := true
		oxm := ofp4.OxmGeneric(m)
		if oxm.Ok() && ofp4.OxmExperimenterHeader(oxm).Id() == StratosOxmBasicId {
			switch oxm.ExpType() {
			default:
				return false, fmt.Errorf("unsupported field")
			case STRATOS_BASIC_LINKTYPE:
				if oxm.Value()[0] == linkType {
					matchFail = false
				}
			case STRATOS_BASIC_DOT11_FRAME_CTRL:
				if pkt == nil {
					pkt = getPacket(data)
				}
				if dot11, ok := pkt.Layer(layers.LayerTypeDot11).(*layers.Dot11); ok {
					field := make([]byte, 2)
					field[0] = uint8(dot11.Type)<<2 | dot11.Proto
					field[1] = uint8(dot11.Flags)

					value := oxm.Value()
					mask := oxm.Mask()
					if len(mask) > 0 {
						field = maskBytes(field, mask)
						value = maskBytes(value, mask)
					}
					if bytes.Equal(field, value) {
						matchFail = false
					}
				}
			case STRATOS_BASIC_BSSID:
				if pkt == nil {
					pkt = getPacket(data)
				}
				if dot11 := pkt.Layer(layers.LayerTypeDot11); dot11 != nil {
					var bssid []byte
					if t, ok := dot11.(*layers.Dot11); ok {
						if t.Flags.ToDS() {
							if t.Flags.FromDS() {
								// 4addr, no bssid
							} else {
								bssid = []byte(t.Address1)
							}
						} else {
							if t.Flags.FromDS() {
								bssid = []byte(t.Address2)
							} else {
								bssid = []byte(t.Address3)
							}
						}
					}
					if bssid != nil {
						value := oxm.Value()
						mask := oxm.Mask()
						if len(mask) > 0 {
							bssid = maskBytes(bssid, mask)
							value = maskBytes(value, mask)
						}
						if bytes.Equal(bssid, value) {
							matchFail = false
						}
					}
				}
			case STRATOS_BASIC_SSID:
				if pkt == nil {
					pkt = getPacket(data)
				}
				for _, l := range pkt.Layers() {
					if el, ok := l.(*layers.Dot11InformationElement); ok {
						if el.ID == layers.Dot11InformationElementIDSSID {
							info := make([]byte, 32)
							copy(info, el.Info)
							value := oxm.Value()
							mask := oxm.Mask()
							if len(mask) > 0 {
								info = maskBytes(info, mask)
								value = maskBytes(value, mask)
							}
							if bytes.Equal(info, value) {
								matchFail = false
							}
						}
					}
				}
			}
		}
		if matchFail {
			return false, nil
		}
	}
	return true, nil
}

func (self StratosOxm) SetField(data Frame, oxms []byte) (Frame, error) {
	return data, fmt.Errorf("setting linktype is not unsupported")
}

func (self StratosOxm) Fit(narrow, wide []byte) (bool, error) {
	for _, n := range ofp4.Oxm(narrow).Iter() {
		matchFail := false
		ng := ofp4.OxmGeneric(n)
		if ng.Ok() && ofp4.OxmExperimenterHeader(n).Id() == StratosOxmBasicId {
			matchFail = true
			switch ng.ExpType() {
			case STRATOS_BASIC_LINKTYPE:
				for _, w := range ofp4.Oxm(wide).Iter() {
					wg := ofp4.OxmGeneric(w)
					if wg.Ok() && ng.Id() == wg.Id() &&
						bytes.Equal(ng.Value(), wg.Value()) {
						matchFail = false
					}
				}
			}
		}
		if matchFail {
			return false, nil
		}
	}
	return true, nil
}

func (self StratosOxm) Conflict(a, b []byte) (bool, error) {
	for _, ab := range ofp4.Oxm(a).Iter() {
		abg := ofp4.OxmGeneric(ab)
		if abg.Ok() && ofp4.OxmExperimenterHeader(ab).Id() == StratosOxmBasicId {
			switch abg.ExpType() {
			case STRATOS_BASIC_LINKTYPE:
				for _, bb := range ofp4.Oxm(b).Iter() {
					bbg := ofp4.OxmGeneric(bb)
					if bbg.Ok() && abg.Id() == bbg.Id() {
						if !bytes.Equal(abg.Value(), bbg.Value()) {
							return true, nil
						}
					}
				}
			}
		}
	}
	return false, nil
}

func (self StratosOxm) OxmId(field []byte) ([]byte, error) {
	return field, nil
}

func (self StratosOxm) Expand(fields []byte) ([]byte, error) {
	return fields, nil
}

func MakeOxmBasic(field uint8, value []byte, mask []byte) ofp4.Oxm {
	length := len(value) + len(mask)
	hdr := uint32(length)
	hdr |= ofp4.OFPXMC_OPENFLOW_BASIC<<ofp4.OXM_CLASS_SHIFT | uint32(field)<<ofp4.OXM_FIELD_SHIFT
	if len(mask) != 0 {
		hdr |= 1 << ofp4.OXM_HASMASK_SHIFT
	}
	ret := make([]byte, 4, 4+length)
	binary.BigEndian.PutUint32(ret, hdr)
	ret = append(ret, value...)
	ret = append(ret, mask...)
	return ofp4.Oxm(ret)
}

func MakeOxmStratosBasic(field uint16, value []byte, mask []byte) ofp4.Oxm {
	length := 6 + len(value) + len(mask)
	hdr := uint32(length)
	hdr |= ofp4.OFPXMC_EXPERIMENTER<<ofp4.OXM_CLASS_SHIFT | STRATOS_OXM_FIELD_BASIC<<ofp4.OXM_FIELD_SHIFT
	if len(mask) != 0 {
		hdr |= 1 << ofp4.OXM_HASMASK_SHIFT
	}
	ret := make([]byte, 10, 10+length)
	binary.BigEndian.PutUint32(ret, hdr)
	binary.BigEndian.PutUint32(ret[4:], STRATOS_EXPERIMENTER_ID)
	binary.BigEndian.PutUint16(ret[8:], field)
	ret = append(ret, value...)
	ret = append(ret, mask...)
	return ofp4.Oxm(ret)
}
