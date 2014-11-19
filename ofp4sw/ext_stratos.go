package ofp4sw

import (
	"bytes"
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

var StratosOxmBasicId uint64 = (ofp4.OFPXMC_EXPERIMENTER<<ofp4.OXM_CLASS_SHIFT|STRATOS_OXM_FIELD_BASIC<<ofp4.OXM_FIELD_SHIFT)<<32 | STRATOS_EXPERIMENTER_ID

const (
	STRATOS_BASIC_LINKTYPE = 1
)

type StratosOxm struct{}

func (self StratosOxm) Match(data Frame, oxms []byte) (bool, error) {
	for m := range ofp4.OxmBytes(oxms).Iter() {
		matchFail := true
		oxm := ofp4.OxmGenericBytes(m)
		if oxm.Ok() && ofp4.OxmExperimenterBytes(oxm).Id() == StratosOxmBasicId {
			switch oxm.ExpType() {
			default:
				return false, fmt.Errorf("unsupported field")
			case STRATOS_BASIC_LINKTYPE:
				for p := range ofp4.OxmBytes(data.Match).Iter() {
					field := ofp4.OxmGenericBytes(p)
					if field.Ok() &&
						ofp4.OxmExperimenterBytes(field).Id() == StratosOxmBasicId &&
						field.ExpType() == STRATOS_BASIC_LINKTYPE &&
						bytes.Equal(field.Value(), oxm.Value()) {
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

func (self StratosOxm) SetField(data Frame, oxms []byte) (Frame, error) {
	return data, fmt.Errorf("setting linktype is not unsupported")
}

func (self StratosOxm) Fit(narrow, wide []byte) (bool, error) {
	for n := range ofp4.OxmBytes(narrow).Iter() {
		matchFail := false
		ng := ofp4.OxmGenericBytes(n)
		if ng.Ok() && ofp4.OxmExperimenterBytes(n).Id() == StratosOxmBasicId {
			matchFail = true
			switch ng.ExpType() {
			case STRATOS_BASIC_LINKTYPE:
				for w := range ofp4.OxmBytes(wide).Iter() {
					wg := ofp4.OxmGenericBytes(w)
					if wg.Ok() &&
						ofp4.OxmExperimenterBytes(w).Id() == StratosOxmBasicId &&
						wg.ExpType() == STRATOS_BASIC_LINKTYPE &&
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
	for ab := range ofp4.OxmBytes(a).Iter() {
		abg := ofp4.OxmGenericBytes(ab)
		if abg.Ok() && ofp4.OxmExperimenterBytes(ab).Id() == StratosOxmBasicId {
			switch abg.ExpType() {
			case STRATOS_BASIC_LINKTYPE:
				for bb := range ofp4.OxmBytes(b).Iter() {
					bbg := ofp4.OxmGenericBytes(bb)
					if bbg.Ok() &&
						ofp4.OxmExperimenterBytes(bb).Id() == StratosOxmBasicId &&
						bbg.ExpType() == STRATOS_BASIC_LINKTYPE {
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

func MakeOxmBasic(field uint8, value []byte, mask []byte) ofp4.OxmBytes {
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
	return ofp4.OxmBytes(ret)
}

func MakeOxmStratosBasic(field uint16, value []byte, mask []byte) ofp4.OxmBytes {
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
	return ofp4.OxmBytes(ret)
}
