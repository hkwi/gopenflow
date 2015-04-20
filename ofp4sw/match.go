package ofp4sw

import (
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"github.com/hkwi/gopenflow/oxm"
	"hash/fnv"
	"log"
)

var oxmBasicHandler oxmBasic

var _ = OxmHandler(oxmBasicHandler)

/*
oxm_type without oxm_has_mask and oxm_length for OFPXMC_EXPERIMENTER.
*/
var oxmHandlers map[uint32]OxmHandler = make(map[uint32]OxmHandler)
var oxmKeys map[OxmKey]uint32 = make(map[OxmKey]uint32)

func AddOxmHandler(experimenter uint32, handle OxmHandler) {
	oxmHandlers[experimenter] = handle
}

type match map[OxmKey]OxmPayload

func (self match) Match(data Frame) bool {
	for oxmKey, oxmPayload := range self {
		var handler OxmHandler
		switch k := oxmKey.(type) {
		case OxmKeyBasic:
			if oxm.Header(k).Class() == ofp4.OFPXMC_OPENFLOW_BASIC {
				handler = oxmBasicHandler
			}
		default:
			handler = oxmHandlers[oxmKeys[oxmKey]]
		}
		if handler == nil {
			log.Printf("oxm handler not found for %v", oxmKey)
			return false
		}
		if result, err := handler.Match(data, oxmKey, oxmPayload); err != nil {
			log.Print(err)
			return false
		} else if !result {
			return false
		}
	}
	return true
}

/*
Returned value will be true if self in the flow table matches target in openflow query message.
You must pass expanded match.
*/
func (self match) Fit(target match) (bool, error) {
	for oxmKey, sPayload := range self {
		if tPayload, ok := target[oxmKey]; ok {
			var handler OxmHandler
			switch oxmKey.(type) {
			case OxmKeyBasic:
				handler = oxmBasicHandler
			default:
				handler = oxmHandlers[oxmKeys[oxmKey]]
			}
			if handler == nil {
				return false, fmt.Errorf("oxm handler not found")
			}
			if r, err := handler.Fit(oxmKey, sPayload, tPayload); err != nil {
				return false, err
			} else if !r {
				return false, nil
			}
		}
	}
	return true, nil
}

/*
You should pass expanded match.
*/
func (self match) Conflict(target match) (bool, error) {
	uni := make(map[OxmKey]bool)
	for k, _ := range self {
		uni[k] = true
	}
	for k, _ := range target {
		uni[k] = true
	}

	for oxmKey, _ := range uni {
		if sPayload, ok := self[oxmKey]; !ok {
			continue
		} else if tPayload, ok := target[oxmKey]; !ok {
			continue
		} else {
			var handle OxmHandler
			switch k := oxmKey.(type) {
			case OxmKeyBasic:
				if oxm.Header(k).Class() == ofp4.OFPXMC_OPENFLOW_BASIC {
					handle = oxmBasicHandler
				}
			default:
				handle = oxmHandlers[oxmKeys[oxmKey]]
			}
			if handle == nil {
				return false, ofp4.MakeErrorMsg(
					ofp4.OFPET_BAD_MATCH,
					ofp4.OFPBMC_BAD_TYPE,
				)
			}
			if result, err := handle.Conflict(oxmKey, sPayload, tPayload); err != nil {
				return false, err
			} else if result {
				return true, nil
			}
		}
	}
	return false, nil
}

func (self match) MarshalBinary() ([]byte, error) {
	var ret []byte
	for k, v := range self {
		ret = append(ret, k.Bytes(v)...)
	}
	return ret, nil
}

func (self match) UnmarshalBinary(msg []byte) error {
	exps := make(map[uint32]bool)
	for _, oxm := range ofp4.Oxm(msg).Iter() {
		hdr := oxm.Header()
		switch hdr.Class() {
		case ofp4.OFPXMC_OPENFLOW_BASIC:
			self[OxmKeyBasic(hdr.Type())] = OxmValueMask{
				Value: oxm.Value(),
				Mask:  oxm.Mask(),
			}
		case ofp4.OFPXMC_EXPERIMENTER:
			exps[ofp4.OxmExperimenterHeader(oxm).Experimenter()] = true
		default:
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_MATCH,
				ofp4.OFPBMC_BAD_TYPE,
			)
		}
	}
	for exp, _ := range exps {
		if handle, ok := oxmHandlers[exp]; ok {
			for k, v := range handle.Parse(msg) {
				oxmKeys[k] = exp
				self[k] = v
			}
		} else {
			return ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_MATCH,
				ofp4.OFPBRC_BAD_LEN,
			)
		}
	}
	return nil
}

func (self match) Expand() (match, error) {
	var exps []uint32
	ret := make(map[OxmKey]OxmPayload)
	for k, v := range self {
		oxm := ofp4.Oxm(k.Bytes(v))
		if oxm.Header().Class() == ofp4.OFPXMC_EXPERIMENTER {
			exps = append(exps, ofp4.OxmExperimenterHeader(oxm).Experimenter())
		}
		ret[k] = v
	}
	oxmBasicHandler.Expand(ret)
	for _, exp := range exps {
		if handle, ok := oxmHandlers[exp]; !ok {
			return nil, ofp4.MakeErrorMsg(
				ofp4.OFPET_BAD_MATCH,
				ofp4.OFPBMC_BAD_TYPE,
			)
		} else if err := handle.Expand(ret); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

/*
You must pass expanded match.
*/
func (self match) Equal(target match) (bool, error) {
	if ss, err := self.Expand(); err != nil {
		return false, err
	} else if tt, err := target.Expand(); err != nil {
		return false, err
	} else {
		if r1, err := ss.Fit(tt); err != nil {
			return false, err
		} else if r2, err := tt.Fit(ss); err != nil {
			return false, err
		} else if r1 && r2 {
			return true, nil
		}
		return false, nil
	}
}

// matchHash is for oxm vs oxm intersection.
// note this is not a normal oxm, because this may have mask
// even if oxm definition does not have mask.
type matchHash map[OxmKey]OxmPayload

// creates a common match union parameter.
func (self matchHash) Merge(from matchHash) {
	var removal []OxmKey
	for k, s := range self {
		var a, b OxmValueMask
		var length int
		if bKey, ok := k.(OxmKeyBasic); !ok || oxm.Header(bKey).Class() != ofp4.OFPXMC_OPENFLOW_BASIC {
			continue
		} else if f, ok := from[k]; !ok {
			removal = append(removal, k)
			continue
		} else {
			a = s.(OxmValueMask)
			b = f.(OxmValueMask)
			length, _ = ofp4.OxmOfDefs(uint32(bKey))
		}
		fullMask := true
		mask := make([]byte, length)
		for i, _ := range mask {
			mask[i] = 0xFF
		}
		if a.Mask != nil {
			for i, _ := range mask {
				mask[i] &= a.Mask[i]
			}
		}
		if b.Mask != nil {
			for i, _ := range mask {
				mask[i] &= b.Mask[i]
			}
		}
		for i, m := range mask {
			mask[i] &^= (a.Value[i] & m) ^ (b.Value[i] & m)
			if mask[i] != 0 {
				fullMask = false
			}
		}
		if fullMask {
			removal = append(removal, k)
			continue
		}
		payload := OxmValueMask{
			Value: make([]byte, length),
			Mask:  mask,
		}
		for i, m := range mask {
			payload.Value[i] = a.Value[i] & m
		}
		self[k] = payload
	}
	for _, rem := range removal {
		delete(self, rem)
	}
}

func (self matchHash) Key(target matchHash) uint32 {
	hasher := fnv.New32()
	for k, s := range self {
		var value, mask []byte
		if bKey, ok := k.(OxmKeyBasic); !ok || oxm.Header(bKey).Class() != ofp4.OFPXMC_OPENFLOW_BASIC {
			continue
		} else {
			length, _ := ofp4.OxmOfDefs(uint32(bKey))
			value = make([]byte, length)
			mask = make([]byte, length)
		}
		if t, ok := target[k]; ok {
			a := s.(OxmValueMask)
			b := t.(OxmValueMask)
			for i, _ := range mask {
				mask[i] = 0xFF
			}
			if a.Mask != nil {
				for i, _ := range mask {
					mask[i] &= a.Mask[i]
				}
			}
			if b.Mask != nil {
				for i, _ := range mask {
					mask[i] &= b.Mask[i]
				}
			}
			for i, _ := range value {
				value[i] = b.Value[i] & mask[i]
			}
		}
		hasher.Write(value)
	}
	return hasher.Sum32()
}
