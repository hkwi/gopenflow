package ofp4

import (
	"encoding"
	"encoding/binary"
)

type bandList []Band

func (obj bandList) MarshalBinary() ([]byte, error) {
	var data []byte
	for _, band := range []Band(obj) {
		if buf, err := band.MarshalBinary(); err != nil {
			return nil, err
		} else {
			data = append(data, buf...)
		}
	}
	return data, nil
}

func (obj *bandList) UnmarshalBinary(data []byte) error {
	var bands []Band
	for cur := 0; cur < len(data); {
		bType := binary.BigEndian.Uint16(data[cur : 2+cur])
		bLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var band Band
		switch bType {
		default:
			return Error{OFPET_METER_MOD_FAILED, OFPMMFC_BAD_BAND, nil}
		case OFPMBT_DROP:
			band = new(MeterBandDrop)
		case OFPMBT_DSCP_REMARK:
			band = new(MeterBandDscpRemark)
		case OFPMBT_EXPERIMENTER:
			band = new(MeterBandExperimenter)
		}
		if err := band.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[cur : cur+bLen]); err != nil {
			return err
		}
		bands = append(bands, band)
		cur += bLen
	}
	*obj = bandList(bands)
	return nil
}

type MeterBandDrop struct {
	Rate      uint32
	BurstSize uint32
}

func (obj MeterBandDrop) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPMBT_DROP)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint32(data[4:8], obj.Rate)
	binary.BigEndian.PutUint32(data[8:12], obj.BurstSize)
	return
}
func (obj *MeterBandDrop) UnmarshalBinary(data []byte) (err error) {
	obj.Rate = binary.BigEndian.Uint32(data[4:8])
	obj.BurstSize = binary.BigEndian.Uint32(data[8:12])
	return
}

type MeterBandDscpRemark struct {
	Rate      uint32
	BurstSize uint32
	PrecLevel uint8
}

func (obj MeterBandDscpRemark) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPMBT_DSCP_REMARK)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint32(data[4:8], obj.Rate)
	binary.BigEndian.PutUint32(data[8:12], obj.BurstSize)
	data[12] = obj.PrecLevel
	return
}
func (obj *MeterBandDscpRemark) UnmarshalBinary(data []byte) (err error) {
	obj.Rate = binary.BigEndian.Uint32(data[4:8])
	obj.BurstSize = binary.BigEndian.Uint32(data[8:12])
	obj.PrecLevel = data[12]
	return
}

type MeterBandExperimenter struct {
	Rate         uint32
	BurstSize    uint32
	Experimenter uint32
	Data         []byte
}

func (obj MeterBandExperimenter) MarshalBinary() (data []byte, err error) {
	prefix := make([]byte, 16)
	binary.BigEndian.PutUint16(prefix[0:2], OFPMBT_EXPERIMENTER)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(16+len(obj.Data)))
	binary.BigEndian.PutUint32(prefix[4:8], obj.Rate)
	binary.BigEndian.PutUint32(prefix[8:12], obj.BurstSize)
	binary.BigEndian.PutUint32(prefix[8:12], obj.Experimenter)

	data = append(prefix, obj.Data...)
	return
}
func (obj *MeterBandExperimenter) UnmarshalBinary(data []byte) (err error) {
	obj.Rate = binary.BigEndian.Uint32(data[4:8])
	obj.BurstSize = binary.BigEndian.Uint32(data[8:12])
	obj.Experimenter = binary.BigEndian.Uint32(data[12:16])
	obj.Data = data[16:]
	return
}
