package ofp4obj

import (
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
		buf := data[cur : cur+bLen]

		switch bType {
		default:
			return Error{
				Type: OFPET_METER_MOD_FAILED,
				Code: OFPMMFC_BAD_BAND,
			}
		case OFPMBT_DROP:
			var band MeterBandDrop
			if err := band.UnmarshalBinary(buf); err != nil {
				return err
			}
			bands = append(bands, band)
		case OFPMBT_DSCP_REMARK:
			var band MeterBandDscpRemark
			if err := band.UnmarshalBinary(buf); err != nil {
				return err
			}
			bands = append(bands, band)
		case OFPMBT_EXPERIMENTER:
			var band MeterBandExperimenter
			if err := band.UnmarshalBinary(buf); err != nil {
				return err
			}
			bands = append(bands, band)
		}
		cur += bLen
	}
	*obj = bandList(bands)
	return nil
}

type MeterBandDrop struct {
	Rate      uint32
	BurstSize uint32
}

func (obj MeterBandDrop) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPMBT_DROP)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint32(data[4:8], obj.Rate)
	binary.BigEndian.PutUint32(data[8:12], obj.BurstSize)
	return data, nil
}

func (obj *MeterBandDrop) UnmarshalBinary(data []byte) error {
	obj.Rate = binary.BigEndian.Uint32(data[4:8])
	obj.BurstSize = binary.BigEndian.Uint32(data[8:12])
	return nil
}

type MeterBandDscpRemark struct {
	Rate      uint32
	BurstSize uint32
	PrecLevel uint8
}

func (obj MeterBandDscpRemark) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPMBT_DSCP_REMARK)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint32(data[4:8], obj.Rate)
	binary.BigEndian.PutUint32(data[8:12], obj.BurstSize)
	data[12] = obj.PrecLevel
	return data, nil
}
func (obj *MeterBandDscpRemark) UnmarshalBinary(data []byte) error {
	obj.Rate = binary.BigEndian.Uint32(data[4:8])
	obj.BurstSize = binary.BigEndian.Uint32(data[8:12])
	obj.PrecLevel = data[12]
	return nil
}

type MeterBandExperimenter struct {
	Rate         uint32
	BurstSize    uint32
	Experimenter uint32
	Data         []byte
}

func (obj MeterBandExperimenter) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16+len(obj.Data))
	binary.BigEndian.PutUint16(data[0:2], OFPMBT_EXPERIMENTER)
	binary.BigEndian.PutUint16(data[2:4], uint16(16+len(obj.Data)))
	binary.BigEndian.PutUint32(data[4:8], obj.Rate)
	binary.BigEndian.PutUint32(data[8:12], obj.BurstSize)
	binary.BigEndian.PutUint32(data[12:16], obj.Experimenter)
	copy(data[16:], obj.Data)
	return data, nil
}

func (obj *MeterBandExperimenter) UnmarshalBinary(data []byte) error {
	obj.Rate = binary.BigEndian.Uint32(data[4:8])
	obj.BurstSize = binary.BigEndian.Uint32(data[8:12])
	obj.Experimenter = binary.BigEndian.Uint32(data[12:16])
	obj.Data = data[16:]
	return nil
}
