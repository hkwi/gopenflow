package ofp4

import (
	"encoding/binary"
	"errors"
)

func queuePropertiesUnmarshalBinary(data []byte) (properties []TypedData, err error) {
	for cur := 0; cur < len(data); {
		pType := binary.BigEndian.Uint16(data[cur : 2+cur])
		pLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var property TypedData
		switch pType {
		default:
			err = errors.New("Unknown OFPIT_")
			return
		case OFPQT_MIN_RATE:
			property = new(QueuePropMinRate)
		case OFPQT_MAX_RATE:
			property = new(QueuePropMaxRate)
		case OFPQT_EXPERIMENTER:
			property = new(QueuePropExperimenter)
		}
		if err = property.UnmarshalBinary(data[cur : cur+pLen]); err != nil {
			return
		}
		properties = append(properties, property)
		cur += pLen
	}
	return
}

type QueuePropMinRate struct {
	Rate uint16
}

func (obj *QueuePropMinRate) GetType() uint16 {
	return OFPQT_MIN_RATE
}
func (obj *QueuePropMinRate) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPQT_MIN_RATE)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint16(data[8:10], obj.Rate)
	return
}
func (obj *QueuePropMinRate) UnmarshalBinary(data []byte) (err error) {
	obj.Rate = binary.BigEndian.Uint16(data[8:10])
	return
}

type QueuePropMaxRate struct {
	Rate uint16
}

func (obj *QueuePropMaxRate) GetType() uint16 {
	return OFPQT_MAX_RATE
}
func (obj *QueuePropMaxRate) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPQT_MAX_RATE)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint16(data[8:10], obj.Rate)
	return
}
func (obj *QueuePropMaxRate) UnmarshalBinary(data []byte) (err error) {
	obj.Rate = binary.BigEndian.Uint16(data[8:10])
	return
}

type QueuePropExperimenter struct {
	Experimenter uint32
	Data         []byte
}

func (obj *QueuePropExperimenter) GetType() uint16 {
	return OFPQT_EXPERIMENTER
}
func (obj *QueuePropExperimenter) MarshalBinary() (data []byte, err error) {
	prefix := make([]byte, 16)

	binary.BigEndian.PutUint16(prefix[0:2], OFPQT_EXPERIMENTER)
	binary.BigEndian.PutUint16(prefix[2:4], 16)
	binary.BigEndian.PutUint32(prefix[8:12], obj.Experimenter)
	data = append(prefix, obj.Data...)
	return
}
func (obj *QueuePropExperimenter) UnmarshalBinary(data []byte) (err error) {
	obj.Experimenter = binary.BigEndian.Uint32(data[8:12])
	obj.Data = data[16:]
	return
}
