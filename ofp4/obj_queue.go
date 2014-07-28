package ofp4

import (
	"encoding"
	"encoding/binary"
	"errors"
)

type queueProperties []encoding.BinaryMarshaler

func (self queueProperties) MarshalBinary() ([]byte, error) {
	return Array(self).MarshalBinary()
}

func (self *queueProperties) UnmarshalBinary(data []byte) error {
	var properties []encoding.BinaryMarshaler
	for cur := 0; cur < len(data); {
		pType := binary.BigEndian.Uint16(data[cur : 2+cur])
		pLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var property encoding.BinaryMarshaler
		switch pType {
		default:
			return errors.New("Unknown OFPIT_")
		case OFPQT_MIN_RATE:
			property = new(QueuePropMinRate)
		case OFPQT_MAX_RATE:
			property = new(QueuePropMaxRate)
		case OFPQT_EXPERIMENTER:
			property = new(QueuePropExperimenter)
		}
		if err := property.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[cur : cur+pLen]); err != nil {
			return err
		}
		properties = append(properties, property)
		cur += pLen
	}
	*self = properties
	return nil
}

type QueuePropMinRate struct {
	Rate uint16
}

func (obj QueuePropMinRate) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPQT_MIN_RATE)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint16(data[8:10], obj.Rate)
	// 6 padding
	return data, nil
}

func (obj *QueuePropMinRate) UnmarshalBinary(data []byte) error {
	obj.Rate = binary.BigEndian.Uint16(data[8:10])
	return nil
}

type QueuePropMaxRate struct {
	Rate uint16
}

func (obj QueuePropMaxRate) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPQT_MAX_RATE)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint16(data[8:10], obj.Rate)
	// 6 padding
	return data, nil
}
func (obj *QueuePropMaxRate) UnmarshalBinary(data []byte) error {
	obj.Rate = binary.BigEndian.Uint16(data[8:10])
	return nil
}

type QueuePropExperimenter struct {
	Experimenter uint32
	Data         []byte
}

func (obj QueuePropExperimenter) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16+len(obj.Data))
	binary.BigEndian.PutUint16(data[0:2], OFPQT_EXPERIMENTER)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint32(data[8:12], obj.Experimenter)
	// 4 padding
	copy(data[16:], obj.Data)
	return data, nil
}

func (obj *QueuePropExperimenter) UnmarshalBinary(data []byte) (err error) {
	obj.Experimenter = binary.BigEndian.Uint32(data[8:12])
	obj.Data = data[16:]
	return
}
