package gopenflow

import (
	"encoding"
	"encoding/binary"
	"errors"
	"gopenflow/ofp4"
)

type Any interface{}

func Parse(data []byte) (obj Any, err error) {
	switch data[0] {
	default:
		err = errors.New("Unsupported version")
		return
	case 4: // Openflow 1.3
		length := int(binary.BigEndian.Uint16(data[2:4]))
		obj = new(ofp4.Message)
		if err = obj.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[0:length]); err != nil {
			return
		}
	}
	return
}
