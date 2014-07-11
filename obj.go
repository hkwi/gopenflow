/*
Package gopenflow implements common openflow routines.
*/
package gopenflow

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
)

func Parse(data []byte) (encoding.BinaryMarshaler, error) {
	switch data[0] {
	default:
		return nil, &Error{1, 0}
	case 4: // Openflow 1.3
		length := int(binary.BigEndian.Uint16(data[2:4]))
		obj = new(ofp4.Message)
		if err = obj.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[0:length]); err != nil {
			return nil, err
		} else {
			return obj, nil
		}
	}
}

type Error struct {
	Type uint16
	Code uint16
}

func (obj Error) Error() string {
	return fmt.Sprintf("ofp_error type=%d code=%d", obj.Type, obj.Code)
}
