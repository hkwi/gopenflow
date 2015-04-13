/*
Package gopenflow implements common openflow routines.
*/
package gopenflow

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"io"
)

func Parse(data []byte) (encoding.BinaryMarshaler, error) {
	switch data[0] {
	default:
		return nil, &Error{1, 0}
	case 4: // Openflow 1.3
		length := int(binary.BigEndian.Uint16(data[2:4]))
		return ofp4.Header(data[0:length]), nil
	}
}

type Error struct {
	Type uint16
	Code uint16
}

func (obj Error) Error() string {
	return fmt.Sprintf("ofp_error type=%d code=%d", obj.Type, obj.Code)
}

func ReadMessage(source io.Reader) ([]byte, error) {
	hdr := make([]byte, 8)
	if n, err := source.Read(hdr); err != nil {
		return nil, err
	} else if n != 8 {
		return nil, fmt.Errorf("openflow header read error")
	}
	length := int(binary.BigEndian.Uint16(hdr[2:]))
	switch {
	case length < 8:
		return nil, fmt.Errorf("openflow length error")
	case length == 8:
		return hdr, nil
	default:
		buf := make([]byte, length)
		copy(buf, hdr)
		offset := 8
		for offset < length {
			if n, err := source.Read(buf[offset:]); err != nil {
				return nil, err
			} else if n == 0 {
				return nil, fmt.Errorf("reached EOF during reading openflow body")
			} else {
				offset += n
			}
		}
		return buf, nil
	}
}
