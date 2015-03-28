package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"strconv"
	"strings"
)

func buildStratos(field uint8, eType uint16, vm ValueMask) []byte {
	length := len(vm.Value) + len(vm.Mask)
	buf := make([]byte, 10+length)

	hdr := ofp4.OxmHeader(ofp4.OFPXMC_EXPERIMENTER<<ofp4.OXM_CLASS_SHIFT | uint32(field)<<ofp4.OXM_FIELD_SHIFT)
	hdr.SetLength(6 + length)
	if len(vm.Mask) > 0 {
		hdr.SetMask(true)
	}
	binary.BigEndian.PutUint32(buf, uint32(hdr))
	binary.BigEndian.PutUint32(buf[4:], STRATOS_EXPERIMENTER_ID)
	binary.BigEndian.PutUint16(buf[8:], eType)
	copy(buf[10:], vm.Value)
	copy(buf[10+len(vm.Value):], vm.Mask)
	return buf
}

var StratosW2M = map[string]func(string) ([]byte, error){
	"dot11": func(arg string) ([]byte, error) {
		vm := ValueMask{}
		if n, err := strconv.ParseUint(arg, 0, 8); err != nil {
			return nil, err
		} else {
			vm.Value = intBytes(uint8(n))
		}
		return buildStratos(STRATOS_OXM_FIELD_BASIC, STROXM_BASIC_DOT11, vm), nil
	},
	"frame_ctrl": func(arg string) ([]byte, error) {
		vm := ValueMask{}
		p := strings.SplitN(arg, "/", 2)
		if v, err := hex.DecodeString(p[0]); err != nil {
			return nil, err
		} else {
			vm.Value = v
		}
		if len(p) > 1 {
			if v, err := hex.DecodeString(p[1]); err != nil {
				return nil, err
			} else {
				vm.Mask = v
			}
		}
		return buildStratos(STRATOS_OXM_FIELD_BASIC, STROXM_BASIC_DOT11_FRAME_CTRL, vm), nil
	},
	"addr1":           decodeMac(STROXM_BASIC_DOT11_ADDR1),
	"addr2":           decodeMac(STROXM_BASIC_DOT11_ADDR2),
	"addr3":           decodeMac(STROXM_BASIC_DOT11_ADDR3),
	"addr4":           decodeMac(STROXM_BASIC_DOT11_ADDR4),
	"ssid":            strUnsupported,
	"action_category": strUnsupported,
	"public_action":   strUnsupported,
	"dot11_tag":       strUnsupported,
}

func strUnsupported(arg string) ([]byte, error) {
	return nil, fmt.Errorf("unspported")
}

func decodeMac(eType uint16) func(string) ([]byte, error) {
	mac2bytes := func(arg string) ([]byte, error) {
		buf := make([]byte, 6)
		mac := strings.SplitN(arg, ":", 6)
		if len(mac) != 6 {
			return nil, fmt.Errorf("not a mac value: %s", arg)
		}
		for i, c := range mac {
			if n, err := strconv.ParseUint(c, 16, 8); err != nil {
				return nil, err
			} else {
				buf[i] = uint8(n)
			}
		}
		return buf, nil
	}
	return func(arg string) ([]byte, error) {
		pair := strings.SplitN(arg, "/", 2)

		vm := ValueMask{}
		if v, err := mac2bytes(pair[0]); err != nil {
			return nil, err
		} else {
			vm.Value = v
		}
		if len(pair) == 2 {
			if v, err := mac2bytes(pair[1]); err != nil {
				return nil, err
			} else {
				vm.Mask = v
			}
		}
		return buildStratos(STRATOS_OXM_FIELD_BASIC, eType, vm), nil
	}
}

//////////////////////////////////

const (
	STRATOS_EXPERIMENTER_ID = 0xFF00E04D
)

const (
	STRATOS_OXM_FIELD_BASIC = iota
	STRATOS_OXM_FIELD_RADIOTAP
)

const (
	STROXM_BASIC_UNKNOWN = iota
	// match, oob, set
	STROXM_BASIC_DOT11
	// match, set
	STROXM_BASIC_DOT11_FRAME_CTRL
	STROXM_BASIC_DOT11_ADDR1
	STROXM_BASIC_DOT11_ADDR2
	STROXM_BASIC_DOT11_ADDR3
	STROXM_BASIC_DOT11_ADDR4
	STROXM_BASIC_DOT11_SSID
	STROXM_BASIC_DOT11_ACTION_CATEGORY
	STROXM_BASIC_DOT11_PUBLIC_ACTION
	// match
	STROXM_BASIC_DOT11_TAG
	STROXM_BASIC_DOT11_TAG_VENDOR
)

const (
	STROXM_RADIOTAP_TSFT = iota
	STROXM_RADIOTAP_FLAGS
	STROXM_RADIOTAP_RATE
	STROXM_RADIOTAP_CHANNEL
	STROXM_RADIOTAP_FHSS
	STROXM_RADIOTAP_DBM_ANTSIGNAL
	STROXM_RADIOTAP_DBM_ANTNOISE
	STROXM_RADIOTAP_LOCK_QUALITY
	STROXM_RADIOTAP_TX_ATTENUATION
	STROXM_RADIOTAP_DB_TX_ATTENUATION
	STROXM_RADIOTAP_DBM_TX_POWER
	STROXM_RADIOTAP_ANTENNA
	STROXM_RADIOTAP_DB_ANTSIGNAL
	STROXM_RADIOTAP_DB_ANTNOISE
	STROXM_RADIOTAP_RX_FLAGS
	STROXM_RADIOTAP_TX_FLAGS
	STROXM_RADIOTAP_RTS_RETRIES
	STROXM_RADIOTAP_DATA_RETRIES
	_
	STROXM_RADIOTAP_MCS
	STROXM_RADIOTAP_AMPDU_STATUS
)
