package oxm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

type Stratos struct{}

var stratosStringer = Stratos{}

func (self Stratos) FromOxm(buf []byte) string {
	ret := "?"

	hdr := Oxm(buf).Header()
	length := hdr.Length() - 4
	value := buf[8 : 8+length]
	mask := []byte(nil)
	hasMask := hdr.HasMask()
	if hasMask {
		value = buf[8 : 8+length/2]
		mask = buf[8+length/2 : 8+length]
	}

	switch hdr.Field() {
	case STROXM_BASIC_DOT11:
		ret = fmt.Sprintf("dot11=%d", value[0])
	case STROXM_BASIC_DOT11_FRAME_CTRL:
		if hasMask {
			ret = fmt.Sprintf("dot11_frame_ctrl=%s/%s",
				hex.EncodeToString(value),
				hex.EncodeToString(mask))
		} else {
			ret = fmt.Sprintf("dot11_frame_ctrl=%s",
				hex.EncodeToString(value))
		}
	case STROXM_BASIC_DOT11_ADDR1:
		if hasMask {
			ret = fmt.Sprintf("dot11_addr1=%v/%v",
				net.HardwareAddr(value),
				net.HardwareAddr(mask))
		} else {
			ret = fmt.Sprintf("dot11_addr1=%v",
				net.HardwareAddr(value))
		}
	case STROXM_BASIC_DOT11_ADDR2:
		if hasMask {
			ret = fmt.Sprintf("dot11_addr2=%v/%v",
				net.HardwareAddr(value),
				net.HardwareAddr(mask))
		} else {
			ret = fmt.Sprintf("dot11_addr2=%v",
				net.HardwareAddr(value))
		}
	case STROXM_BASIC_DOT11_ADDR3:
		if hasMask {
			ret = fmt.Sprintf("dot11_addr3=%v/%v",
				net.HardwareAddr(value),
				net.HardwareAddr(mask))
		} else {
			ret = fmt.Sprintf("dot11_addr3=%v",
				net.HardwareAddr(value))
		}
	case STROXM_BASIC_DOT11_ADDR4:
		if hasMask {
			ret = fmt.Sprintf("dot11_addr4=%v/%v",
				net.HardwareAddr(value),
				net.HardwareAddr(mask))
		} else {
			ret = fmt.Sprintf("dot11_addr4=%v",
				net.HardwareAddr(value))
		}
	case STROXM_BASIC_DOT11_SSID:
		if hasMask {
			ret = fmt.Sprintf("dot11_ssid=%s/%s",
				strings.Split(string(value), "\x00")[0],
				hex.EncodeToString(mask))
		} else {
			ret = fmt.Sprintf("dot11_ssid=%s",
				string(value))
		}
	case STROXM_BASIC_DOT11_ACTION_CATEGORY:
		if hasMask {
			ret = fmt.Sprintf("dot11_action_category=%s/%s",
				hex.EncodeToString(value),
				hex.EncodeToString(mask))
		} else {
			ret = fmt.Sprintf("dot11_action_category=%s",
				hex.EncodeToString(value))
		}
	case STROXM_BASIC_DOT11_PUBLIC_ACTION:
		ret = fmt.Sprintf("dot11_public_action=%d", value[0])
	case STROXM_BASIC_DOT11_TAG:
		ret = fmt.Sprintf("dot11_tag=%d", value[0])
	case STROXM_BASIC_DOT11_TAG_VENDOR:
		ret = fmt.Sprintf("dot11_tag_vendor=%s", hex.EncodeToString(value))
	case STROXM_RADIOTAP_TSFT: // msec
		ret = fmt.Sprintf("radiotap_tsft=%d",
			binary.LittleEndian.Uint64(value))
	case STROXM_RADIOTAP_FLAGS:
		ret = fmt.Sprintf("radiotap_flags=0x%02x", value[0])
	case STROXM_RADIOTAP_RATE: // bps
		kbps := float64(value[0]) * 500.0
		if kbps < 1000 {
			ret = fmt.Sprintf("radiotap_rate=%.1fK", kbps)
		} else {
			ret = fmt.Sprintf("radiotap_rate=%.1fM", kbps/1000.0)
		}
	case STROXM_RADIOTAP_CHANNEL:
		ret = fmt.Sprintf("radiotap_channel=%d:0x%04x",
			binary.LittleEndian.Uint16(value),
			binary.LittleEndian.Uint16(value[2:]))
		if hasMask {
			freq := binary.LittleEndian.Uint16(mask)
			if freq != 0 {
				ret += fmt.Sprintf("/0x%04x:0x%04x",
					freq,
					binary.LittleEndian.Uint16(mask[2:]))
			} else {
				ret += fmt.Sprintf("/:0x%04x",
					binary.LittleEndian.Uint16(mask[2:]))
			}
		}
	case STROXM_RADIOTAP_FHSS:
		ret = fmt.Sprintf("radiotap_fhss=%s", hex.EncodeToString(value))
	case STROXM_RADIOTAP_DBM_ANTSIGNAL:
		ret = fmt.Sprintf("radiotap_dbm_antsignal=%d", int8(value[0]))
	case STROXM_RADIOTAP_DBM_ANTNOISE:
		ret = fmt.Sprintf("radiotap_dbm_antnoise=%d", int8(value[0]))
	case STROXM_RADIOTAP_LOCK_QUALITY:
		ret = fmt.Sprintf("radiotap_lock_quality=%d",
			binary.LittleEndian.Uint16(value))
	case STROXM_RADIOTAP_TX_ATTENUATION:
		ret = fmt.Sprintf("radiotap_tx_attenuation=%d",
			binary.LittleEndian.Uint16(value))
	case STROXM_RADIOTAP_DB_TX_ATTENUATION:
		ret = fmt.Sprintf("radiotap_db_tx_attenuation=%d",
			binary.LittleEndian.Uint16(value))
	case STROXM_RADIOTAP_DBM_TX_POWER:
		ret = fmt.Sprintf("radiotap_dbm_tx_power=%d", int(value[0]))
	case STROXM_RADIOTAP_ANTENNA:
		ret = fmt.Sprintf("radiotap_antenna=%d", value[0])
	case STROXM_RADIOTAP_DB_ANTSIGNAL:
		ret = fmt.Sprintf("radiotap_db_antsignal=%d", value[0])
	case STROXM_RADIOTAP_DB_ANTNOISE:
		ret = fmt.Sprintf("radiotap_db_antnoise=%d", value[0])
	case STROXM_RADIOTAP_RX_FLAGS:
		ret = fmt.Sprintf("radiotap_rx_flags=0x%04x",
			binary.LittleEndian.Uint16(value))
	case STROXM_RADIOTAP_TX_FLAGS:
		ret = fmt.Sprintf("radiotap_tx_flags=0x%04x",
			binary.LittleEndian.Uint16(value))
	case STROXM_RADIOTAP_RTS_RETRIES:
		ret = fmt.Sprintf("radiotap_rts_retries=%d", value[0])
	case STROXM_RADIOTAP_DATA_RETRIES:
		ret = fmt.Sprintf("radiotap_data_retries=%d", value[0])
	case STROXM_RADIOTAP_MCS:
		// [3]uint8 ... flags(IEEE80211_RADIOTAP_MCS_HAVE_*), flags(IEEE80211_RADIOTAP_MCS_*), index
		str := func(buf []byte) string {
			var c []string
			for i, v := range buf {
				if v == 0 {
					c = append(c, "")
				} else if i < 2 {
					c = append(c, fmt.Sprintf("0x%02x", v))
				} else {
					c = append(c, fmt.Sprintf("%d", v))
				}
			}
			return strings.Join(c, ":")
		}

		if hasMask {
			ret = fmt.Sprintf("radiotap_mcs=%s/%s", str(value), str(mask))
		} else {
			ret = fmt.Sprintf("radiotap_mcs=%s", str(value))
		}
	case STROXM_RADIOTAP_AMPDU_STATUS:
		str := func(buf []byte) string {
			var c []string
			if v := binary.LittleEndian.Uint32(buf); v != 0 {
				c = append(c, fmt.Sprintf("0x%08x", v))
			} else {
				c = append(c, "")
			}
			if v := binary.LittleEndian.Uint16(buf[4:]); v != 0 {
				c = append(c, fmt.Sprintf("0x%04x", v))
			} else {
				c = append(c, "")
			}
			if buf[6] != 0 {
				c = append(c, fmt.Sprintf("0x%02x", buf[6]))
			} else {
				c = append(c, "")
			}
			if buf[7] != 0 {
				c = append(c, fmt.Sprintf("0x%02x", buf[7]))
			} else {
				c = append(c, "")
			}
			return strings.Join(c, ":")
		}
		if hasMask {
			ret = fmt.Sprintf("radiotap_ampdu_status=%s/%s", str(value), str(mask))
		} else {
			ret = fmt.Sprintf("radiotap_ampdu_status=%s", str(value))
		}
	case STROXM_RADIOTAP_VHT:
		// u16 known, u8 flags, u8 bandwidth, u8 mcs_nss[4], u8 coding, u8 group_id, u16 partial_aid
		str := func(buf []byte) string {
			var c []string
			if v := binary.LittleEndian.Uint16(buf); v != 0 { // known
				c = append(c, fmt.Sprintf("0x%04x", v))
			} else {
				c = append(c, "")
			}
			if buf[2] != 0 { // flags
				c = append(c, fmt.Sprintf("0x%02x", buf[2]))
			} else {
				c = append(c, "")
			}
			c = append(c, fmt.Sprintf("%d", buf[3]))
			if buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] == 0 {
				c = append(c, "")
			} else {
				c = append(c, hex.EncodeToString(buf[4:8]))
			}
			if buf[8] != 0 {
				c = append(c, fmt.Sprintf("0x%02x", buf[8]))
			} else {
				c = append(c, "")
			}
			c = append(c, fmt.Sprintf("%d", buf[9]))
			c = append(c, fmt.Sprintf("0x04x", binary.LittleEndian.Uint16(buf[10:])))
			return strings.Join(c, ":")
		}

		if hasMask {
			ret = fmt.Sprintf("radiotap_vht=%s/%s", str(value), str(mask))
		} else {
			ret = fmt.Sprintf("radiotap_vht=%s", str(value))
		}
	}
	return ret
}

func (self Stratos) ToOxm(txt string) (buf []byte, eatLen int, err error) {
	labelIdx := strings.IndexRune(txt, '=')
	if labelIdx < 0 {
		err = fmt.Errorf("not a stratos format")
		return
	}
	label := txt[:labelIdx]
	args := txt[labelIdx+1:]
	value, mask, baseN := parsePair(args)
	var expType uint8

	switch label {
	case "dot11":
		expType = STROXM_BASIC_DOT11
		buf = make([]byte, 9)
		if err = parseInt(value, &buf[8]); err != nil {
			return
		}
	case "dot11_tag", "dot11_public_action":
		switch label {
		case "dot11_tag":
			expType = STROXM_BASIC_DOT11_TAG
		case "dot11_public_action":
			expType = STROXM_BASIC_DOT11_PUBLIC_ACTION
		}
		buf = make([]byte, 9)
		if err = parseInt(value, &buf[8]); err != nil {
			return
		}
	case "dot11_frame_ctrl", "dot11_action_category", "dot11_tag_vendor":
		switch label {
		case "dot11_frame_ctrl":
			expType = STROXM_BASIC_DOT11_FRAME_CTRL
		case "dot11_action_category":
			expType = STROXM_BASIC_DOT11_ACTION_CATEGORY
		case "dot11_tag_vendor":
			expType = STROXM_BASIC_DOT11_TAG_VENDOR
		}

		var v, m []byte
		if v, err = hex.DecodeString(value); err != nil {
			return
		} else if len(mask) == 0 {
			buf = make([]byte, 8+len(v))
			copy(buf[8:], v)
		} else if m, err = hex.DecodeString(mask); err != nil {
			return
		} else {
			buf = make([]byte, 8+len(v)+len(m))
			copy(buf[8:], v)
			copy(buf[8+len(v):], m)
		}
	case "dot11_addr1", "dot11_addr2", "dot11_addr3", "dot11_addr4":
		switch label {
		case "dot11_addr1":
			expType = STROXM_BASIC_DOT11_ADDR1
		case "dot11_addr2":
			expType = STROXM_BASIC_DOT11_ADDR2
		case "dot11_addr3":
			expType = STROXM_BASIC_DOT11_ADDR3
		case "dot11_addr4":
			expType = STROXM_BASIC_DOT11_ADDR4
		}
		var v, m []byte
		if v, err = net.ParseMAC(value); err != nil {
			return
		} else if len(mask) == 0 {
			buf = make([]byte, 14)
			copy(buf[8:], v)
		} else if m, err = net.ParseMAC(value); err != nil {
			return
		} else {
			buf = make([]byte, 20)
			copy(buf[8:], v)
			copy(buf[14:], m)
		}
	case "dot11_ssid":
		expType = STROXM_BASIC_DOT11_SSID
		var v, m []byte
		v = []byte(value)
		if len(mask) == 0 {
			buf = make([]byte, 8+len(v))
			copy(buf[8:], v)
		} else if m, err = hex.DecodeString(mask); err != nil {
			return
		} else {
			switch {
			case len(m) > len(v):
				v = append(v, make([]byte, len(m)-len(v))...)
			case len(m) < len(v):
				m = append(m, make([]byte, len(v)-len(m))...)
			}
			buf = make([]byte, 8+len(v)+len(m))
			copy(buf[8:], v)
			copy(buf[8+len(v):], m)
		}
	case "radiotap_tsft":
		expType = STROXM_RADIOTAP_TSFT
		var v uint64
		if err = parseInt(value, &v); err != nil {
			return
		}
		buf = make([]byte, 16)
		binary.LittleEndian.PutUint64(buf[8:], v)
	case "radiotap_dbm_antsignal", "radiotap_dbm_antnoise", "radiotap_dbm_tx_power":
		switch label {
		case "radiotap_dbm_antsignal":
			expType = STROXM_RADIOTAP_DBM_ANTSIGNAL
		case "radiotap_dbm_antnoise":
			expType = STROXM_RADIOTAP_DBM_ANTNOISE
		case "radiotap_dbm_tx_power":
			expType = STROXM_RADIOTAP_DBM_TX_POWER
		}
		var v, m int8
		if err = parseInt(value, &v); err != nil {
			return
		} else if len(mask) == 0 {
			buf = make([]byte, 9)
			buf[8] = uint8(v)
		} else if err = parseInt(mask, &m); err != nil {
			return
		} else {
			buf = make([]byte, 10)
			buf[8] = uint8(v)
			buf[9] = uint8(m)
		}
	case "radiotap_flags", "radiotap_db_antsignal", "radiotap_db_antnoise", "radiotap_antenna",
		"radiotap_rts_retries", "radiotap_data_retries":
		switch label {
		case "radiotap_flags":
			expType = STROXM_RADIOTAP_FLAGS
		case "radiotap_dbm_antsignal":
			expType = STROXM_RADIOTAP_DBM_ANTSIGNAL
		case "radiotap_dbm_antnoise":
			expType = STROXM_RADIOTAP_DBM_ANTNOISE
		case "radiotap_antenna":
			expType = STROXM_RADIOTAP_ANTENNA
		case "radiotap_rts_retries":
			expType = STROXM_RADIOTAP_RTS_RETRIES
		case "radiotap_data_retries":
			expType = STROXM_RADIOTAP_DATA_RETRIES
		}
		var v, m uint8
		if err = parseInt(value, &v); err != nil {
			return
		} else if len(mask) == 0 {
			buf = make([]byte, 9)
			buf[8] = v
		} else if err = parseInt(mask, &m); err != nil {
			return
		} else {
			buf = make([]byte, 10)
			buf[8] = v
			buf[9] = m
		}
	case "radiotap_lock_quality", "radiotap_tx_attenuation", "radiotap_db_tx_attenuation",
		"radiotap_rx_flags", "radiotap_tx_flags":
		switch label {
		case "radiotap_lock_quality":
			expType = STROXM_RADIOTAP_LOCK_QUALITY
		case "radiotap_tx_attenuation":
			expType = STROXM_RADIOTAP_TX_ATTENUATION
		case "radiotap_db_tx_attenuation":
			expType = STROXM_RADIOTAP_DB_TX_ATTENUATION
		case "radiotap_rx_flags":
			expType = STROXM_RADIOTAP_RX_FLAGS
		case "radiotap_tx_flags":
			expType = STROXM_RADIOTAP_TX_FLAGS
		}
		var v, m uint16
		if err = parseInt(value, &v); err != nil {
			return
		} else if len(mask) == 0 {
			buf = make([]byte, 10)
			binary.LittleEndian.PutUint16(buf[8:], v)
		} else if err = parseInt(mask, &m); err != nil {
			return
		} else {
			buf = make([]byte, 12)
			binary.LittleEndian.PutUint16(buf[8:], v)
			binary.LittleEndian.PutUint16(buf[10:], m)
		}
	case "radiotap_rate":
		expType = STROXM_RADIOTAP_RATE
		var kbps float32
		var n int
		if n, err = fmt.Sscanf(value, "%fK", &kbps); err == nil && n == 1 {
			buf = make([]byte, 10)
			binary.LittleEndian.PutUint16(buf[8:], uint16(kbps/500.0))
		} else if n, err = fmt.Sscanf(value, "%fM", &kbps); err == nil && n == 1 {
			buf = make([]byte, 10)
			binary.LittleEndian.PutUint16(buf[8:], uint16(kbps*2))
		} else {
			if err == nil {
				err = fmt.Errorf("rate parse error")
			}
			return
		}
	case "radiotap_channel":
		expType = STROXM_RADIOTAP_CHANNEL
		parse := func(txt string, buf []byte) bool {
			var value [2]uint16
			for i, vtxt := range strings.SplitN(txt, ":", 2) {
				if len(vtxt) == 0 {
					continue
				}
				if err = parseInt(vtxt, &value[i]); err != nil {
					return false
				} else {
					binary.LittleEndian.PutUint16(buf[2*i:], value[i])
				}
			}
			return true
		}

		if len(mask) == 0 {
			buf = make([]byte, 12)
			if !parse(value, buf[8:]) {
				return
			}
		} else {
			buf = make([]byte, 16)
			if !parse(value, buf[8:]) || !parse(mask, buf[12:]) {
				return
			}
		}
	case "radiotap_fhss":
		expType = STROXM_RADIOTAP_FHSS
		var v, m []byte
		if v, err = hex.DecodeString(value); err != nil {
			return
		} else if len(mask) == 0 {
			buf = make([]byte, 8+len(v))
			copy(buf[8:], v)
		} else if m, err = hex.DecodeString(mask); err != nil {
			return
		} else {
			length := len(v)
			if len(v) < len(m) {
				length = len(m)
			}
			buf = make([]byte, 8+length*2)
			copy(buf[8:], v)
			copy(buf[8+length:], m)
		}
	case "radiotap_mcs":
		expType = STROXM_RADIOTAP_MCS
		parse := func(txt string, buf []byte) bool {
			for i, vp := range strings.SplitN(value, ":", 3) {
				if len(vp) == 0 {
					continue
				}
				var v uint8
				if err = parseInt(vp, &v); err != nil {
					return false
				} else {
					buf[i] = v
				}
			}
			return true
		}
		if len(mask) == 0 {
			buf = make([]byte, 11)
			if !parse(value, buf[8:]) {
				return
			}
		} else {
			buf = make([]byte, 14)
			if !parse(value, buf[8:]) || !parse(mask, buf[11:]) {
				return
			}
		}
	case "radiotap_ampdu_status":
		expType = STROXM_RADIOTAP_AMPDU_STATUS
		parse := func(txt string, buf []byte) bool {
			for i, vp := range strings.SplitN(value, ":", 4) {
				switch {
				case i == 0:
					var v uint32
					if err = parseInt(vp, &v); err != nil {
						return false
					} else {
						binary.LittleEndian.PutUint32(buf, v)
					}
				case i == 1:
					var v uint16
					if err = parseInt(vp, &v); err != nil {
						return false
					} else {
						binary.LittleEndian.PutUint16(buf[4:], v)
					}
				default:
					var v uint8
					if err = parseInt(vp, &v); err != nil {
						return false
					} else {
						buf[6+i] = v
					}
				}
			}
			return true
		}
		if len(mask) == 0 {
			buf = make([]byte, 16)
			if !parse(value, buf[8:]) {
				return
			}
		} else {
			buf = make([]byte, 24)
			if !parse(value, buf[8:]) || !parse(mask, buf[16:]) {
				return
			}
		}
	case "radiotap_vht":
		expType = STROXM_RADIOTAP_VHT
		parse := func(txt string, buf []byte) bool {
			idx := [...]int{0, 2, 3, 4, 8, 9, 10}
			for i, vp := range strings.SplitN(value, ":", 7) {
				switch i {
				case 0, 6:
					var v uint16
					if err = parseInt(vp, &v); err != nil {
						return false
					} else {
						binary.LittleEndian.PutUint16(buf[idx[i]:], v)
					}
				case 1, 2, 4, 5:
					var v uint8
					if err = parseInt(vp, &v); err != nil {
						return false
					} else {
						buf[idx[i]] = v
					}
				default:
					var v []byte
					if v, err = hex.DecodeString(vp); err != nil {
						return false
					} else {
						copy(buf[idx[i]:], v)
					}
				}
			}
			return true
		}
		if len(mask) == 0 {
			buf = make([]byte, 20)
			if !parse(value, buf[8:]) {
				return
			}
		} else {
			buf = make([]byte, 32)
			if !parse(value, buf[8:]) || !parse(mask, buf[20:]) {
				return
			}
		}
	}
	if len(buf) == 0 {
		err = fmt.Errorf("not a stratos rule %s", txt)
		return
	}
	binary.BigEndian.PutUint16(buf, uint16(OFPXMC_EXPERIMENTER))
	buf[2] = expType << 1
	if len(mask) > 0 {
		buf[2] |= 1
	}
	buf[3] = uint8(len(buf) - 4)
	binary.BigEndian.PutUint32(buf[4:], STRATOS_EXPERIMENTER_ID)

	eatLen = labelIdx + 1 + baseN
	return
}
