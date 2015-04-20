// +build linux

package gopenflow

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/oxm"
	"github.com/hkwi/nlgo"
	layers2 "github.com/hkwi/suppl/gopacket/layers"
)

func makeLwapp(dot11pkt []byte) ([]byte, error) {
	//
	// Ether HDR + LWAPP HDR + 802.11
	//
	pkt := make([]byte, 20, 20+len(dot11pkt))

	dpkt := gopacket.NewPacket(dot11pkt, layers.LayerTypeDot11, gopacket.Lazy)
	if dtl := dpkt.Layer(layers.LayerTypeDot11); dtl == nil {
		return nil, fmt.Errorf("dot11 layer error")
	} else if dt, ok := dtl.(*layers.Dot11); !ok {
		return nil, fmt.Errorf("dot11 layer type error")
	} else {
		dst := dt.Address1
		if dt.Flags.ToDS() {
			dst = dt.Address3
		}
		copy(pkt[0:6], dst)

		src := dt.Address2
		if dt.Flags.FromDS() {
			if dt.Flags.ToDS() {
				src = dt.Address4
			} else {
				src = dt.Address3
			}
		}
		copy(pkt[6:12], src)

		binary.BigEndian.PutUint16(pkt[12:14], 0x88bb) // LWAPP(L2)

		// LWAPP header
		// LWAPP Frag ID is zero
		binary.BigEndian.PutUint16(pkt[16:18], uint16(len(dot11pkt))) // LWAPP Length
		// Status/WLANs is zero
	}
	return append(pkt, dot11pkt...), nil
}

type oxmExperimenter struct {
	Experimenter uint32
	Field        uint8
	Type         uint16
	Value        []byte
}

func (self oxmExperimenter) Bytes() []byte {
	buf := make([]byte, 10+len(self.Value))
	hdr := uint32(0xffff0000)
	hdr |= uint32(self.Field) << 9
	hdr |= uint32(6 + len(self.Value))
	binary.BigEndian.PutUint32(buf, hdr)
	binary.BigEndian.PutUint32(buf[4:], self.Experimenter)
	binary.BigEndian.PutUint16(buf[8:], self.Type)
	copy(buf[10:], self.Value)
	return buf
}

func fetchOxmExperimenter(buf []byte) []oxmExperimenter {
	var ret []oxmExperimenter
	for len(buf) > 10 {
		hdr := binary.BigEndian.Uint32(buf)
		length := int(hdr & 0x7F)
		if (hdr >> 16) == 0xffff {
			ret = append(ret, oxmExperimenter{
				Experimenter: binary.BigEndian.Uint32(buf[4:]),
				Field:        uint8(hdr >> 9),
				Type:         binary.BigEndian.Uint16(buf[8:]),
				Value:        buf[10 : 4+length],
			})
		}
		buf = buf[4+length:]
	}
	return ret
}

func FrameFromRadiotap(rt *layers.RadioTap) (Frame, error) {
	// XXX: FCS
	oob := oxmExperimenter{
		Experimenter: oxm.STRATOS_EXPERIMENTER_ID,
		Field:        oxm.STRATOS_OXM_FIELD_BASIC,
		Type:         oxm.STROXM_BASIC_DOT11,
		Value:        []byte{1},
	}.Bytes()
	radiotapAdd := func(expType uint16, value []byte) {
		oob = append(oob, oxmExperimenter{
			Experimenter: oxm.STRATOS_EXPERIMENTER_ID,
			Field:        oxm.STRATOS_OXM_FIELD_RADIOTAP,
			Type:         expType,
			Value:        value,
		}.Bytes()...)
	}
	if rt.Present.TSFT() {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, rt.TSFT)
		radiotapAdd(oxm.STROXM_RADIOTAP_TSFT, buf)
	}
	if rt.Present.Flags() {
		radiotapAdd(oxm.STROXM_RADIOTAP_FLAGS, []byte{uint8(rt.Flags)})
	}
	if rt.Present.Rate() {
		radiotapAdd(oxm.STROXM_RADIOTAP_RATE, []byte{uint8(rt.Rate)})
	}
	if rt.Present.Channel() {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint16(buf, uint16(rt.ChannelFrequency))
		binary.LittleEndian.PutUint16(buf[2:], uint16(rt.ChannelFlags))
		radiotapAdd(oxm.STROXM_RADIOTAP_CHANNEL, buf)
	}
	if rt.Present.FHSS() {
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, rt.FHSS)
		radiotapAdd(oxm.STROXM_RADIOTAP_FHSS, buf)
	}
	if rt.Present.DBMAntennaSignal() {
		radiotapAdd(oxm.STROXM_RADIOTAP_DBM_ANTSIGNAL, []byte{uint8(rt.DBMAntennaSignal)})
	}
	if rt.Present.DBMAntennaNoise() {
		radiotapAdd(oxm.STROXM_RADIOTAP_DBM_ANTNOISE, []byte{uint8(rt.DBMAntennaNoise)})
	}
	if rt.Present.LockQuality() {
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, rt.LockQuality)
		radiotapAdd(oxm.STROXM_RADIOTAP_LOCK_QUALITY, buf)
	}
	if rt.Present.TxAttenuation() {
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, rt.TxAttenuation)
		radiotapAdd(oxm.STROXM_RADIOTAP_TX_ATTENUATION, buf)
	}
	if rt.Present.DBTxAttenuation() {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint16(buf, rt.DBTxAttenuation)
		radiotapAdd(oxm.STROXM_RADIOTAP_DB_TX_ATTENUATION, buf)
	}
	if rt.Present.DBMTxPower() {
		radiotapAdd(oxm.STROXM_RADIOTAP_DBM_TX_POWER, []byte{uint8(rt.DBMTxPower)})
	}
	if rt.Present.Antenna() {
		radiotapAdd(oxm.STROXM_RADIOTAP_ANTENNA, []byte{rt.Antenna})
	}
	if rt.Present.DBAntennaSignal() {
		radiotapAdd(oxm.STROXM_RADIOTAP_DB_ANTSIGNAL, []byte{uint8(rt.DBAntennaSignal)})
	}
	if rt.Present.DBAntennaNoise() {
		radiotapAdd(oxm.STROXM_RADIOTAP_DB_ANTNOISE, []byte{uint8(rt.DBAntennaNoise)})
	}
	if rt.Present.RxFlags() {
		// gopacket no-impl
	}
	if rt.Present.TxFlags() {
		// gopacket no-impl
	}
	if rt.Present.RtsRetries() {
		// gopacket no-impl
	}
	if rt.Present.DataRetries() {
		// gopacket no-impl
	}

	dot11 := rt.Payload
	if !rt.Flags.FCS() {
		dot11 = append(dot11, 0, 0, 0, 0) // append dummy FCS - because dot11 parser requires this
	}

	if data, err := makeLwapp(dot11); err != nil {
		return Frame{}, err
	} else {
		return Frame{
			Data: data,
			Oob:  oob,
		}, nil
	}
}

func (self *Frame) Dot11() ([]byte, error) {
	dpkt := gopacket.NewPacket(self.Data, layers.LayerTypeEthernet, gopacket.Lazy)
	if dtl := dpkt.Layer(layers2.LayerTypeLwapp); dtl == nil {
		return nil, fmt.Errorf("dot11 layer error")
	} else if dt, ok := dtl.(*layers2.Lwapp); !ok {
		return nil, fmt.Errorf("dot11 layer type error")
	} else if dt.NextLayerType() != layers.LayerTypeDot11 {
		return nil, fmt.Errorf("lwapp data packet required")
	} else {
		return dt.Payload, nil
	}
}

func (self *Frame) Radiotap() ([]byte, error) {
	if dot11pkt, err := self.Dot11(); err != nil {
		return nil, err
	} else {
		// dropping all of oob information here. by the way, kernel can handle
		// RADIOTAP_FLAGS and RADIOTAP_TX_FLAGS
		length := 8 + len(dot11pkt)
		pkt := make([]byte, 8, length)
		binary.LittleEndian.PutUint16(pkt[2:], uint16(length))
		pkt = append(pkt, dot11pkt...)
		return pkt, nil
	}
}

func FrameFromNlAttr(attrs nlgo.AttrList) (Frame, error) {
	freq := attrs.Get(nlgo.NL80211_ATTR_WIPHY_FREQ).(uint32)
	freqValue := make([]byte, 3)
	binary.LittleEndian.PutUint16(freqValue, uint16(freq))

	oob := oxmExperimenter{
		Experimenter: oxm.STRATOS_EXPERIMENTER_ID,
		Field:        oxm.STRATOS_OXM_FIELD_RADIOTAP,
		Type:         oxm.STROXM_RADIOTAP_CHANNEL,
		Value:        freqValue,
	}.Bytes()
	if t := attrs.Get(nlgo.NL80211_ATTR_RX_SIGNAL_DBM); t != nil {
		oob = append(oob, oxmExperimenter{
			Experimenter: oxm.STRATOS_EXPERIMENTER_ID,
			Field:        oxm.STRATOS_OXM_FIELD_RADIOTAP,
			Type:         oxm.STROXM_RADIOTAP_DBM_ANTSIGNAL,
			Value:        []byte{uint8(t.(uint32))},
		}.Bytes()...)
	}
	if data, err := makeLwapp(attrs.Get(nlgo.NL80211_ATTR_FRAME).([]byte)); err != nil {
		return Frame{}, err
	} else {
		return Frame{
			Data: data,
			Oob:  oob,
		}, nil
	}
}
