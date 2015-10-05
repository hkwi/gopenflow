// +build linux

package gopenflow

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/oxm"
	"github.com/hkwi/nlgo"
	_ "github.com/hkwi/suppl/gopacket/layers"
)

func makeLwapp(dot11pkt, mac []byte, fragmentId uint8) ([]byte, error) {
	//
	// Ether HDR + LWAPP HDR + 802.11(without FCS)
	//
	// as wireshark lwapp dissector handles.
	//
	pkt := make([]byte, 20, 20+len(dot11pkt))

	// eth dst is any
	copy(pkt[6:12], mac)                           // eth src is mac
	binary.BigEndian.PutUint16(pkt[12:14], 0x88bb) // LWAPP(L2)

	// LWAPP header
	pkt[15] = fragmentId                                          // LWAPP Frag ID
	binary.BigEndian.PutUint16(pkt[16:18], uint16(len(dot11pkt))) // LWAPP Length
	// Status/WLANs is zero

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

func FrameFromRadiotap(rt *layers.RadioTap, mac []byte, fragmentId uint8) (Frame, error) {
	var status [2]uint8

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
		status[0] = uint8(rt.DBMAntennaSignal) // RSSI in dBm
		radiotapAdd(oxm.STROXM_RADIOTAP_DBM_ANTSIGNAL, []byte{uint8(rt.DBMAntennaSignal)})
	}
	if rt.Present.DBMAntennaNoise() {
		if rt.Present.DBMAntennaSignal() {
			status[1] = uint8(rt.DBMAntennaSignal - rt.DBMAntennaNoise) // SNR in dB
		}
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
	if rt.Flags.FCS() {
		dot11 = dot11[:len(dot11)-4] // remove FCS
	}

	if data, err := makeLwapp(dot11, mac, fragmentId); err != nil {
		return Frame{}, err
	} else {
		copy(data[18:], status[:])

		return Frame{
			Data: data,
			Oob:  oob,
		}, nil
	}
}

func (self *Frame) Dot11() ([]byte, error) {
	// requires LWAPP gopacket registration here
	dpkt := gopacket.NewPacket(self.Data, layers.LayerTypeEthernet, gopacket.Lazy)

	if dot11Layer := dpkt.Layer(layers.LayerTypeDot11); dot11Layer != nil {
		dot11, _ := dot11Layer.(*layers.Dot11)
		payload := make([]byte, len(dot11.Contents)+len(dot11.Payload)+4)
		copy(payload, dot11.Contents)
		copy(payload[len(dot11.Contents):], dot11.Payload)
		binary.LittleEndian.PutUint32(payload[len(dot11.Contents)+len(dot11.Payload):], dot11.Checksum)
		return payload, nil
	}
	return nil, fmt.Errorf("no dot11 layer")
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

func FrameFromNlAttr(attrs nlgo.AttrMap, mac []byte, fragmentId uint8) (Frame, error) {
	freq := uint32(attrs.Get(nlgo.NL80211_ATTR_WIPHY_FREQ).(nlgo.U32))
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
			Value:        []byte{uint8(t.(nlgo.U32))},
		}.Bytes()...)
	}
	if data, err := makeLwapp([]byte(attrs.Get(nlgo.NL80211_ATTR_FRAME).(nlgo.Binary)), mac, fragmentId); err != nil {
		return Frame{}, err
	} else {
		return Frame{
			Data: data,
			Oob:  oob,
		}, nil
	}
}
