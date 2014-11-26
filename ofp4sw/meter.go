package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
	"sync"
	"time"
)

type packetDrop struct{}

func (_ packetDrop) Error() string {
	return "meter drop packet"
}

const baseInterval = 2.0

type meter struct {
	flagPkts    bool
	flagBurst   bool
	flagStats   bool
	lock        *sync.Mutex
	created     time.Time
	packetCount uint64
	byteCount   uint64
	bands       []band
	highestBand band

	meterTime time.Time
	rate      float64
}

func (m *meter) process(data *frame) error {
	var length int
	if eth, err := data.data(); err != nil {
		return err
	} else {
		length = len(eth)
	}

	now := time.Now()
	meterInterval := float64(now.Sub(m.meterTime)) / float64(time.Second)

	m.lock.Lock()
	defer m.lock.Unlock()

	if m.flagStats {
		m.packetCount++
		m.byteCount += uint64(length)
	}

	inc := float64(length*8) / 1000.0 // kilobits
	if m.flagPkts {
		inc = 1
	}
	if m.flagBurst {
		for _, bi := range m.bands {
			drain := meterInterval * float64(bi.getRate()) * 8 / 1000.0
			if m.flagPkts {
				drain = meterInterval * float64(bi.getRate())
			}
			switch b := bi.(type) {
			case bandDrop:
				b.bucket -= drain
				if b.bucket < 0 {
					b.bucket = 0
				}
			case bandDscpRemark:
				b.bucket -= drain
				if b.bucket < 0 {
					b.bucket = 0
				}
			case bandExperimenter:
				b.bucket -= drain
				if b.bucket < 0 {
					b.bucket = 0
				}
			default:
				panic("Unexpected band")
			}
		}
		for _, bi := range m.bands {
			switch b := bi.(type) {
			case bandDrop:
				if b.bucket+inc > float64(b.burstSize) {
					if m.flagStats {
						b.packetCount++
						b.byteCount += uint64(length)
					}
					return &packetDrop{}
				}
			case bandDscpRemark:
				if b.bucket+inc > float64(b.burstSize) {
					if err := b.remark(data); err != nil {
						return err
					}
					if m.flagStats {
						b.packetCount++
						b.byteCount += uint64(length)
					}
					return nil
				}
			case bandExperimenter:
				if b.bucket+inc > float64(b.burstSize) {
					// do nothing
					if m.flagStats {
						b.packetCount++
						b.byteCount += uint64(length)
					}
					return nil
				}
			default:
				panic("Unexpected band")
			}
		}
		for _, bi := range m.bands {
			switch b := bi.(type) {
			case bandDrop:
				b.bucket += inc
			case bandDscpRemark:
				b.bucket += inc
			case bandExperimenter:
				b.bucket += inc
			default:
				panic("Unexpected band")
			}
		}
	}

	rate := (m.rate*baseInterval + inc) / (baseInterval + meterInterval)

	if m.highestBand != nil && rate > float64(m.highestBand.getRate()) {
		switch b := m.highestBand.(type) {
		case bandDrop:
			if m.flagStats {
				b.packetCount++
				b.byteCount += uint64(length)
			}
			return &packetDrop{}
		case bandDscpRemark:
			if m.flagStats {
				b.packetCount++
				b.byteCount += uint64(length)
			}
			return b.remark(data)
		case bandExperimenter:
			// do nothing
			if m.flagStats {
				b.packetCount++
				b.byteCount += uint64(length)
			}
			return nil
		default:
			panic("Unexpected band")
		}
	}
	m.meterTime = now
	m.rate = rate
	return nil
}

type band interface {
	getRate() uint32
	getPacketCount() uint64
	getByteCount() uint64
	MarshalBinary() ([]byte, error)
}

type bandCommon struct {
	rate      uint32
	burstSize uint32

	bucket      float64
	packetCount uint64
	byteCount   uint64
}

func (self bandCommon) getRate() uint32 {
	return self.rate
}

func (self bandCommon) getPacketCount() uint64 {
	return self.packetCount
}

func (self bandCommon) getByteCount() uint64 {
	return self.byteCount
}

type bandDrop struct {
	bandCommon
}

func (self bandDrop) MarshalBinary() ([]byte, error) {
	return ofp4.MakeMeterBandDrop(self.rate, self.burstSize), nil
}

type bandDscpRemark struct {
	bandCommon
	precLevel uint8
}

func (self bandDscpRemark) MarshalBinary() ([]byte, error) {
	return ofp4.MakeMeterBandDscpRemark(self.rate, self.burstSize, self.precLevel), nil
}

func (self bandDscpRemark) remark(data *frame) error {
	if v, err := data.getValue(ofp4.OXM_OF_IP_DSCP); err != nil {
		return nil
	} else {
		phb := uint8(v[0]) >> 3
		prec := uint8(v[0]) >> 1 & 0x03
		if prec != 0 && (phb == 1 || phb == 2 || phb == 3 || phb == 4) {
			prec += self.precLevel
			if prec > 0x03 {
				prec = 0x03
			}
			if err := data.setValue(oxmBasic{
				Type:  ofp4.OXM_OF_IP_DSCP,
				Value: []byte{byte(phb<<3 | prec<<1)},
				Mask:  []byte{0xff},
			}); err != nil {
				return err
			}
		}
		return nil
	}
}

type bandExperimenter struct {
	bandCommon
	experimenter uint32
	data         []byte
}

func (self bandExperimenter) MarshalBinary() ([]byte, error) {
	return ofp4.MakeMeterBandExperimenter(self.rate, self.burstSize, self.experimenter).AppendData(self.data), nil
}

type bandList []band

func (self *bandList) UnmarshalBinary(data []byte) error {
	msgs := ofp4.MeterBandHeader(data).Iter()
	bands := make([]band, len(msgs))
	for i, msg := range msgs {
		var b band
		switch msg.Type() {
		case ofp4.OFPMBT_DROP:
			b = bandDrop{
				bandCommon: bandCommon{
					rate:      msg.Rate(),
					burstSize: msg.BurstSize(),
				},
			}
		case ofp4.OFPMBT_DSCP_REMARK:
			b = bandDscpRemark{
				bandCommon: bandCommon{
					rate:      msg.Rate(),
					burstSize: msg.BurstSize(),
				},
				precLevel: ofp4.MeterBandDscpRemark(msg).PrecLevel(),
			}
		case ofp4.OFPMBT_EXPERIMENTER:
			b = bandExperimenter{
				bandCommon: bandCommon{
					rate:      msg.Rate(),
					burstSize: msg.BurstSize(),
				},
				experimenter: ofp4.MeterBandExperimenter(msg).Experimenter(),
				data:         msg[16:],
			}
		}
		bands[i] = b
	}
	*self = bands
	return nil
}

func (pipe *Pipeline) deleteMeterInside(meterId uint32) error {
	if _, exists := pipe.meters[meterId]; exists {
		delete(pipe.meters, meterId)
		pipe.filterFlowsInside(flowFilter{
			opUnregister: true,
			outPort:      ofp4.OFPP_ANY,
			outGroup:     ofp4.OFPG_ANY,
			meterId:      meterId,
		})
	} else {
		return ofp4.MakeErrorMsg(
			ofp4.OFPET_METER_MOD_FAILED,
			ofp4.OFPMMFC_UNKNOWN_METER,
		)
	}
	return nil
}
