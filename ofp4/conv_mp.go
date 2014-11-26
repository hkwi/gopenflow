package ofp4

import (
	"encoding/binary"
)

type Desc []byte

func (self Desc) MfrDesc() []byte {
	return self[0:256]
}

func (self Desc) HwDesc() []byte {
	return self[256:512]
}

func (self Desc) SwDesc() []byte {
	return self[512:768]
}

func (self Desc) SerialNum() []byte {
	return self[768:800]
}

func (self Desc) DpDesc() []byte {
	return self[800:1056]
}

type FlowStatsRequest []byte

func (self FlowStatsRequest) TableId() uint8 {
	return self[0]
}

func (self FlowStatsRequest) OutPort() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self FlowStatsRequest) OutGroup() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self FlowStatsRequest) Cookie() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func (self FlowStatsRequest) CookieMask() uint64 {
	return binary.BigEndian.Uint64(self[24:])
}

func (self FlowStatsRequest) Match() Match {
	m := Match(self[32:])
	return Match(m[:align8(int(m.Length()))])
}

type FlowStats []byte

func (self FlowStats) Length() int {
	return int(binary.BigEndian.Uint16(self))
}

func (self FlowStats) TableId() uint8 {
	return self[2]
}

func (self FlowStats) DurationSec() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self FlowStats) DurationNsec() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self FlowStats) Priority() uint16 {
	return binary.BigEndian.Uint16(self[12:])
}

func (self FlowStats) IdleTimeout() uint16 {
	return binary.BigEndian.Uint16(self[14:])
}

func (self FlowStats) HardTimeout() uint16 {
	return binary.BigEndian.Uint16(self[16:])
}

func (self FlowStats) Flags() uint16 {
	return binary.BigEndian.Uint16(self[18:])
}

func (self FlowStats) Cookie() uint64 {
	return binary.BigEndian.Uint64(self[24:])
}

func (self FlowStats) PacketCount() uint64 {
	return binary.BigEndian.Uint64(self[32:])
}

func (self FlowStats) ByteCount() uint64 {
	return binary.BigEndian.Uint64(self[40:])
}

func (self FlowStats) Match() Match {
	m := Match(self[48:])
	return Match(m[:align8(int(m.Length()))])
}

func (self FlowStats) Instructions() []Instruction {
	var ret []Instruction
	end := self.Length()
	for cur := 48 + len(self.Match()); cur < end; {
		i := Instruction(self[cur:])
		ret = append(ret, Instruction(i[:i.Len()]))
		cur += i.Len()
	}
	return ret
}

func MakeFlowStats(
	tableId uint8,
	durationSec uint32,
	durationNsec uint32,
	priority uint16,
	idleTimeout uint16,
	hardTimeout uint16,
	flags uint16,
	cookie uint64,
	packetCount uint64,
	byteCount uint64,
	match Match,
	instructions Instruction,
) FlowStats {
	length := 48 + len(match) + len(instructions)
	self := make([]byte, length)

	binary.BigEndian.PutUint16(self, uint16(length))
	self[2] = tableId
	binary.BigEndian.PutUint32(self[4:], durationSec)
	binary.BigEndian.PutUint32(self[8:], durationNsec)
	binary.BigEndian.PutUint16(self[12:], priority)
	binary.BigEndian.PutUint16(self[14:], idleTimeout)
	binary.BigEndian.PutUint16(self[16:], hardTimeout)
	binary.BigEndian.PutUint16(self[18:], flags)
	binary.BigEndian.PutUint64(self[24:], cookie)
	binary.BigEndian.PutUint64(self[32:], packetCount)
	binary.BigEndian.PutUint64(self[40:], byteCount)
	copy(self[48:], match)
	copy(self[48+len(match):], instructions)
	return self
}

type AggregateStatsRequest []byte

func (self AggregateStatsRequest) TableId() uint8 {
	return self[0]
}

func (self AggregateStatsRequest) OutPort() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self AggregateStatsRequest) OutGroup() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self AggregateStatsRequest) Cookie() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func (self AggregateStatsRequest) CookieMask() uint64 {
	return binary.BigEndian.Uint64(self[24:])
}

func (self AggregateStatsRequest) Match() Match {
	m := Match(self[32:])
	return Match(m[:align8(int(m.Length()))])
}

type AggregateStatsReply []byte

func (self AggregateStatsReply) PacketCount() uint64 {
	return binary.BigEndian.Uint64(self)
}

func (self AggregateStatsReply) ByteCount() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}

func (self AggregateStatsReply) FlowCount() uint32 {
	return binary.BigEndian.Uint32(self[16:])
}

func MakeAggregateStatsReply(
	packetCount uint64,
	byteCount uint64,
	flowCount uint32) AggregateStatsReply {
	self := make([]byte, 24)
	binary.BigEndian.PutUint64(self, packetCount)
	binary.BigEndian.PutUint64(self[8:], byteCount)
	binary.BigEndian.PutUint32(self[16:], flowCount)
	return self
}

type TableStats []byte

func (self TableStats) TableId() uint8 {
	return self[0]
}

func (self TableStats) ActiveCount() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self TableStats) LookupCount() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}

func (self TableStats) MatchedCount() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func MakeTableStats(
	tableId uint8,
	activeCount uint32,
	lookupCount uint64,
	matchedCount uint64,
) TableStats {
	self := make([]byte, 24)
	self[0] = tableId
	binary.BigEndian.PutUint32(self[4:], activeCount)
	binary.BigEndian.PutUint64(self[8:], lookupCount)
	binary.BigEndian.PutUint64(self[16:], matchedCount)
	return self
}

type TableFeatures []byte

// Length is padded to 64 bits
func (self TableFeatures) Length() int {
	return int(binary.BigEndian.Uint64(self))
}

func (self TableFeatures) TableId() uint8 {
	return self[2]
}

func (self TableFeatures) Name() []byte {
	return self[8:40]
}

func (self TableFeatures) MetadataMatch() uint64 {
	return binary.BigEndian.Uint64(self[40:])
}

func (self TableFeatures) MetadataWrite() uint64 {
	return binary.BigEndian.Uint64(self[48:])
}

func (self TableFeatures) Config() uint32 {
	return binary.BigEndian.Uint32(self[56:])
}

func (self TableFeatures) MaxEntries() uint32 {
	return binary.BigEndian.Uint32(self[60:])
}

func (self TableFeatures) Properties() TableFeaturePropHeader {
	return TableFeaturePropHeader(self[64:])
}

func (self TableFeatures) Iter() []TableFeatures {
	var seq []TableFeatures
	for cur := 0; cur < len(self); {
		f := TableFeatures(self)
		seq = append(seq, f[:f.Length()])
		cur += f.Length()
	}
	return seq
}

func MakeTableFeatures(
	tableId uint8,
	name []byte,
	metadataMatch uint64,
	metadataWrite uint64,
	config uint32,
	maxEntries uint32,
	properties TableFeaturePropHeader,
) TableFeatures {
	length := 64 + len(properties)
	self := make([]byte, length)
	binary.BigEndian.PutUint16(self, uint16(length))
	self[2] = tableId
	copy(self[8:40], name)
	binary.BigEndian.PutUint64(self[40:], metadataMatch)
	binary.BigEndian.PutUint64(self[48:], metadataWrite)
	binary.BigEndian.PutUint32(self[56:], config)
	binary.BigEndian.PutUint32(self[60:], maxEntries)
	copy(self[64:], properties)
	return self
}

type PortStatsRequest []byte

func (self PortStatsRequest) PortNo() uint32 {
	return binary.BigEndian.Uint32(self)
}

type PortStats []byte

func (self PortStats) PortNo() uint32 {
	return binary.BigEndian.Uint32(self)
}

func (self PortStats) RxPackets() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}

func (self PortStats) TxPackets() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func (self PortStats) RxBytes() uint64 {
	return binary.BigEndian.Uint64(self[24:])
}

func (self PortStats) TxBytes() uint64 {
	return binary.BigEndian.Uint64(self[32:])
}

func (self PortStats) RxDropped() uint64 {
	return binary.BigEndian.Uint64(self[40:])
}

func (self PortStats) TxDropped() uint64 {
	return binary.BigEndian.Uint64(self[48:])
}

func (self PortStats) RxErrors() uint64 {
	return binary.BigEndian.Uint64(self[56:])
}

func (self PortStats) TxErrors() uint64 {
	return binary.BigEndian.Uint64(self[64:])
}

func (self PortStats) RxFrameErr() uint64 {
	return binary.BigEndian.Uint64(self[72:])
}

func (self PortStats) RxOverErr() uint64 {
	return binary.BigEndian.Uint64(self[80:])
}

func (self PortStats) RxCrcErr() uint64 {
	return binary.BigEndian.Uint64(self[88:])
}

func (self PortStats) Collisions() uint64 {
	return binary.BigEndian.Uint64(self[96:])
}

func (self PortStats) DurationSec() uint32 {
	return binary.BigEndian.Uint32(self[104:])
}

func (self PortStats) DurationNsec() uint32 {
	return binary.BigEndian.Uint32(self[108:])
}

func MakePortStats(
	portNo uint32,
	rxPackets uint64,
	txPackets uint64,
	rxBytes uint64,
	txBytes uint64,
	rxDropped uint64,
	txDropped uint64,
	rxErrors uint64,
	txErrors uint64,
	rxFrameErr uint64,
	rxOverErr uint64,
	rxCrcErr uint64,
	collisions uint64,
	durationSec uint32,
	durationNsec uint32,
) PortStats {
	self := make([]byte, 112)
	binary.BigEndian.PutUint32(self, portNo)
	binary.BigEndian.PutUint64(self[8:], rxPackets)
	binary.BigEndian.PutUint64(self[16:], txPackets)
	binary.BigEndian.PutUint64(self[24:], rxBytes)
	binary.BigEndian.PutUint64(self[32:], txBytes)
	binary.BigEndian.PutUint64(self[40:], rxDropped)
	binary.BigEndian.PutUint64(self[48:], txDropped)
	binary.BigEndian.PutUint64(self[56:], rxErrors)
	binary.BigEndian.PutUint64(self[64:], txErrors)
	binary.BigEndian.PutUint64(self[72:], rxFrameErr)
	binary.BigEndian.PutUint64(self[80:], rxOverErr)
	binary.BigEndian.PutUint64(self[88:], rxCrcErr)
	binary.BigEndian.PutUint64(self[96:], collisions)
	binary.BigEndian.PutUint32(self[104:], durationSec)
	binary.BigEndian.PutUint32(self[108:], durationNsec)
	return self
}

type GroupDesc []byte

// Length of this entry.
func (self GroupDesc) Length() int {
	return int(binary.BigEndian.Uint16(self))
}

func (self GroupDesc) Type() uint8 {
	return self[2]
}

func (self GroupDesc) GroupId() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self GroupDesc) Buckets() Bucket {
	return Bucket(self[8:self.Length()])
}

func (self GroupDesc) Iter() []GroupDesc {
	var seq []GroupDesc
	for cur := 0; cur < len(self); {
		desc := GroupDesc(self[cur:])
		seq = append(seq, desc[:desc.Length()])
		cur += desc.Length()
	}
	return seq
}

func MakeGroupDesc(ofpgt uint8, groupId uint32, buckets Bucket) GroupDesc {
	length := 8 + len(buckets)
	self := make([]byte, length)
	binary.BigEndian.PutUint16(self, uint16(length))
	self[2] = ofpgt
	binary.BigEndian.PutUint32(self[4:], groupId)
	copy(self[8:], buckets)
	return self
}

type GroupFeatures []byte

func (self GroupFeatures) Types() uint32 {
	return binary.BigEndian.Uint32(self)
}

func (self GroupFeatures) Capabilities() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self GroupFeatures) MaxGroups() [4]uint32 {
	var ret [4]uint32
	ret[0] = binary.BigEndian.Uint32(self[8:])
	ret[1] = binary.BigEndian.Uint32(self[12:])
	ret[2] = binary.BigEndian.Uint32(self[16:])
	ret[3] = binary.BigEndian.Uint32(self[20:])
	return ret
}

func (self GroupFeatures) Actions() [4]uint32 {
	var ret [4]uint32
	ret[0] = binary.BigEndian.Uint32(self[24:])
	ret[1] = binary.BigEndian.Uint32(self[28:])
	ret[2] = binary.BigEndian.Uint32(self[32:])
	ret[3] = binary.BigEndian.Uint32(self[36:])
	return ret
}

func MakeGroupFeatures(
	types uint32,
	capabilities uint32,
	maxGroups [4]uint32,
	actions [4]uint32) GroupFeatures {
	self := make([]byte, 40)
	binary.BigEndian.PutUint32(self, types)
	binary.BigEndian.PutUint32(self[4:], capabilities)
	for i, v := range maxGroups {
		binary.BigEndian.PutUint32(self[8+4*i:], v)
	}
	for i, v := range actions {
		binary.BigEndian.PutUint32(self[24+4*i:], v)
	}
	return self
}

type MeterMultipartRequest []byte

func (self MeterMultipartRequest) MeterId() uint32 {
	return binary.BigEndian.Uint32(self)
}

type MeterBandStats []byte

func (self MeterBandStats) PacketBandCount() uint64 {
	return binary.BigEndian.Uint64(self)
}

func (self MeterBandStats) ByteBandCount() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}

func (self MeterBandStats) Iter() []MeterBandStats {
	var seq []MeterBandStats
	for cur := 0; cur < len(self); cur += 16 {
		seq = append(seq, self[cur:cur+16])
	}
	return seq
}

func MakeMeterBandStats(packetBandCount, byteBandCount uint64) MeterBandStats {
	self := make([]byte, 16)
	binary.BigEndian.PutUint64(self, packetBandCount)
	binary.BigEndian.PutUint64(self, byteBandCount)
	return self
}

type MeterStats []byte

func (self MeterStats) MeterId() uint32 {
	return binary.BigEndian.Uint32(self)
}

func (self MeterStats) Len() int {
	return int(binary.BigEndian.Uint16(self[4:]))
}

func (self MeterStats) FlowCount() uint32 {
	return binary.BigEndian.Uint32(self[12:])
}

func (self MeterStats) PacketInCount() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func (self MeterStats) ByteInCount() uint64 {
	return binary.BigEndian.Uint64(self[24:])
}

func (self MeterStats) DurationSec() uint32 {
	return binary.BigEndian.Uint32(self[32:])
}

func (self MeterStats) DurationNsec() uint32 {
	return binary.BigEndian.Uint32(self[36:])
}

func (self MeterStats) BandStats() MeterBandStats {
	return MeterBandStats(self[40:self.Len()])
}

func (self MeterStats) Iter() []MeterStats {
	var seq []MeterStats
	for cur := 0; cur < len(self); {
		stat := MeterStats(self[cur:])
		seq = append(seq, stat[:stat.Len()])
		cur += stat.Len()
	}
	return seq
}

func MakeMeterStats(
	meterId uint32,
	flowCount uint32,
	packetInCount uint64,
	byteInCount uint64,
	durationSec uint32,
	durationNsec uint32,
	bands MeterBandStats) MeterStats {
	length := 40 + len(bands)
	self := make([]byte, length)
	binary.BigEndian.PutUint32(self, meterId)
	binary.BigEndian.PutUint16(self[4:], uint16(length))
	binary.BigEndian.PutUint32(self[12:], flowCount)
	binary.BigEndian.PutUint64(self[16:], packetInCount)
	binary.BigEndian.PutUint64(self[24:], byteInCount)
	binary.BigEndian.PutUint32(self[32:], durationSec)
	binary.BigEndian.PutUint32(self[36:], durationNsec)
	copy(self[40:], bands)
	return self
}

type MeterBandHeader []byte

func (self MeterBandHeader) Type() uint16 {
	return binary.BigEndian.Uint16(self)
}

/*
 * Length in bytes of this band
 */
func (self MeterBandHeader) Len() int {
	return int(binary.BigEndian.Uint16(self[2:]))
}

func (self MeterBandHeader) Rate() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self MeterBandHeader) BurstSize() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self MeterBandHeader) Iter() []MeterBandHeader {
	var ret []MeterBandHeader
	for cur := 0; cur < len(self); {
		b := MeterBandHeader(self[cur:])
		ret = append(ret, b[:b.Len()])
		cur += b.Len()
	}
	return ret
}

type MeterBandDrop []byte

func MakeMeterBandDrop(rate, burstSize uint32) MeterBandDrop {
	self := make([]byte, 16)
	binary.BigEndian.PutUint16(self, OFPMBT_DROP)
	binary.BigEndian.PutUint16(self[2:], 16)
	binary.BigEndian.PutUint32(self[4:], rate)
	binary.BigEndian.PutUint32(self[8:], burstSize)
	return self
}

type MeterBandDscpRemark []byte

func (self MeterBandDscpRemark) PrecLevel() uint8 {
	return self[12]
}

func MakeMeterBandDscpRemark(rate, burstSize uint32, precLevel uint8) MeterBandDscpRemark {
	self := make([]byte, 16)
	binary.BigEndian.PutUint16(self, OFPMBT_DSCP_REMARK)
	binary.BigEndian.PutUint16(self[2:], 16)
	binary.BigEndian.PutUint32(self[4:], rate)
	binary.BigEndian.PutUint32(self[8:], burstSize)
	self[12] = precLevel
	return self
}

type MeterBandExperimenter []byte

func (self MeterBandExperimenter) Experimenter() uint32 {
	return binary.BigEndian.Uint32(self[12:])
}

func (self MeterBandExperimenter) AppendData(data []byte) MeterBandExperimenter {
	length := len(self) + len(data)
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	return append(self, data...)
}

func MakeMeterBandExperimenter(rate, burstSize, experimenter uint32) MeterBandExperimenter {
	self := make([]byte, 16)
	binary.BigEndian.PutUint16(self, OFPMBT_EXPERIMENTER)
	binary.BigEndian.PutUint16(self[2:], 16)
	binary.BigEndian.PutUint32(self[4:], rate)
	binary.BigEndian.PutUint32(self[8:], burstSize)
	binary.BigEndian.PutUint32(self[12:], experimenter)
	return self
}

type MeterConfig []byte

func (self MeterConfig) Length() int {
	return int(binary.BigEndian.Uint16(self))
}

func (self MeterConfig) Flags() uint16 {
	return binary.BigEndian.Uint16(self[2:])
}

func (self MeterConfig) MeterId() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self MeterConfig) Bands() MeterBandHeader {
	return MeterBandHeader(self[8:])
}

func MakeMeterConfig(flags uint16, meterId uint32, bands MeterBandHeader) MeterConfig {
	length := 8 + len(bands)
	self := make([]byte, length)
	binary.BigEndian.PutUint16(self, uint16(length))
	binary.BigEndian.PutUint16(self[2:], flags)
	binary.BigEndian.PutUint32(self[4:], meterId)
	copy(self[8:], bands)
	return self
}

type MeterFeatures []byte

func (self MeterFeatures) MaxMeter() uint32 {
	return binary.BigEndian.Uint32(self)
}

func (self MeterFeatures) BandTypes() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self MeterFeatures) Capabilities() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self MeterFeatures) MaxBands() uint8 {
	return self[12]
}

func (self MeterFeatures) MaxColor() uint8 {
	return self[13]
}

type ExperimenterMultipartHeader []byte

func (self ExperimenterMultipartHeader) Experimenter() uint32 {
	return binary.BigEndian.Uint32(self)
}

func (self ExperimenterMultipartHeader) ExpType() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}
