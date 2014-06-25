package ofp4

type OfpHelloElemVersionbitmapEx struct {
	OfpHelloElemVersionbitmap
	Bitmaps []uint32
}

type OfpHelloEx struct {
	OfpHello
	Elements []interface{}
}

type OfpErrorMsgEx struct {
	OfpErrorMsg
	Data []byte
}

type OfpErrorExperimenterMsgEx struct {
	OfpErrorExperimenterMsg
	Data []byte
}

type OfpHeaderEx struct {
	OfpHeader
	Data []byte
}

type OfpExperimenterHeaderEx struct {
	OfpExperimenterHeader
	Data []byte
}

type OfpMatchIf interface {
	GetLength() uint16
}

type OfpMatchEx struct {
	OfpMatch
	Fields []byte
}

type OfpPacketInEx struct {
	Header   OfpHeader
	BufferId uint32
	TotalLen uint16
	Reason   uint8
	TableId  uint8
	Cookie   uint64
	Match    OfpMatchIf
	Data     []byte
}

type OfpFlowRemovedEx struct {
	Header       OfpHeader
	Cookie       uint64
	Priority     uint16
	Reason       uint8
	TableId      uint8
	DurationSec  uint32
	DurationNsec uint32
	IdleTimeout  uint16
	HardTimeout  uint16
	PacketCount  uint64
	ByteCount    uint64
	Match        OfpMatchIf
}

type OfpActionIf interface {
	GetLen() uint16
}

type OfpPacketOutEx struct {
	OfpPacketOut
	Actions []OfpActionIf
	Data    []byte
}

type OfpActionSetFieldEx struct {
	OfpActionSetField
	Data []byte
}

type OfpActionExperimenterHeaderEx struct {
	OfpActionExperimenterHeader
	Data []byte
}

type OfpInstructionIf interface {
	GetLen() uint16
}

type OfpFlowModEx struct {
	Header       OfpHeader
	Cookie       uint64
	CookieMask   uint64
	TableId      uint8
	Command      uint8
	IdleTimeout  uint16
	HardTimeout  uint16
	Priority     uint16
	BufferId     uint32
	OutPort      uint32
	OutGroup     uint32
	Flags        uint16
	Match        OfpMatchIf
	Instructions []OfpInstructionIf
}

type OfpInstructionActionsEx struct {
	OfpInstructionActions
	Actions []OfpActionIf
}

type OfpInstructionExperimenterEx struct {
	OfpInstructionExperimenter
	Data []byte
}

type OfpBucketIf interface {
	GetLen() uint16
}

type OfpBucketEx struct {
	OfpBucket
	Actions []OfpActionIf
}

type OfpGroupModEx struct {
	OfpGroupMod
	Buckets []OfpBucketIf
}

type OfpMeterStatsEx struct {
	OfpMeterStats
	BandStats []OfpMeterBandStats
}

type OfpMeterConfigEx struct {
	OfpMeterConfig
	Bands []OfpMeterBandHeader
}

type OfpMultipartPayloadIf interface{}

type OfpMultipartRequestEx struct {
	OfpMultipartRequest
	Body OfpMultipartPayloadIf
}

type OfpMultipartReplyEx struct {
	OfpMultipartReply
	Body OfpMultipartPayloadIf
}

type OfpFlowStatsRequestEx struct {
	TableId    uint8
	OutPort    uint32
	OutGroup   uint32
	Cookie     uint64
	CookieMask uint64
	Match      OfpMatchIf
}

type OfpAggregateStatsRequestEx struct {
	TableId    uint8
	OutPort    uint32
	OutGroup   uint32
	Cookie     uint64
	CookieMask uint64
	Match      OfpMatchIf
}

type OfpFlowStatsEx struct {
	Length       uint16
	TableId      uint8
	DurationSec  uint32
	DurationNsec uint32
	Priority     uint16
	IdleTimeout  uint16
	HardTimeout  uint16
	Flags        uint16
	Cookie       uint64
	PacketCount  uint64
	ByteCount    uint64
	Match        OfpMatchIf
	Instructions []OfpInstructionIf
}

type OfpGroupStatsEx struct {
	OfpGroupStats
	BucketStats []OfpBucketCounter
}

type OfpGroupDescEx struct {
	OfpGroupDesc
	Buckets []OfpBucketIf
}

type OfpTableFeaturePropIf interface {
	GetLength() uint16
}

type OfpTableFeaturesEx struct {
	OfpTableFeatures
	Properties []OfpTableFeaturePropIf
}

type OfpTableFeaturePropInstructionsEx struct {
	OfpTableFeaturePropInstructions
	InstructionIds []OfpInstructionIf
}

type OfpTableFeaturePropNextTablesEx struct {
	OfpTableFeaturePropNextTables
	NextTableIds []uint8
}

type OfpTableFeaturePropActionsEx struct {
	OfpTableFeaturePropActions
	ActionIds []OfpActionIf
}

type OfpTableFeaturePropOxmEx struct {
	OfpTableFeaturePropOxm
	OxmIds []uint32
}

type OfpTableFeaturePropExperimenterEx struct {
	OfpTableFeaturePropExperimenter
	Data []byte
}

type OfpExperimenterMultipartHeaderEx struct {
	OfpExperimenterMultipartHeader
	Data []byte
}

type OfpQueueGetConfigReplyEx struct {
	OfpQueueGetConfigReply
	Queues []OfpPacketQueueEx
}

type OfpPacketQueueEx struct {
	OfpPacketQueue
	Properties []OfpQueuePropIf
}

type OfpQueuePropIf interface {
	GetLen() uint16
}

type OfpQueuePropExperimenterEx struct {
	OfpQueuePropExperimenter
	Data []byte
}

type OfpMeterModEx struct {
	OfpMeterMod
	Bands []OfpMeterBandHeader
}
