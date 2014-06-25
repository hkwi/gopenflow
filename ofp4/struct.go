package ofp4

type OfpHeader struct {
	Version uint8
	Type    uint8
	Length  uint16
	Xid     uint32
}

type OfpPort struct {
	PortNo     uint32
	_          [4]uint8
	HwAddr     [6]byte
	_          [2]uint8
	Name       [16]byte
	Config     uint32
	State      uint32
	Curr       uint32
	Advertised uint32
	Supported  uint32
	Peer       uint32
	CurrSpeed  uint32
	MaxSpeed   uint32
}

type OfpPacketQueue struct {
	QueueId uint32
	Port    uint32
	Len     uint16
	_       [6]uint8
	// Properties []OfpQueuePropIf
}

type OfpQueuePropHeader struct {
	Property uint16
	Len      uint16
	_        [4]uint8
}

func (queuePropHeader *OfpQueuePropHeader) GetLen() uint16 {
	return queuePropHeader.Len
}

type OfpQueuePropMinRate struct {
	PropHeader OfpQueuePropHeader
	Rate       uint16
	_          [6]uint8
}

func (queuePropHeader *OfpQueuePropMinRate) GetLen() uint16 {
	return queuePropHeader.PropHeader.Len
}

type OfpQueuePropMaxRate struct {
	PropHeader OfpQueuePropHeader
	Rate       uint16
	_          [6]uint8
}

func (queuePropHeader *OfpQueuePropMaxRate) GetLen() uint16 {
	return queuePropHeader.PropHeader.Len
}

type OfpQueuePropExperimenter struct {
	PropHeader   OfpQueuePropHeader
	Experimenter uint32
	_            [4]uint8
}

func (queuePropHeader *OfpQueuePropExperimenter) GetLen() uint16 {
	return queuePropHeader.PropHeader.Len
}

type OfpMatch struct {
	Type   uint16
	Length uint16
}

func (match *OfpMatch) GetLength() uint16 {
	return match.Length
}

type OfpOxmExperimenterHeader struct {
	OxmHeader    uint32
	Experimenter uint32
}

type OfpInstruction struct {
	Type uint16
	Len  uint16
}

type OfpInstructionGotoTable struct {
	Type    uint16
	Len     uint16
	TableId uint8
	_       [3]uint8
}

func (inst *OfpInstructionGotoTable) GetLen() uint16 {
	return inst.Len
}

type OfpInstructionWriteMetadata struct {
	Type         uint16
	Len          uint16
	_            [4]uint8
	Metadata     uint64
	MetadataMask uint64
}

func (inst *OfpInstructionWriteMetadata) GetLen() uint16 {
	return inst.Len
}

type OfpInstructionActions struct {
	Type uint16
	Len  uint16
	_    [4]uint8
	// actions []OfpActionHeader
}

func (inst *OfpInstructionActions) GetLen() uint16 {
	return inst.Len
}

type OfpInstructionMeter struct {
	Type    uint16
	Len     uint16
	MeterId uint32
}

func (inst *OfpInstructionMeter) GetLen() uint16 {
	return inst.Len
}

type OfpInstructionExperimenter struct {
	Type         uint16
	Len          uint16
	Experimenter uint32
}

func (inst *OfpInstructionExperimenter) GetLen() uint16 {
	return inst.Len
}

type OfpActionHeader struct {
	Type uint16
	Len  uint16
	_    [4]uint8
}

func (action *OfpActionHeader) GetLen() uint16 {
	return action.Len
}

type OfpActionOutput struct {
	Type   uint16
	Len    uint16
	Port   uint32
	MaxLen uint16
	_      [6]uint8
}

func (action *OfpActionOutput) GetLen() uint16 {
	return action.Len
}

type OfpActionGroup struct {
	Type    uint16
	Len     uint16
	GroupId uint32
}

func (action *OfpActionGroup) GetLen() uint16 {
	return action.Len
}

type OfpActionSetQueue struct {
	Type    uint16
	Len     uint16
	QueueId uint32
}

func (action *OfpActionSetQueue) GetLen() uint16 {
	return action.Len
}

type OfpActionMplsTtl struct {
	Type    uint16
	Len     uint16
	MplsTtl uint8
	_       [3]uint8
}

func (action *OfpActionMplsTtl) GetLen() uint16 {
	return action.Len
}

type OfpActionNwTtl struct {
	Type  uint16
	Len   uint16
	NwTtl uint8
	_     [3]uint8
}

func (action *OfpActionNwTtl) GetLen() uint16 {
	return action.Len
}

type OfpActionPush struct {
	Type      uint16
	Len       uint16
	Ethertype uint16
	_         [2]uint8
}

func (action *OfpActionPush) GetLen() uint16 {
	return action.Len
}

type OfpActionPopMpls struct {
	Type      uint16
	Len       uint16
	Ethertype uint16
	_         [2]uint8
}

func (action *OfpActionPopMpls) GetLen() uint16 {
	return action.Len
}

type OfpActionSetField struct {
	Type uint16
	Len  uint16
	// OXM TLV with PADDING
}

func (action *OfpActionSetField) GetLen() uint16 {
	return action.Len
}

type OfpActionExperimenterHeader struct {
	Type         uint16
	Len          uint16
	Experimenter uint32
}

func (action *OfpActionExperimenterHeader) GetLen() uint16 {
	return action.Len
}

type OfpSwitchFeatures struct {
	Header       OfpHeader
	DatapathId   uint64
	NBuffers     uint32
	NTables      uint8
	AuxiliaryId  uint8
	_            [2]uint8
	Capabilities uint32
	Reserved     uint32
}

type OfpSwitchConfig struct {
	Header      OfpHeader
	Flags       uint16
	MissSendLen uint16
}

type OfpTableMod struct {
	Header  OfpHeader
	TableId uint8
	_       [3]uint8
	Config  uint32
}

type OfpFlowMod struct {
	Header      OfpHeader
	Cookie      uint64
	CookieMask  uint64
	TableId     uint8
	Command     uint8
	IdleTimeout uint16
	HardTimeout uint16
	Priority    uint16
	BufferId    uint32
	OutPort     uint32
	OutGroup    uint32
	Flags       uint16
	_           [2]uint8
	Match       OfpMatch
	// instructions with PADDING
}

type OfpGroupMod struct {
	Header  OfpHeader
	Command uint16
	Type    uint8
	_       uint8
	GroupId uint32
	// bucket
}

type OfpBucket struct {
	Len        uint16
	Weight     uint16
	WatchPort  uint32
	WatchGroup uint32
	_          [4]uint8
	// actions
}

func (bucket *OfpBucket) GetLen() uint16 {
	return bucket.Len
}

type OfpPortMod struct {
	Header    OfpHeader
	PortNo    uint32
	_         [4]uint8
	HwAddr    [6]byte
	_         [2]uint8
	Config    uint32
	Mask      uint32
	Advertise uint32
	_         [4]uint8
}

type OfpMeterMod struct {
	Header  OfpHeader
	Command uint16
	Flags   uint16
	MeterId uint32
	// bands
}

type OfpMeterBandHeader struct {
	Type      uint16
	Len       uint16
	Rate      uint32
	BurstSize uint32
}

type OfpMeterBandDrop struct {
	Type      uint16
	Len       uint16
	Rate      uint32
	BurstSize uint32
	_         [4]uint8
}

type OfpMeterBandDscpRemark struct {
	Type      uint16
	Len       uint16
	Rate      uint32
	BurstSize uint32
	PrecLevel uint8
	_         [3]uint8
}

type OfpMeterBandExperimenter struct {
	Type         uint16
	Len          uint16
	Rate         uint32
	BurstSize    uint32
	Experimenter uint32
}

type OfpMultipartRequest struct {
	Header OfpHeader
	Type   uint16
	Flags  uint16
	_      [4]uint8
	// body
}

type OfpMultipartReply struct {
	Header OfpHeader
	Type   uint16
	Flags  uint16
	_      [4]uint8
	// body
}

type OfpDesc struct {
	MfrDesc   [256]byte
	HwDesc    [256]byte
	SwDesc    [256]byte
	SerialNum [32]byte
	DpDesc    [256]byte
}

type OfpFlowStatsRequest struct {
	TableId    uint8
	_          [3]uint8
	OutPort    uint32
	OutGroup   uint32
	_          [4]uint8
	Cookie     uint64
	CookieMask uint64
	Match      OfpMatch
}

type OfpFlowStats struct {
	Length       uint16
	TableId      uint8
	_            uint8
	DurationSec  uint32
	DurationNsec uint32
	Priority     uint16
	IdleTimeout  uint16
	HardTimeout  uint16
	Flags        uint16
	_            [4]uint8
	Cookie       uint64
	PacketCount  uint64
	ByteCount    uint64
	Match        OfpMatch
	// instructions
}

type OfpAggregateStatsRequest struct {
	TableId    uint8
	_          [3]uint8
	OutPort    uint32
	OutGroup   uint32
	_          [4]uint8
	Cookie     uint64
	CookieMask uint64
	Match      OfpMatch
}

type OfpAggregateStatsReply struct {
	PacketCount uint64
	ByteCount   uint64
	FlowCount   uint32
	_           [4]uint8
}

type OfpTableStats struct {
	TableId      uint8
	_            [3]uint8
	ActiveCount  uint32
	LookupCount  uint64
	MatchedCount uint64
}

type OfpTableFeatures struct {
	Length        uint16
	TableId       uint8
	_             [5]uint8
	Name          [32]byte
	MetadataMatch uint64
	MetadataWrite uint64
	Config        uint32
	MaxEntries    uint32
	// properties
}

func (feat *OfpTableFeatures) GetLength() uint16 {
	return feat.Length
}

type OfpTableFeaturePropHeader struct {
	Type   uint16
	Length uint16
}

func (feat *OfpTableFeaturePropHeader) GetLength() uint16 {
	return feat.Length
}

type OfpTableFeaturePropInstructions struct {
	Type   uint16
	Length uint16
	// instructino_ids
}

func (feat *OfpTableFeaturePropInstructions) GetLength() uint16 {
	return feat.Length
}

type OfpTableFeaturePropNextTables struct {
	Type   uint16
	Length uint16
	// next_table_ids [0]uint8
}

func (feat *OfpTableFeaturePropNextTables) GetLength() uint16 {
	return feat.Length
}

type OfpTableFeaturePropActions struct {
	Type   uint16
	Length uint16
	// action_ids [0]OfpActionHeader
}

func (feat *OfpTableFeaturePropActions) GetLength() uint16 {
	return feat.Length
}

type OfpTableFeaturePropOxm struct {
	Type   uint16
	Length uint16
	// oxm_ids [0]uint32
}

func (feat *OfpTableFeaturePropOxm) GetLength() uint16 {
	return feat.Length
}

type OfpTableFeaturePropExperimenter struct {
	Type          uint16
	Length        uint16
	Experiimenter uint32
	ExpType       uint32
	// data [0]uint32
}

func (feat *OfpTableFeaturePropExperimenter) GetLength() uint16 {
	return feat.Length
}

type OfpPortStatsRequest struct {
	PortNo uint32
	_      [4]uint8
}

type OfpPortStats struct {
	PortNo       uint32
	_            [4]uint8
	RxPackets    uint64
	TxPackets    uint64
	RxBytes      uint64
	TxBytes      uint64
	RxDropped    uint64
	TxDropped    uint64
	RxErrors     uint64
	TxErrors     uint64
	RxFrameErr   uint64
	RxOverErr    uint64
	RxCrcErr     uint64
	Collisions   uint64
	DurationSec  uint32
	DurationNsec uint32
}

type OfpQueueStatsRequest struct {
	PortNo  uint32
	QueueId uint32
}

type OfpQueueStats struct {
	PortNo       uint32
	QueueId      uint32
	TxBytes      uint64
	TxPackets    uint64
	TxErrors     uint64
	DurationSec  uint32
	DurationNsec uint32
}

type OfpGroupStatsRequest struct {
	GroupId uint32
	_       [4]uint8
}

type OfpGroupStats struct {
	Length       uint16
	_            [2]uint8
	GroupId      uint32
	RefCount     uint32
	_            [4]uint8
	PacketCount  uint64
	ByteCount    uint64
	DurationSec  uint32
	DurationNsec uint32
	// buckets_stats [0]OfpBucketCounter
}

type OfpBucketCounter struct {
	PacketCount uint64
	ByteCount   uint64
}

type OfpGroupDesc struct {
	Length  uint16
	Type    uint8
	_       uint8
	GroupId uint32
	// buckets []OfpBucket
}

type OfpGroupFeatures struct {
	Types        uint32
	Capabilities uint32
	MaxGroups    [4]uint32
	Actions      [4]uint32
}

type OfpMeterMultipartRequest struct {
	MeterId uint32
	_       [4]uint8
}

type OfpMeterStats struct {
	MeterId       uint32
	Len           uint16
	_             [6]uint8
	FlowCount     uint32
	PacketInCount uint64
	ByteInCount   uint64
	DurationSec   uint32
	DurationNsec  uint32
	// BandStats []OfpMeterBandStats
}

type OfpMeterBandStats struct {
	PacketBandCount uint64
	ByteBandCount   uint64
}

type OfpMeterConfig struct {
	Length  uint16
	Flags   uint16
	MeterId uint32
	// bands [0]OfpMeterBandHeader
}

type OfpMeterFeatures struct {
	MaxMeter     uint32
	BandTypes    uint32
	Capabilities uint32
	MaxBands     uint8
	MaxColor     uint8
	_            [2]uint8
}

type OfpExperimenterMultipartHeader struct {
	Expeirmenter uint32
	ExpType      uint32
}

type OfpQueueGetConfigRequest struct {
	Header OfpHeader
	Port   uint32
	_      [4]uint8
}

type OfpQueueGetConfigReply struct {
	Header OfpHeader
	Port   uint32
	_      [4]uint8
	// queues [0]OfpPacketQueue
}

type OfpPacketOut struct {
	Header     OfpHeader
	BufferId   uint32
	InPort     uint32
	ActionsLen uint16
	_          [6]uint8
	// actions [0]OfpActionHeader
}

type OfpRoleRequest struct {
	Header       OfpHeader
	Role         uint32
	_            [4]uint8
	GenerationId uint64
}

type OfpAsyncConfig struct {
	Header          OfpHeader
	PacketInMask    [2]uint32
	PortStatusMask  [2]uint32
	FlowRemovedMask [2]uint32
}

type OfpPacketIn struct {
	Header   OfpHeader
	BufferId uint32
	TotalLen uint16
	Reason   uint8
	TableId  uint8
	Cookie   uint64
	Match    OfpMatch
	// pad & data
}

type OfpFlowRemoved struct {
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
	Match        OfpMatch
}

type OfpPortStatus struct {
	Header OfpHeader
	Reason uint8
	_      [7]uint8
	Desc   OfpPort
}

type OfpErrorMsg struct {
	Header OfpHeader
	Type   uint16
	Code   uint16
	// data [0]uint8
}

type OfpErrorExperimenterMsg struct {
	Header       OfpHeader
	Type         uint16
	ExpType      uint16
	Experimenter uint32
	// data [0]uint8
}

type OfpHello struct {
	Header OfpHeader
	// elements [0]OfpHelloElemHeader
}

type OfpHelloElemHeader struct {
	Type   uint16
	Length uint16
}

type OfpHelloElemVersionbitmap struct {
	Type   uint16
	Length uint16
	// bitmaps [0]uint32
}

type OfpExperimenterHeader struct {
	Header       OfpHeader
	Experimenter uint32
	ExpType      uint32
}
