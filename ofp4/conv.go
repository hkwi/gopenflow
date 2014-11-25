package ofp4

import (
	"encoding/binary"
)

func align8(num int) int {
	return (num + 7) / 8 * 8
}

type Header []byte

func (self Header) Version() uint8 {
	return self[0]
}

func (self Header) Type() uint8 {
	return self[1]
}

func (self Header) Length() int {
	return int(binary.BigEndian.Uint16(self[2:]))
}

func (self Header) Xid() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self Header) Iter() []Header {
	var seq []Header
	for cur := 0; cur < len(self); {
		msg := Header(self)
		seq = append(seq, msg[:msg.Length()])
		cur += msg.Length()
	}
	return seq
}

func (self Header) SetXid(xid uint32) Header {
	binary.BigEndian.PutUint32(self[4:], xid)
	return self
}

func (self Header) AppendData(data []byte) Header {
	length := len(self) + len(data)
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	return append(self, data...)
}

func MakeHeader(ofpt uint8) Header {
	self := make([]byte, 8)
	self[0] = 4
	self[1] = ofpt
	binary.BigEndian.PutUint16(self[2:], 8)
	return self
}

type HelloElemHeader []byte

func (self HelloElemHeader) Type() uint16 {
	return binary.BigEndian.Uint16(self)
}

// Length in bytes including header, excluding padding.
func (self HelloElemHeader) Length() int {
	return int(binary.BigEndian.Uint16(self[2:]))
}

func (self HelloElemHeader) Iter() []HelloElemHeader {
	var seq []HelloElemHeader
	for cur := 0; cur < len(self); {
		el := HelloElemHeader(self[cur:])
		seq = append(seq, el[:el.Length()])
		cur += el.Length()
	}
	return seq
}

type HelloElemVersionbitmap []byte

func (self HelloElemVersionbitmap) Bitmaps() []uint32 {
	inner := HelloElemHeader(self).Length() - 4
	ret := make([]uint32, inner/4)
	for i, _ := range ret {
		ret[i] = binary.BigEndian.Uint32(self[4+4*i:])
	}
	return ret
}

func MakeHelloElemVersionbitmap(bitmaps []uint32) HelloElemHeader {
	inner := 4 + len(bitmaps)*4
	length := align8(inner)
	ret := make([]byte, length)
	binary.BigEndian.PutUint16(ret, OFPHET_VERSIONBITMAP)
	binary.BigEndian.PutUint16(ret[2:], uint16(inner))
	for i, b := range bitmaps {
		binary.BigEndian.PutUint32(ret[4+4*i:], b)
	}
	return ret
}

type Hello []byte

func (self Hello) Elements() HelloElemHeader {
	return HelloElemHeader(self[8:Header(self).Length()])
}

func MakeHello(elements HelloElemHeader) Header {
	var length int = 8 + len(elements)
	self := make([]byte, 8, length)
	self[0] = 4
	self[1] = OFPT_HELLO
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	copy(self[8:], elements)
	return self
}

type ErrorMsg []byte

func (self ErrorMsg) Type() uint16 {
	return binary.BigEndian.Uint16(self[8:])
}

func (self ErrorMsg) Code() uint16 {
	return binary.BigEndian.Uint16(self[12:])
}

func (self ErrorMsg) Data() []byte {
	return self[16:]
}

func MakeErrorMsg(etype, ecode uint16) ErrorMsg {
	self := make([]byte, 12)
	self[0] = 4
	self[1] = OFPT_ERROR
	binary.BigEndian.PutUint16(self[2:], 12)
	binary.BigEndian.PutUint16(self[8:], etype)
	binary.BigEndian.PutUint16(self[10:], ecode)
	return ErrorMsg(self)
}

func (self ErrorMsg) Error() string {
	// XXX: make this better
	return "ofp error"
}

type ExperimenterHeader []byte

func (self ExperimenterHeader) Experimenter() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self ExperimenterHeader) ExpType() uint32 {
	return binary.BigEndian.Uint32(self[12:])
}

func MakeExperimenterHeader(experimenter, expType uint32) Header {
	self := make([]byte, 16)
	self[0] = 4
	self[1] = OFPT_EXPERIMENTER
	binary.BigEndian.PutUint16(self[2:], 16)
	binary.BigEndian.PutUint32(self[8:], experimenter)
	binary.BigEndian.PutUint32(self[12:], expType)
	return self
}

type SwitchFeatures []byte

func (self SwitchFeatures) DatapathId() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}

func (self SwitchFeatures) NBuffers() uint32 {
	return binary.BigEndian.Uint32(self[16:])
}

func (self SwitchFeatures) NTables() uint8 {
	return self[20]
}

func (self SwitchFeatures) AuxiliaryId() uint8 {
	return self[21]
}

func (self SwitchFeatures) Capabilities() uint32 {
	return binary.BigEndian.Uint32(self[24:])
}

func MakeSwitchFeatures(datapathId uint64,
	nBuffers uint32,
	nTables uint8,
	auxiliaryId uint8,
	capabilities uint32) Header {
	self := make([]byte, 32)
	self[0] = 4
	self[1] = OFPT_FEATURES_REPLY
	binary.BigEndian.PutUint16(self[2:], 32)
	binary.BigEndian.PutUint64(self[8:], datapathId)
	binary.BigEndian.PutUint32(self[16:], nBuffers)
	self[20] = nTables
	self[21] = auxiliaryId
	binary.BigEndian.PutUint32(self[24:], capabilities)
	return self
}

type SwitchConfig []byte

func (self SwitchConfig) Flags() uint16 {
	return binary.BigEndian.Uint16(self[8:])
}

func (self SwitchConfig) MissSendLen() uint16 {
	return binary.BigEndian.Uint16(self[10:])
}

func MakeSwitchConfig(flags, missSendLen uint16) Header {
	self := make([]byte, 12)
	self[0] = 4
	self[1] = OFPT_GET_CONFIG_REPLY
	binary.BigEndian.PutUint16(self[2:], 12)
	binary.BigEndian.PutUint16(self[8:], flags)
	binary.BigEndian.PutUint16(self[10:], missSendLen)
	return self
}

type Match []byte

func (self Match) Type() uint16 {
	return binary.BigEndian.Uint16(self)
}

// Length of ofp_match, excluding padding
func (self Match) Length() int {
	return int(binary.BigEndian.Uint16(self[2:]))
}

func (self Match) OxmFields() []byte {
	return self[4:self.Length()]
}

func MakeMatch(fields []byte) Match {
	length := 4 + len(fields)
	self := make([]byte, align8(length))
	binary.BigEndian.PutUint16(self, OFPMT_OXM)
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	copy(self[4:], fields)
	return self
}

type PacketIn []byte

func (self PacketIn) BufferId() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self PacketIn) TotalLen() uint16 {
	return binary.BigEndian.Uint16(self[12:])
}

func (self PacketIn) Reason() uint8 {
	return self[14]
}

func (self PacketIn) TableId() uint8 {
	return self[15]
}

func (self PacketIn) Cookie() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func (self PacketIn) Match() Match {
	m := Match(self[24:])
	return Match(m[:align8(int(m.Length()))])
}

func (self PacketIn) Data() []byte {
	return self[26+len(self.Match()):]
}

func MakePacketIn(bufferId uint32,
	totalLen uint16,
	reason uint8,
	tableId uint8,
	cookie uint64,
	match Match,
	data []byte) Header {
	length := 26 + len(match) + len(data)
	self := make([]byte, length)
	self[0] = 4
	self[1] = OFPT_PACKET_IN
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	binary.BigEndian.PutUint32(self[8:], bufferId)
	binary.BigEndian.PutUint16(self[12:], totalLen)
	self[14] = reason
	self[15] = tableId
	binary.BigEndian.PutUint64(self[16:], cookie)
	copy(self[24:], match)
	copy(self[26+len(match):], data)
	return self
}

type FlowRemoved []byte

func (self FlowRemoved) Cookie() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}

func (self FlowRemoved) Priority() uint16 {
	return binary.BigEndian.Uint16(self[16:])
}

func (self FlowRemoved) Reason() uint8 {
	return self[18]
}

func (self FlowRemoved) TableId() uint8 {
	return self[19]
}

func (self FlowRemoved) DurationSec() uint32 {
	return binary.BigEndian.Uint32(self[20:])
}

func (self FlowRemoved) DurationNsec() uint32 {
	return binary.BigEndian.Uint32(self[24:])
}

func (self FlowRemoved) IdleTimeout() uint16 {
	return binary.BigEndian.Uint16(self[28:])
}

func (self FlowRemoved) HardTimeout() uint16 {
	return binary.BigEndian.Uint16(self[30:])
}

func (self FlowRemoved) PacketCount() uint64 {
	return binary.BigEndian.Uint64(self[32:])
}

func (self FlowRemoved) ByteCount() uint64 {
	return binary.BigEndian.Uint64(self[40:])
}

func (self FlowRemoved) Match() Match {
	m := Match(self[48:])
	return Match(m[:align8(m.Length())])
}

func MakeFlowRemoved(cookie uint64,
	priority uint16,
	reason uint8,
	tableId uint8,
	durationSec uint32,
	durationNsec uint32,
	idleTimeout uint16,
	hardTimeout uint16,
	packetCount uint64,
	byteCount uint64,
	match Match) Header {
	length := 48 + align8(len(match))
	self := make([]byte, length)
	self[0] = 4
	self[1] = OFPT_FLOW_REMOVED
	binary.BigEndian.PutUint16(self[2:], uint16(length))

	binary.BigEndian.PutUint64(self[8:], cookie)
	binary.BigEndian.PutUint16(self[16:], priority)
	self[18] = reason
	self[19] = tableId
	binary.BigEndian.PutUint32(self[20:], durationSec)
	binary.BigEndian.PutUint32(self[24:], durationNsec)
	binary.BigEndian.PutUint16(self[28:], idleTimeout)
	binary.BigEndian.PutUint16(self[30:], hardTimeout)
	binary.BigEndian.PutUint64(self[32:], packetCount)
	binary.BigEndian.PutUint64(self[40:], byteCount)
	copy(self[48:], match)
	return self
}

type Port []byte

func (self Port) PortNo() uint32 {
	return binary.BigEndian.Uint32(self)
}

func (self Port) HwAddr() [6]byte {
	var ret [6]byte
	copy(ret[:], self[8:])
	return ret
}

func (self Port) Name() [16]byte {
	var ret [16]byte
	copy(ret[:], self[16:])
	return ret
}

func (self Port) Config() uint32 {
	return binary.BigEndian.Uint32(self[32:])
}

func (self Port) State() uint32 {
	return binary.BigEndian.Uint32(self[36:])
}

func (self Port) Curr() uint32 {
	return binary.BigEndian.Uint32(self[40:])
}

func (self Port) Advertised() uint32 {
	return binary.BigEndian.Uint32(self[44:])
}

func (self Port) Supported() uint32 {
	return binary.BigEndian.Uint32(self[48:])
}

func (self Port) Peer() uint32 {
	return binary.BigEndian.Uint32(self[52:])
}

func (self Port) CurrSpeed() uint32 {
	return binary.BigEndian.Uint32(self[56:])
}

func (self Port) MaxSpeed() uint32 {
	return binary.BigEndian.Uint32(self[60:])
}

func MakePort(portNo uint32,
	hwAddr [6]byte,
	name []byte,
	config uint32,
	state uint32,
	curr uint32,
	advertised uint32,
	supported uint32,
	peer uint32,
	currSpeed uint32,
	maxSpeed uint32) Port {
	self := make([]byte, 64)
	binary.BigEndian.PutUint32(self, portNo)
	copy(self[8:], hwAddr[:])
	copy(self[16:32], name)
	binary.BigEndian.PutUint32(self[32:], config)
	binary.BigEndian.PutUint32(self[36:], state)
	binary.BigEndian.PutUint32(self[40:], curr)
	binary.BigEndian.PutUint32(self[44:], advertised)
	binary.BigEndian.PutUint32(self[48:], supported)
	binary.BigEndian.PutUint32(self[52:], peer)
	binary.BigEndian.PutUint32(self[56:], currSpeed)
	binary.BigEndian.PutUint32(self[60:], maxSpeed)
	return self
}

type PortStatus []byte

func (self PortStatus) Reason() uint8 {
	return self[8]
}

func (self PortStatus) Desc() Port {
	return Port(self[8:72])
}

func MakePortStatus(reason uint8, desc Port) Header {
	ret := make([]byte, 80)
	ret[0] = 4
	ret[1] = OFPT_PORT_STATUS
	binary.BigEndian.PutUint16(ret[2:], 80)
	ret[8] = reason
	copy(ret[16:], desc)
	return ret
}

type PacketOut []byte

func (self PacketOut) BufferId() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self PacketOut) InPort() uint32 {
	return binary.BigEndian.Uint32(self[12:])
}

/*
 * Size of action array in bytes.
 */
func (self PacketOut) ActionsLen() int {
	return int(binary.BigEndian.Uint16(self[16:]))
}

func (self PacketOut) Actions() ActionHeader {
	return ActionHeader(self[24 : 24+self.ActionsLen()])
}

func (self PacketOut) Data() []byte {
	return self[24+self.ActionsLen() : Header(self).Length()]
}

type FlowMod []byte

func (self FlowMod) Cookie() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}

func (self FlowMod) CookieMask() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func (self FlowMod) TableId() uint8 {
	return self[24]
}

func (self FlowMod) Command() uint8 {
	return self[25]
}

func (self FlowMod) IdleTimeout() uint16 {
	return binary.BigEndian.Uint16(self[26:])
}

func (self FlowMod) HardTimeout() uint16 {
	return binary.BigEndian.Uint16(self[28:])
}

func (self FlowMod) Priority() uint16 {
	return binary.BigEndian.Uint16(self[30:])
}

func (self FlowMod) BufferId() uint32 {
	return binary.BigEndian.Uint32(self[32:])
}

func (self FlowMod) OutPort() uint32 {
	return binary.BigEndian.Uint32(self[36:])
}

func (self FlowMod) OutGroup() uint32 {
	return binary.BigEndian.Uint32(self[40:])
}

func (self FlowMod) Flags() uint16 {
	return binary.BigEndian.Uint16(self[44:])
}

func (self FlowMod) Match() Match {
	m := Match(self[48:])
	return Match(m[:align8(int(m.Length()))])
}

func (self FlowMod) Instructions() Instruction {
	return Instruction(self[48:Header(self).Length()])
}

type GroupMod []byte

func (self GroupMod) Command() uint16 {
	return binary.BigEndian.Uint16(self[8:])
}

func (self GroupMod) Type() uint8 {
	return self[10]
}

func (self GroupMod) GroupId() uint32 {
	return binary.BigEndian.Uint32(self[12:])
}

func (self GroupMod) Buckets() Bucket {
	return Bucket(self[16:])
}

type PortMod []byte

func (self PortMod) PortNo() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self PortMod) HwAddr() [6]byte {
	var ret [6]byte
	copy(ret[:], self[16:])
	return ret
}

func (self PortMod) Config() uint32 {
	return binary.BigEndian.Uint32(self[24:])
}

func (self PortMod) Mask() uint32 {
	return binary.BigEndian.Uint32(self[28:])
}

func (self PortMod) Advertise() uint32 {
	return binary.BigEndian.Uint32(self[32:])
}

type TableMod []byte

func (self TableMod) TableId() uint8 {
	return self[8]
}

func (self TableMod) Config() uint32 {
	return binary.BigEndian.Uint32(self[12:])
}

type MultipartRequest []byte

func (self MultipartRequest) Type() uint16 {
	return binary.BigEndian.Uint16(self[8:])
}

func (self MultipartRequest) Flags() uint16 {
	return binary.BigEndian.Uint16(self[10:])
}

func (self MultipartRequest) Body() []byte {
	return self[16:Header(self).Length()]
}

func MakeMultipartRequest(mtype, flags uint16, body []byte) Header {
	length := 16 + len(body)
	self := make([]byte, length)
	self[0] = 4
	self[1] = OFPT_MULTIPART_REQUEST
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	binary.BigEndian.PutUint16(self[8:], mtype)
	binary.BigEndian.PutUint16(self[10:], flags)
	copy(self[16:], body)
	return self
}

type MultipartReply []byte

func (self MultipartReply) Type() uint16 {
	return binary.BigEndian.Uint16(self[8:])
}

func (self MultipartReply) Flags() uint16 {
	return binary.BigEndian.Uint16(self[10:])
}

func (self MultipartReply) Body() []byte {
	return self[16:Header(self).Length()]
}

func MakeMultipartReply(mtype, flags uint16, body []byte) Header {
	length := 16 + len(body)
	self := make([]byte, length)
	self[0] = 4
	self[1] = OFPT_MULTIPART_REPLY
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	binary.BigEndian.PutUint16(self[8:], mtype)
	binary.BigEndian.PutUint16(self[10:], flags)
	copy(self[16:], body)
	return self
}

type QueueGetConfigRequest []byte

func (self QueueGetConfigRequest) Port() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

type QueuePropHeader []byte

func (self QueuePropHeader) Property() uint16 {
	return binary.BigEndian.Uint16(self)
}

/*
 * Length of property, including header.
 */
func (self QueuePropHeader) Len() int {
	return int(binary.BigEndian.Uint16(self[2:]))
}

type PacketQueue []byte

func (self PacketQueue) QueueId() uint32 {
	return binary.BigEndian.Uint32(self)
}

func (self PacketQueue) Port() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

/*
 * Length in bytes of this queue desc, including header.
 */
func (self PacketQueue) Len() int {
	return int(binary.BigEndian.Uint16(self[8:]))
}

func (self PacketQueue) Properties() []QueuePropHeader {
	var ret []QueuePropHeader
	length := self.Len()
	for cur := 16; cur < length; {
		p := QueuePropHeader(self[cur:])
		ret = append(ret, QueuePropHeader(p[:p.Len()]))
		cur += p.Len()
	}
	return ret
}

type QueueGetConfigReply []byte

func (self QueueGetConfigReply) Port() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self QueueGetConfigReply) Queues() []PacketQueue {
	var ret []PacketQueue
	length := Header(self).Length()
	for cur := 16; cur < length; {
		q := PacketQueue(self[cur:])
		ret = append(ret, q[:q.Len()])
		cur += q.Len()
	}
	return ret
}

type RoleRequest []byte

func (self RoleRequest) Role() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self RoleRequest) GenerationId() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

type AsyncConfig []byte

func (self AsyncConfig) PacketInMask() [2]uint32 {
	var ret [2]uint32
	ret[0] = binary.BigEndian.Uint32(self[8:])
	ret[1] = binary.BigEndian.Uint32(self[12:])
	return ret
}

func (self AsyncConfig) PortStatusMask() [2]uint32 {
	var ret [2]uint32
	ret[0] = binary.BigEndian.Uint32(self[16:])
	ret[1] = binary.BigEndian.Uint32(self[20:])
	return ret
}

func (self AsyncConfig) FlowRemovedMask() [2]uint32 {
	var ret [2]uint32
	ret[0] = binary.BigEndian.Uint32(self[24:])
	ret[1] = binary.BigEndian.Uint32(self[28:])
	return ret
}

type MeterMod []byte

func (self MeterMod) Command() uint16 {
	return binary.BigEndian.Uint16(self[8:])
}

func (self MeterMod) Flags() uint16 {
	return binary.BigEndian.Uint16(self[10:])
}

func (self MeterMod) MeterId() uint32 {
	return binary.BigEndian.Uint32(self[12:])
}

func (self MeterMod) Bands() MeterBandHeader {
	return MeterBandHeader(self[16:Header(self).Length()])
}
