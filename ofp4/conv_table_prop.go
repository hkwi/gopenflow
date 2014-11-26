package ofp4

import (
	"encoding/binary"
)

type TableFeaturePropHeader []byte

func (self TableFeaturePropHeader) Type() uint16 {
	return binary.BigEndian.Uint16(self)
}

func (self TableFeaturePropHeader) Length() int {
	return int(binary.BigEndian.Uint16(self[2:]))
}

func (self TableFeaturePropHeader) Iter() []TableFeaturePropHeader {
	var ret []TableFeaturePropHeader
	for cur := 0; cur < len(self); {
		p := TableFeaturePropHeader(self[cur:])
		length := align8(p.Length())
		ret = append(ret, p[:length])
		cur += length
	}
	return ret
}

func MakeTableFeaturePropHeader(ofptfpt uint16, payload []byte) TableFeaturePropHeader {
	length := 4 + len(payload)
	self := make([]byte, align8(length))
	binary.BigEndian.PutUint16(self, ofptfpt)
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	copy(self[4:], payload)
	return self
}

type TableFeaturePropInstructions []byte

func (self TableFeaturePropInstructions) InstructionIds() Instruction {
	return Instruction(self[4:])
}

func MakeTableFeaturePropInstructions(ofptfpt uint16, instructionIds Instruction) TableFeaturePropHeader {
	return MakeTableFeaturePropHeader(ofptfpt, instructionIds)
}

type TableFeaturePropNextTables []byte

func (self TableFeaturePropNextTables) NextTableIds() []uint8 {
	return self[4:TableFeaturePropHeader(self).Length()]
}

func MakeTableFeaturePropNextTables(ofptfpt uint16, nextTableIds []uint8) TableFeaturePropHeader {
	return MakeTableFeaturePropHeader(ofptfpt, nextTableIds)
}

type TableFeaturePropActions []byte

func (self TableFeaturePropActions) ActionIds() ActionHeader {
	return ActionHeader(self[4:])
}

func MakeTableFeaturePropActions(ofptfpt uint16, actionIds ActionHeader) TableFeaturePropHeader {
	return MakeTableFeaturePropHeader(ofptfpt, actionIds)
}

type TableFeaturePropOxm []byte

func (self TableFeaturePropOxm) OxmIds() Oxm {
	return Oxm(self[4:TableFeaturePropHeader(self).Length()])
}

func MakeTableFeaturePropOxm(ofptfpt uint16, oxmIds Oxm) TableFeaturePropHeader {
	return MakeTableFeaturePropHeader(ofptfpt, oxmIds)
}

type TableFeaturePropExperimenter []byte

func (self TableFeaturePropExperimenter) Experimenter() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self TableFeaturePropExperimenter) ExpType() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self TableFeaturePropExperimenter) ExperimenterData() []byte {
	return self[12:TableFeaturePropHeader(self).Length()]
}

func MakeTableFeaturePropExperimenter(ofptfpt uint16, experimenter uint32, expType uint32, experimenterData []byte) TableFeaturePropHeader {
	length := 12 + len(experimenterData)
	self := make([]byte, align8(length))
	binary.BigEndian.PutUint16(self, ofptfpt)
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	binary.BigEndian.PutUint32(self[4:], experimenter)
	binary.BigEndian.PutUint32(self[8:], expType)
	copy(self[12:], experimenterData)
	return self
}

type QueueStatsRequest []byte

func (self QueueStatsRequest) PortNo() uint32 {
	return binary.BigEndian.Uint32(self)
}

func (self QueueStatsRequest) QueueId() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

type QueueStats []byte

func (self QueueStats) PortNo() uint32 {
	return binary.BigEndian.Uint32(self)
}

func (self QueueStats) QueueId() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self QueueStats) TxBytes() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}

func (self QueueStats) TxPackets() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func (self QueueStats) TxErrors() uint64 {
	return binary.BigEndian.Uint64(self[24:])
}

func (self QueueStats) DurationSec() uint32 {
	return binary.BigEndian.Uint32(self[32:])
}

func (self QueueStats) DurationNsec() uint32 {
	return binary.BigEndian.Uint32(self[36:])
}

type GroupStatsRequest []byte

func (self GroupStatsRequest) GroupId() uint32 {
	return binary.BigEndian.Uint32(self)
}

type GroupStats []byte

func (self GroupStats) Length() int {
	return int(binary.BigEndian.Uint16(self))
}

func (self GroupStats) GroupId() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self GroupStats) RefCount() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self GroupStats) PacketCount() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func (self GroupStats) ByteCount() uint64 {
	return binary.BigEndian.Uint64(self[24:])
}

func (self GroupStats) DurationSec() uint32 {
	return binary.BigEndian.Uint32(self[32:])
}

func (self GroupStats) DurationNsec() uint32 {
	return binary.BigEndian.Uint32(self[36:])
}

func (self GroupStats) BucketStats() []BucketCounter {
	var ret []BucketCounter
	end := self.Length()
	for cur := 40; cur < end; cur += 16 {
		ret = append(ret, BucketCounter(self[cur:cur+16]))
	}
	return ret
}
