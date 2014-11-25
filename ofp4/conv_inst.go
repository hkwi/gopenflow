package ofp4

import (
	"encoding/binary"
)

type Instruction []byte

func (self Instruction) Type() uint16 {
	return binary.BigEndian.Uint16(self)
}

func (self Instruction) Len() int {
	return int(binary.BigEndian.Uint16(self[2:]))
}

func (self Instruction) Iter() []Instruction {
	var seq []Instruction
	for cur := 0; cur < len(self); {
		i := Instruction(self[cur:])
		seq = append(seq, Instruction(i[:i.Len()]))
		cur += i.Len()
	}
	return seq
}

func MakeInstruction(ofpit uint16) Instruction {
	self := make([]byte, 4)
	binary.BigEndian.PutUint16(self, ofpit)
	binary.BigEndian.PutUint16(self[2:], 4)
	return self
}

type InstructionGotoTable []byte

func (self InstructionGotoTable) TableId() uint8 {
	return self[4]
}

func MakeInstructionGotoTable(tableId uint8) Instruction {
	self := make([]byte, 8)
	binary.BigEndian.PutUint16(self, OFPIT_GOTO_TABLE)
	binary.BigEndian.PutUint16(self[2:], 8)
	self[4] = tableId
	return self
}

type InstructionWriteMetadata []byte

func (self InstructionWriteMetadata) Metadata() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}

func (self InstructionWriteMetadata) MetadataMask() uint64 {
	return binary.BigEndian.Uint64(self[16:])
}

func MakeInstructionWriteMetadata(metadata, metadataMask uint64) Instruction {
	self := make([]byte, 24)
	binary.BigEndian.PutUint16(self, OFPIT_WRITE_METADATA)
	binary.BigEndian.PutUint16(self[2:], 24)
	binary.BigEndian.PutUint64(self[8:], metadata)
	binary.BigEndian.PutUint64(self[16:], metadataMask)
	return self
}

type InstructionActions []byte

func (self InstructionActions) Actions() ActionHeader {
	return ActionHeader(self[8:Instruction(self).Len()])
}

func MakeInstructionActions(ofpit uint16, actions ActionHeader) Instruction {
	length := 8 + len(actions)
	self := make([]byte, length)
	binary.BigEndian.PutUint16(self, ofpit)
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	copy(self[8:], actions)
	return self
}

type InstructionMeter []byte

func (self InstructionMeter) MeterId() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func MakeInstructionMeter(meterId uint32) Instruction {
	self := make([]byte, 8)
	binary.BigEndian.PutUint16(self, OFPIT_METER)
	binary.BigEndian.PutUint16(self[2:], 8)
	binary.BigEndian.PutUint32(self[4:], meterId)
	return self
}

type InstructionExperimenter []byte

func (self InstructionExperimenter) Experimenter() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self InstructionExperimenter) AppendData(data []byte) InstructionExperimenter {
	length := len(self) + len(data)
	binary.BigEndian.PutUint16(self[2:], uint16(length))
	return append(self, data...)
}

func MakeInstructionExperimenter(experimenter uint32) Instruction {
	self := make([]byte, 8)
	binary.BigEndian.PutUint16(self, OFPIT_EXPERIMENTER)
	binary.BigEndian.PutUint16(self[2:], 8)
	binary.BigEndian.PutUint32(self[4:], experimenter)
	return self
}
