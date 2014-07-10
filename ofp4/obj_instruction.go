package ofp4

import (
	"encoding"
	"encoding/binary"
)

type instructionList []Instruction

func (obj instructionList) MarshalBinary() ([]byte, error) {
	var data []byte
	for _, inst := range []Instruction(obj) {
		if buf, err := inst.MarshalBinary(); err != nil {
			return nil, err
		} else {
			data = append(data, buf...)
		}
	}
	return data, nil
}

func (obj *instructionList) UnmarshalBinary(data []byte) error {
	var instructions []Instruction
	for cur := 0; cur < len(data); {
		iType := binary.BigEndian.Uint16(data[cur : 2+cur])
		iLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var instruction Instruction
		switch iType {
		default:
			return Error{OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST, nil}
		case OFPIT_GOTO_TABLE:
			instruction = new(InstructionGotoTable)
		case OFPIT_WRITE_METADATA:
			instruction = new(InstructionWriteMetadata)
		case OFPIT_WRITE_ACTIONS, OFPIT_APPLY_ACTIONS, OFPIT_CLEAR_ACTIONS:
			instruction = new(InstructionActions)
		case OFPIT_METER:
			instruction = new(InstructionMeter)
		case OFPIT_EXPERIMENTER:
			instruction = new(InstructionExperimenter)
		}
		if err := instruction.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[cur : cur+iLen]); err != nil {
			return err
		}
		instructions = append(instructions, instruction)
		cur += iLen
	}
	*obj = instructions
	return nil
}

type instructionIdList []Instruction

func (obj instructionIdList) MarshalBinary() ([]byte, error) {
	return instructionList([]Instruction(obj)).MarshalBinary()
}

func (obj *instructionIdList) UnmarshalBinary(data []byte) error {
	var instructions []Instruction
	for cur := 0; cur < len(data); {
		iType := binary.BigEndian.Uint16(data[cur : 2+cur])
		iLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var instruction Instruction
		switch iType {
		default:
			return Error{OFPET_BAD_INSTRUCTION, OFPBIC_UNKNOWN_INST, nil}
		case OFPIT_GOTO_TABLE, OFPIT_WRITE_METADATA, OFPIT_WRITE_ACTIONS, OFPIT_APPLY_ACTIONS, OFPIT_CLEAR_ACTIONS, OFPIT_METER:
			instruction = new(InstructionId)
		case OFPIT_EXPERIMENTER:
			instruction = new(InstructionExperimenter)
		}
		if err := instruction.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[cur : cur+iLen]); err != nil {
			return err
		}
		instructions = append(instructions, instruction)
		cur += iLen
	}
	*obj = instructions
	return nil
}

type InstructionId struct {
	Type uint16
}

func (obj InstructionId) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], 4)
	return
}
func (obj *InstructionId) UnmarshalBinary(data []byte) (err error) {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	return
}

type InstructionGotoTable struct {
	TableId uint8
}

func (obj InstructionGotoTable) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], OFPIT_GOTO_TABLE)
	binary.BigEndian.PutUint16(data[2:4], 8)
	data[4] = obj.TableId
	return
}
func (obj *InstructionGotoTable) UnmarshalBinary(data []byte) (err error) {
	obj.TableId = data[4]
	return
}

type InstructionWriteMetadata struct {
	Metadata     uint64
	MetadataMask uint64
}

func (obj InstructionWriteMetadata) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 24)
	binary.BigEndian.PutUint16(data[0:2], OFPIT_WRITE_METADATA)
	binary.BigEndian.PutUint16(data[2:4], 24)
	binary.BigEndian.PutUint64(data[8:16], obj.Metadata)
	binary.BigEndian.PutUint64(data[16:24], obj.MetadataMask)
	return
}
func (obj *InstructionWriteMetadata) UnmarshalBinary(data []byte) (err error) {
	obj.Metadata = binary.BigEndian.Uint64(data[8:16])
	obj.MetadataMask = binary.BigEndian.Uint64(data[16:24])
	return
}

type InstructionActions struct {
	Type    uint16
	Actions []Action
}

func (obj InstructionActions) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	if buf, err := actionList(obj.Actions).MarshalBinary(); err != nil {
		return nil, err
	} else {
		data = append(data, buf...)
	}
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	return data, nil
}
func (obj *InstructionActions) UnmarshalBinary(data []byte) error {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	var actions actionList
	if err := actions.UnmarshalBinary(data[8:length]); err != nil {
		return err
	} else {
		obj.Actions = []Action(actions)
	}
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	return nil
}

type InstructionMeter struct {
	MeterId uint32
}

func (obj InstructionMeter) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], OFPIT_METER)
	binary.BigEndian.PutUint16(data[2:4], 8)
	binary.BigEndian.PutUint32(data[4:8], obj.MeterId)
	return
}
func (obj *InstructionMeter) UnmarshalBinary(data []byte) (err error) {
	obj.MeterId = binary.BigEndian.Uint32(data[4:8])
	return
}

type InstructionExperimenter struct {
	Experimenter uint32
	Data         []byte
}

func (obj InstructionExperimenter) MarshalBinary() (data []byte, err error) {
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint16(prefix[0:2], OFPIT_EXPERIMENTER)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(8+len(obj.Data)))
	binary.BigEndian.PutUint32(prefix[4:8], obj.Experimenter)

	data = append(prefix, obj.Data...)
	return
}

func (obj *InstructionExperimenter) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.Experimenter = binary.BigEndian.Uint32(data[4:8])
	obj.Data = data[8:length]
	return
}
