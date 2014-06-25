package ofp4

import (
	"encoding/binary"
	"errors"
)

func instructionIdsUnmarshalBinary(data []byte) (instructions []TypedData, err error) {
	for cur := 0; cur < len(data); {
		iType := binary.BigEndian.Uint16(data[cur : 2+cur])
		iLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var instruction TypedData
		switch iType {
		default:
			err = errors.New("Unknown OFPIT_")
			return
		case OFPIT_GOTO_TABLE, OFPIT_WRITE_METADATA, OFPIT_WRITE_ACTIONS, OFPIT_APPLY_ACTIONS, OFPIT_CLEAR_ACTIONS, OFPIT_METER:
			instruction = new(InstructionId)
		case OFPIT_EXPERIMENTER:
			instruction = new(InstructionExperimenter)
		}
		if err = instruction.UnmarshalBinary(data[cur : cur+iLen]); err != nil {
			return
		}
		instructions = append(instructions, instruction)
		cur += iLen
	}
	return
}

func instructionsUnmarshalBinary(data []byte) (instructions []TypedData, err error) {
	for cur := 0; cur < len(data); {
		iType := binary.BigEndian.Uint16(data[cur : 2+cur])
		iLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var instruction TypedData
		switch iType {
		default:
			err = errors.New("Unknown OFPIT_")
			return
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
		if err = instruction.UnmarshalBinary(data[cur : cur+iLen]); err != nil {
			return
		}
		instructions = append(instructions, instruction)
		cur += iLen
	}
	return
}

type InstructionId struct {
	Type uint16
}

func (obj *InstructionId) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], 4)
	return
}
func (obj *InstructionId) UnmarshalBinary(data []byte) (err error) {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	return
}
func (obj *InstructionId) GetType() uint16 {
	return obj.Type
}

type InstructionGotoTable struct {
	TableId uint8
}

func (obj *InstructionGotoTable) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPIT_GOTO_TABLE)
	binary.BigEndian.PutUint16(data[2:4], 8)
	data[4] = obj.TableId
	return
}
func (obj *InstructionGotoTable) UnmarshalBinary(data []byte) (err error) {
	obj.TableId = data[4]
	return
}
func (obj *InstructionGotoTable) GetType() uint16 {
	return OFPIT_GOTO_TABLE
}

type InstructionWriteMetadata struct {
	Metadata     uint64
	MetadataMask uint64
}

func (obj *InstructionWriteMetadata) MarshalBinary() (data []byte, err error) {
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
func (obj *InstructionWriteMetadata) GetType() uint16 {
	return OFPIT_WRITE_METADATA
}

type InstructionActions struct {
	Type    uint16
	Actions []TypedData
}

func (obj *InstructionActions) MarshalBinary() (data []byte, err error) {
	var actions []byte
	for _, action := range obj.Actions {
		var buf []byte
		if buf, err = action.MarshalBinary(); err != nil {
			return
		}
		actions = append(actions, buf...)
	}

	prefix := make([]byte, 8)
	binary.BigEndian.PutUint16(prefix[0:2], obj.Type)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(8+len(actions)))

	data = append(prefix, actions...)
	return
}
func (obj *InstructionActions) UnmarshalBinary(data []byte) (err error) {
	length := binary.BigEndian.Uint16(data[2:4])
	if obj.Actions, err = actionsUnmarshalBinary(data[8:length]); err != nil {
		return
	}
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	return
}
func (obj *InstructionActions) GetType() uint16 {
	return obj.Type
}

type InstructionMeter struct {
	MeterId uint32
}

func (obj *InstructionMeter) MarshalBinary() (data []byte, err error) {
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
func (obj *InstructionMeter) GetType() uint16 {
	return OFPIT_METER
}

type InstructionExperimenter struct {
	Experimenter uint32
	Data         []byte
}

func (obj *InstructionExperimenter) MarshalBinary() (data []byte, err error) {
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
func (obj *InstructionExperimenter) GetType() uint16 {
	return OFPIT_EXPERIMENTER
}
