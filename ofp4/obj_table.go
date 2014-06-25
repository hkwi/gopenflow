package ofp4

import (
	"encoding/binary"
	"errors"
)

func tableFeaturePropertiesUnmarshalBinary(data []byte) (properties []TypedData, err error) {
	for cur := 0; cur < len(data); {
		pType := binary.BigEndian.Uint16(data[cur : 2+cur])
		pLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var property TypedData
		switch pType {
		default:
			err = errors.New("Unknown OFPMBT_")
			return
		case OFPTFPT_INSTRUCTIONS, OFPTFPT_INSTRUCTIONS_MISS:
			property = new(TableFeaturePropInstructions)
		case OFPTFPT_NEXT_TABLES, OFPTFPT_NEXT_TABLES_MISS:
			property = new(TableFeaturePropNextTables)
		case OFPTFPT_WRITE_ACTIONS, OFPTFPT_WRITE_ACTIONS_MISS, OFPTFPT_APPLY_ACTIONS, OFPTFPT_APPLY_ACTIONS_MISS:
			property = new(TableFeaturePropActions)
		case OFPTFPT_MATCH, OFPTFPT_WILDCARDS, OFPTFPT_WRITE_SETFIELD, OFPTFPT_WRITE_SETFIELD_MISS:
			property = new(TableFeaturePropOxm)
		case OFPTFPT_EXPERIMENTER, OFPTFPT_EXPERIMENTER_MISS:
			property = new(TableFeaturePropExperimenter)
		}
		if err = property.UnmarshalBinary(data[cur : cur+pLen]); err != nil {
			return
		}
		properties = append(properties, property)
		cur += pLen
	}
	return
}

type TableFeaturePropInstructions struct {
	Type           uint16
	InstructionIds []TypedData
}

func (obj *TableFeaturePropInstructions) MarshalBinary() (data []byte, err error) {
	var instructions []byte
	for _, inst := range obj.InstructionIds {
		var buf []byte
		if buf, err = inst.MarshalBinary(); err != nil {
			return
		}
		instructions = append(instructions, buf...)
	}

	length := 4 + len(instructions)
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint16(prefix[0:2], obj.Type)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(align8(length)))

	data = append(append(prefix, instructions...), make([]byte, align8(length)-length)...)
	return
}
func (obj *TableFeaturePropInstructions) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if obj.InstructionIds, err = instructionIdsUnmarshalBinary(data[4:length]); err != nil {
		return
	}
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	return
}
func (obj *TableFeaturePropInstructions) GetType() uint16 {
	return obj.Type
}

type TableFeaturePropNextTables struct {
	Type         uint16
	NextTableIds []uint8
}

func (obj *TableFeaturePropNextTables) MarshalBinary() (data []byte, err error) {
	length := 4 + len(obj.NextTableIds)
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint16(prefix[0:2], obj.Type)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(length))

	data = append(append(prefix, obj.NextTableIds...), make([]byte, align8(length)-length)...)
	return
}
func (obj *TableFeaturePropNextTables) UnmarshalBinary(data []byte) (err error) {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.NextTableIds = data[4:length]
	return
}
func (obj *TableFeaturePropNextTables) GetType() uint16 {
	return obj.Type
}

type TableFeaturePropActions struct {
	Type      uint16
	ActionIds []TypedData
}

func (obj *TableFeaturePropActions) MarshalBinary() (data []byte, err error) {
	var actions []byte
	for _, action := range obj.ActionIds {
		var buf []byte
		if buf, err = action.MarshalBinary(); err != nil {
			return
		}
		actions = append(actions, buf...)
	}
	length := 4 + len(actions)
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint16(prefix[0:2], obj.Type)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(length))

	data = append(append(prefix, actions...), make([]byte, align8(length)-length)...)
	return
}
func (obj *TableFeaturePropActions) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if obj.ActionIds, err = actionIdsUnmarshalBinary(data[4:length]); err != nil {
		return
	}
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	return
}
func (obj *TableFeaturePropActions) GetType() uint16 {
	return obj.Type
}

type TableFeaturePropOxm struct {
	Type   uint16
	OxmIds []uint32
}

func (obj *TableFeaturePropOxm) MarshalBinary() (data []byte, err error) {
	length := 4 + len(obj.OxmIds)*4
	data = make([]byte, align8(length))
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	for i, num := range obj.OxmIds {
		binary.BigEndian.PutUint32(data[4+4*i:8+4*i], num)
	}
	return
}
func (obj *TableFeaturePropOxm) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.OxmIds = make([]uint32, (length-4)/4)
	for i, _ := range obj.OxmIds {
		obj.OxmIds[i] = binary.BigEndian.Uint32(data[4+4*i : 8+4*i])
	}
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	return
}

func (obj *TableFeaturePropOxm) GetType() uint16 {
	return obj.Type
}

type TableFeaturePropExperimenter struct {
	Type         uint16
	Experimenter uint32
	ExpType      uint32
	Data         []byte
}

func (obj *TableFeaturePropExperimenter) MarshalBinary() (data []byte, err error) {
	length := 12 + len(obj.Data)
	prefix := make([]byte, 12)
	binary.BigEndian.PutUint16(prefix[0:2], obj.Type)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(length))
	binary.BigEndian.PutUint32(prefix[4:8], obj.Experimenter)
	binary.BigEndian.PutUint32(prefix[8:12], obj.ExpType)

	data = append(append(prefix, obj.Data...), make([]byte, align8(length)-length)...)
	return
}
func (obj *TableFeaturePropExperimenter) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	obj.Experimenter = binary.BigEndian.Uint32(data[4:8])
	obj.ExpType = binary.BigEndian.Uint32(data[8:12])
	obj.Data = data[12:length]
	return
}
func (obj *TableFeaturePropExperimenter) GetType() uint16 {
	return obj.Type
}
