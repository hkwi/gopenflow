package ofp4

import (
	"encoding"
	"encoding/binary"
)

type tableFeaturePropertyList []encoding.BinaryMarshaler

func (obj tableFeaturePropertyList) MarshalBinary() ([]byte, error) {
	return Array(obj).MarshalBinary()
}

func (obj *tableFeaturePropertyList) UnmarshalBinary(data []byte) error {
	var properties []encoding.BinaryMarshaler
	for cur := 0; cur < len(data); {
		pType := binary.BigEndian.Uint16(data[cur : 2+cur])
		pLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		buf := data[cur : cur+pLen]
		switch pType {
		default:
			return Error{
				Type: OFPET_TABLE_FEATURES_FAILED,
				Code: OFPTFFC_BAD_TYPE,
			}
		case OFPTFPT_INSTRUCTIONS, OFPTFPT_INSTRUCTIONS_MISS:
			var property TableFeaturePropInstructions
			if err := property.UnmarshalBinary(buf); err != nil {
				return err
			}
			properties = append(properties, property)
		case OFPTFPT_NEXT_TABLES, OFPTFPT_NEXT_TABLES_MISS:
			var property TableFeaturePropNextTables
			if err := property.UnmarshalBinary(buf); err != nil {
				return err
			}
			properties = append(properties, property)
		case OFPTFPT_WRITE_ACTIONS, OFPTFPT_WRITE_ACTIONS_MISS, OFPTFPT_APPLY_ACTIONS, OFPTFPT_APPLY_ACTIONS_MISS:
			var property TableFeaturePropActions
			if err := property.UnmarshalBinary(buf); err != nil {
				return err
			}
			properties = append(properties, property)
		case OFPTFPT_MATCH, OFPTFPT_WILDCARDS, OFPTFPT_WRITE_SETFIELD, OFPTFPT_WRITE_SETFIELD_MISS:
			var property TableFeaturePropOxm
			if err := property.UnmarshalBinary(buf); err != nil {
				return err
			}
			properties = append(properties, property)
		case OFPTFPT_EXPERIMENTER, OFPTFPT_EXPERIMENTER_MISS:
			var property TableFeaturePropExperimenter
			if err := property.UnmarshalBinary(buf); err != nil {
				return err
			}
			properties = append(properties, property)
		}
		cur += pLen
	}
	*obj = tableFeaturePropertyList(properties)
	return nil
}

type TableFeaturePropInstructions struct {
	Type           uint16
	InstructionIds []Instruction
}

func (obj TableFeaturePropInstructions) MarshalBinary() ([]byte, error) {
	insts, err := instructionIdList(obj.InstructionIds).MarshalBinary()
	if err != nil {
		return nil, err
	}
	length := 4 + len(insts)
	data := make([]byte, align8(length))
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	copy(data[4:], insts)
	return data, nil
}

func (obj *TableFeaturePropInstructions) UnmarshalBinary(data []byte) error {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	length := int(binary.BigEndian.Uint16(data[2:4]))
	var instructions instructionIdList
	if err := instructions.UnmarshalBinary(data[4:length]); err != nil {
		return err
	} else {
		obj.InstructionIds = []Instruction(instructions)
	}
	return nil
}

type TableFeaturePropNextTables struct {
	Type         uint16
	NextTableIds []uint8
}

func (obj TableFeaturePropNextTables) MarshalBinary() ([]byte, error) {
	length := 4 + len(obj.NextTableIds)
	data := make([]byte, align8(length))
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	copy(data[4:], obj.NextTableIds)
	return data, nil
}

func (obj *TableFeaturePropNextTables) UnmarshalBinary(data []byte) error {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.NextTableIds = data[4:length]
	return nil
}

type TableFeaturePropActions struct {
	Type      uint16
	ActionIds []Action
}

func (obj TableFeaturePropActions) MarshalBinary() ([]byte, error) {
	actions, err := actionIdList(obj.ActionIds).MarshalBinary()
	if err != nil {
		return nil, err
	}
	length := 4 + len(actions)
	data := make([]byte, align8(length))
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	copy(data[4:], actions)
	return data, nil
}

func (obj *TableFeaturePropActions) UnmarshalBinary(data []byte) error {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	length := int(binary.BigEndian.Uint16(data[2:4]))
	var actionIds actionIdList
	if err := actionIds.UnmarshalBinary(data[4:length]); err != nil {
		return err
	} else {
		obj.ActionIds = []Action(actionIds)
	}
	return nil
}

type TableFeaturePropOxm struct {
	Type   uint16
	OxmIds []uint32
}

func (obj TableFeaturePropOxm) MarshalBinary() ([]byte, error) {
	length := 4 + len(obj.OxmIds)*4
	data := make([]byte, align8(length))
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	for i, num := range obj.OxmIds {
		binary.BigEndian.PutUint32(data[4+4*i:8+4*i], uint32(num))
	}
	return data, nil
}

func (obj *TableFeaturePropOxm) UnmarshalBinary(data []byte) error {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.OxmIds = make([]uint32, (length-4)/4)
	for i, _ := range obj.OxmIds {
		obj.OxmIds[i] = OxmHeader(binary.BigEndian.Uint32(data[4+4*i : 8+4*i])).Type()
	}
	return nil
}

type TableFeaturePropExperimenter struct {
	Type         uint16
	Experimenter uint32
	ExpType      uint32
	Data         []byte
}

func (obj TableFeaturePropExperimenter) MarshalBinary() ([]byte, error) {
	length := 12 + len(obj.Data)
	data := make([]byte, align8(length))
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	binary.BigEndian.PutUint32(data[4:8], obj.Experimenter)
	binary.BigEndian.PutUint32(data[8:12], obj.ExpType)
	copy(data[12:], obj.Data)
	return data, nil
}

func (obj *TableFeaturePropExperimenter) UnmarshalBinary(data []byte) error {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	obj.Experimenter = binary.BigEndian.Uint32(data[4:8])
	obj.ExpType = binary.BigEndian.Uint32(data[8:12])
	obj.Data = data[12:length]
	return nil
}
