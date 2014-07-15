package ofp4

import (
	"encoding"
	"encoding/binary"
)

type tableFeaturePropertyList []encoding.BinaryMarshaler

func (obj tableFeaturePropertyList) MarshalBinary() ([]byte, error) {
	var data []byte
	for _, property := range []encoding.BinaryMarshaler(obj) {
		if buf, err := property.MarshalBinary(); err != nil {
			return nil, err
		} else {
			data = append(data, buf...)
		}
	}
	return data, nil
}

func (obj *tableFeaturePropertyList) UnmarshalBinary(data []byte) error {
	var properties []encoding.BinaryMarshaler
	for cur := 0; cur < len(data); {
		pType := binary.BigEndian.Uint16(data[cur : 2+cur])
		pLen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var property encoding.BinaryMarshaler
		switch pType {
		default:
			return Error{OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_TYPE, nil}
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
		if err := property.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[cur : cur+pLen]); err != nil {
			return err
		}
		properties = append(properties, property)
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
	data := make([]byte, 4)
	for _, inst := range obj.InstructionIds {
		if buf, err := inst.MarshalBinary(); err != nil {
			return nil, err
		} else {
			data = append(data, buf...)
		}
	}
	length := len(data)
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	data = append(data, make([]byte, align8(length)-length)...)
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
	data := make([]byte, length)
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	for i, v := range obj.NextTableIds {
		data[4+i] = v
	}
	data = append(data, make([]byte, align8(length)-length)...)
	return data, nil
}

func (obj *TableFeaturePropNextTables) UnmarshalBinary(data []byte) (err error) {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.NextTableIds = data[4:length]
	return
}

type TableFeaturePropActions struct {
	Type      uint16
	ActionIds []Action
}

func (obj TableFeaturePropActions) MarshalBinary() ([]byte, error) {
	data := make([]byte, 4)
	for _, action := range obj.ActionIds {
		if buf, err := action.MarshalBinary(); err != nil {
			return nil, err
		} else {
			data = append(data, buf...)
		}
	}
	length := len(data)
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	data = append(data, make([]byte, align8(length)-length)...)
	return data, nil
}

func (obj *TableFeaturePropActions) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	var actionIds actionIdList
	if err = actionIds.UnmarshalBinary(data[4:length]); err != nil {
		return
	} else {
		obj.ActionIds = []Action(actionIds)
	}
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	return
}

type TableFeaturePropOxm struct {
	Type   uint16
	OxmIds []uint32
}

func (obj TableFeaturePropOxm) MarshalBinary() (data []byte, err error) {
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

type TableFeaturePropExperimenter struct {
	Type         uint16
	Experimenter uint32
	ExpType      uint32
	Data         []byte
}

func (obj TableFeaturePropExperimenter) MarshalBinary() ([]byte, error) {
	data := append(make([]byte, 12), obj.Data...)
	length := len(data)
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	binary.BigEndian.PutUint32(data[4:8], obj.Experimenter)
	binary.BigEndian.PutUint32(data[8:12], obj.ExpType)
	data = append(data, make([]byte, align8(length)-length)...)
	return data, nil
}

func (obj *TableFeaturePropExperimenter) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	obj.Experimenter = binary.BigEndian.Uint32(data[4:8])
	obj.ExpType = binary.BigEndian.Uint32(data[8:12])
	obj.Data = data[12:length]
	return
}
