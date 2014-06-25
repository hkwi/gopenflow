package ofp4

import (
	"encoding/binary"
	"errors"
)

func actionIdsUnmarshalBinary(data []byte) (actions []TypedData, err error) {
	for cur := 0; cur < len(data); {
		atype := binary.BigEndian.Uint16(data[cur : 2+cur])
		alen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var action TypedData
		switch atype {
		default:
			err = errors.New("Unknown OFPAT_")
			return
		case OFPAT_OUTPUT,
			OFPAT_COPY_TTL_OUT,
			OFPAT_COPY_TTL_IN,
			OFPAT_SET_MPLS_TTL,
			OFPAT_DEC_MPLS_TTL,
			OFPAT_PUSH_VLAN,
			OFPAT_POP_VLAN,
			OFPAT_PUSH_MPLS,
			OFPAT_POP_MPLS,
			OFPAT_SET_QUEUE,
			OFPAT_GROUP,
			OFPAT_SET_NW_TTL,
			OFPAT_DEC_NW_TTL,
			OFPAT_SET_FIELD,
			OFPAT_PUSH_PBB,
			OFPAT_POP_PBB:
			action = new(ActionGeneric)
		case OFPAT_EXPERIMENTER:
			action = new(ActionExperimenter)
		}
		if err = action.UnmarshalBinary(data[cur : cur+alen]); err != nil {
			return
		}
		actions = append(actions, action)
		cur += alen
	}
	return
}

func actionsUnmarshalBinary(data []byte) (actions []TypedData, err error) {
	for cur := 0; cur < len(data); {
		atype := binary.BigEndian.Uint16(data[cur : 2+cur])
		alen := int(binary.BigEndian.Uint16(data[2+cur : 4+cur]))
		var action TypedData
		switch atype {
		default:
			err = errors.New("Unknown OFPAT_")
			return
		case OFPAT_COPY_TTL_OUT, OFPAT_COPY_TTL_IN, OFPAT_DEC_MPLS_TTL, OFPAT_POP_VLAN, OFPAT_DEC_NW_TTL, OFPAT_POP_PBB:
			action = new(ActionGeneric)
		case OFPAT_OUTPUT:
			action = new(ActionOutput)
		case OFPAT_SET_MPLS_TTL:
			action = new(ActionMplsTtl)
		case OFPAT_PUSH_VLAN, OFPAT_PUSH_MPLS, OFPAT_PUSH_PBB:
			action = new(ActionPush)
		case OFPAT_POP_MPLS:
			action = new(ActionPopMpls)
		case OFPAT_SET_QUEUE:
			action = new(ActionSetQueue)
		case OFPAT_GROUP:
			action = new(ActionGroup)
		case OFPAT_SET_NW_TTL:
			action = new(ActionNwTtl)
		case OFPAT_SET_FIELD:
			action = new(ActionSetField)
		case OFPAT_EXPERIMENTER:
			action = new(ActionExperimenter)
		}
		if err = action.UnmarshalBinary(data[cur : cur+alen]); err != nil {
			return
		}
		actions = append(actions, action)
		cur += alen
	}
	return
}

type ActionGeneric struct {
	Type uint16
}

func (obj *ActionGeneric) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], 8)
	return
}

func (obj *ActionGeneric) UnmarshalBinary(data []byte) (err error) {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	return
}

func (obj *ActionGeneric) GetType() uint16 {
	return obj.Type
}

type ActionOutput struct {
	Port   uint32
	MaxLen uint16
}

func (obj *ActionOutput) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	binary.BigEndian.PutUint16(data[0:2], OFPAT_OUTPUT)
	binary.BigEndian.PutUint16(data[2:4], 16)
	binary.BigEndian.PutUint32(data[4:8], obj.Port)
	binary.BigEndian.PutUint16(data[8:10], obj.MaxLen)
	return
}
func (obj *ActionOutput) UnmarshalBinary(data []byte) (err error) {
	obj.Port = binary.BigEndian.Uint32(data[4:8])
	obj.MaxLen = binary.BigEndian.Uint16(data[8:10])
	return
}
func (obj *ActionOutput) GetType() uint16 {
	return OFPAT_OUTPUT
}

type ActionMplsTtl struct {
	MplsTtl uint8
}

func (obj *ActionMplsTtl) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], OFPAT_SET_MPLS_TTL)
	binary.BigEndian.PutUint16(data[2:4], 8)
	data[4] = obj.MplsTtl
	return
}
func (obj *ActionMplsTtl) UnmarshalBinary(data []byte) (err error) {
	obj.MplsTtl = data[4]
	return
}
func (obj *ActionMplsTtl) GetType() uint16 {
	return OFPAT_SET_MPLS_TTL
}

type ActionPush struct {
	Type      uint16
	Ethertype uint16
}

func (obj *ActionPush) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], 8)
	binary.BigEndian.PutUint16(data[4:6], obj.Ethertype)
	return
}
func (obj *ActionPush) UnmarshalBinary(data []byte) (err error) {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	obj.Ethertype = binary.BigEndian.Uint16(data[4:6])
	return
}
func (obj *ActionPush) GetType() uint16 {
	return obj.Type
}

type ActionPopMpls struct {
	Ethertype uint16
}

func (obj *ActionPopMpls) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], OFPAT_POP_MPLS)
	binary.BigEndian.PutUint16(data[2:4], 8)
	binary.BigEndian.PutUint16(data[4:6], obj.Ethertype)
	return
}
func (obj *ActionPopMpls) UnmarshalBinary(data []byte) (err error) {
	obj.Ethertype = binary.BigEndian.Uint16(data[4:6])
	return
}
func (obj *ActionPopMpls) GetType() uint16 {
	return OFPAT_POP_MPLS
}

type ActionSetQueue struct {
	QueueId uint32
}

func (obj *ActionSetQueue) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], OFPAT_SET_QUEUE)
	binary.BigEndian.PutUint16(data[2:4], 8)
	binary.BigEndian.PutUint32(data[4:8], obj.QueueId)
	return
}
func (obj *ActionSetQueue) UnmarshalBinary(data []byte) (err error) {
	obj.QueueId = binary.BigEndian.Uint32(data[4:8])
	return
}
func (obj *ActionSetQueue) GetType() uint16 {
	return OFPAT_SET_QUEUE
}

type ActionGroup struct {
	GroupId uint32
}

func (obj *ActionGroup) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], OFPAT_GROUP)
	binary.BigEndian.PutUint16(data[2:4], 8)
	binary.BigEndian.PutUint32(data[4:8], obj.GroupId)
	return
}
func (obj *ActionGroup) UnmarshalBinary(data []byte) (err error) {
	obj.GroupId = binary.BigEndian.Uint32(data[4:8])
	return
}
func (obj *ActionGroup) GetType() uint16 {
	return OFPAT_GROUP
}

type ActionNwTtl struct {
	NwTtl uint8
}

func (obj *ActionNwTtl) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint16(data[0:2], OFPAT_SET_NW_TTL)
	binary.BigEndian.PutUint16(data[2:4], 8)
	data[4] = obj.NwTtl
	return
}
func (obj *ActionNwTtl) UnmarshalBinary(data []byte) (err error) {
	obj.NwTtl = data[4]
	return
}
func (obj *ActionNwTtl) GetType() uint16 {
	return OFPAT_SET_NW_TTL
}

type ActionSetField struct {
	Field []byte
}

func (obj *ActionSetField) MarshalBinary() (data []byte, err error) {
	length := 8 + len(obj.Field)
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint16(prefix[0:2], OFPAT_SET_FIELD)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(align8(length)))
	data = append(append(prefix, obj.Field...), make([]byte, align8(length)-length)...)
	return
}
func (obj *ActionSetField) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.Field = data[8:length]
	return
}
func (obj *ActionSetField) GetType() uint16 {
	return OFPAT_SET_FIELD
}

type ActionExperimenter struct {
	Experimenter uint32
	Data         []byte
}

func (obj *ActionExperimenter) MarshalBinary() (data []byte, err error) {
	length := 8 + len(obj.Data)
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint16(prefix[0:2], OFPAT_EXPERIMENTER)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(align8(length)))
	binary.BigEndian.PutUint32(prefix[4:8], obj.Experimenter)
	data = append(append(prefix, obj.Data...), make([]byte, align8(length)-length)...)
	return
}
func (obj *ActionExperimenter) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.Experimenter = binary.BigEndian.Uint32(data[4:8])
	obj.Data = data[8:length]
	return
}
func (obj *ActionExperimenter) GetType() uint16 {
	return OFPAT_EXPERIMENTER
}
