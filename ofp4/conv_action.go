package ofp4

import (
	"encoding/binary"
)

type ActionHeader []byte

func (self ActionHeader) Type() uint16 {
	return binary.BigEndian.Uint16(self)
}

/*
 * Length of action, including header and padding to make this 64-bit aligned.
 */
func (self ActionHeader) Len() int {
	return int(binary.BigEndian.Uint16(self[2:]))
}

func (self ActionHeader) Iter() []ActionHeader {
	var seq []ActionHeader
	for cur := 0; cur < len(self); {
		a := ActionHeader(self[cur:])
		seq = append(seq, a[:a.Len()])
		cur += a.Len()
	}
	return seq
}

func MakeActionHeader(atype uint16) ActionHeader {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint16(ret[0:], atype)
	binary.BigEndian.PutUint16(ret[2:], 8)
	return ret
}

type ActionOutput []byte

func (self ActionOutput) Port() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self ActionOutput) MaxLen() uint16 {
	return binary.BigEndian.Uint16(self[8:])
}

func MakeActionOutput(port uint32, maxLen uint16) ActionHeader {
	ret := make([]byte, 16)
	binary.BigEndian.PutUint16(ret[0:], OFPAT_OUTPUT)
	binary.BigEndian.PutUint16(ret[2:], 16)
	binary.BigEndian.PutUint32(ret[4:], port)
	binary.BigEndian.PutUint16(ret[8:], maxLen)
	return ret
}

type ActionGroup []byte

func (self ActionGroup) GroupId() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func MakeActionGroup(groupId uint32) ActionHeader {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint16(ret[0:], OFPAT_GROUP)
	binary.BigEndian.PutUint16(ret[2:], 8)
	binary.BigEndian.PutUint32(ret[4:], groupId)
	return ret
}

type ActionSetQueue []byte

func (self ActionSetQueue) QueueId() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func MakeActionSetQueue(queueId uint32) ActionHeader {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint16(ret[0:], OFPAT_SET_QUEUE)
	binary.BigEndian.PutUint16(ret[2:], 8)
	binary.BigEndian.PutUint32(ret[4:], queueId)
	return ret
}

type ActionMplsTtl []byte

func (self ActionMplsTtl) MplsTtl() uint8 {
	return self[4]
}

func MakeActionMplsTtl(mplsTtl uint8) ActionHeader {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint16(ret[0:], OFPAT_SET_MPLS_TTL)
	binary.BigEndian.PutUint16(ret[2:], 8)
	ret[4] = mplsTtl
	return ret
}

type ActionNwTtl []byte

func (self ActionNwTtl) NwTtl() uint8 {
	return self[4]
}

func MakeActionNwTtl(nwTtl uint8) ActionHeader {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint16(ret[0:], OFPAT_SET_NW_TTL)
	binary.BigEndian.PutUint16(ret[2:], 8)
	ret[4] = nwTtl
	return ret
}

type ActionPush []byte

func (self ActionPush) Ethertype() uint16 {
	return binary.BigEndian.Uint16(self[4:])
}

func MakeActionPush(atype uint16, ethertype uint16) ActionHeader {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint16(ret[0:], atype)
	binary.BigEndian.PutUint16(ret[2:], 8)
	binary.BigEndian.PutUint16(ret[4:], ethertype)
	return ret
}

type ActionPopMpls []byte

func (self ActionPopMpls) Ethertype() uint16 {
	return binary.BigEndian.Uint16(self[4:])
}

func MakeActionPopMpls(ethertype uint16) ActionHeader {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint16(ret[0:], OFPAT_POP_MPLS)
	binary.BigEndian.PutUint16(ret[2:], 8)
	binary.BigEndian.PutUint16(ret[4:], ethertype)
	return ret
}

type ActionSetField []byte

func (self ActionSetField) Field() []byte {
	return self[4:ActionHeader(self).Len()]
}

func MakeActionSetField(field []byte) ActionHeader {
	inner := 4 + len(field)
	length := (inner + 7) / 8 * 8
	ret := make([]byte, length)
	binary.BigEndian.PutUint16(ret[0:], OFPAT_SET_FIELD)
	binary.BigEndian.PutUint16(ret[2:], uint16(length))
	copy(ret[4:], field)
	return ret
}

type ActionExperimenterHeader []byte

func (self ActionExperimenterHeader) Experimenter() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self ActionExperimenterHeader) AppendData(data []byte) ActionHeader {
	length := 8 + len(data)
	ret := make([]byte, length)
	copy(ret[:8], self)
	copy(ret[8:], data)
	binary.BigEndian.PutUint16(ret[2:], uint16(length))
	return ret
}

func MakeActionExperimenterHeader(experimenter uint32) ActionHeader {
	self := make([]byte, 8)
	binary.BigEndian.PutUint16(self[0:], OFPAT_EXPERIMENTER)
	binary.BigEndian.PutUint16(self[2:], 8)
	binary.BigEndian.PutUint32(self[4:], experimenter)
	return self
}
