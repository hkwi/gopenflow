package ofp4

import (
	"encoding/binary"
	"errors"
)

func align8(num int) int {
	return (num + 7) / 8 * 8
}

type Any interface{}

type Data interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
	// To reduce type assertions, MarshalBinary() will
	// have pointer reciever, which may be strange.
}

type TypedData interface {
	GetType() uint16 // Use this type where we need type assertion
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
}

type Header struct {
	Version uint8
	Type    uint8
	Xid     uint32
}

type Message struct {
	Header
	Body Any
}

func (obj *Message) MarshalBinary() (data []byte, err error) {
	var body []byte
	if obj.Body != nil {
		switch obj.Type {
		default:
			if body, err = obj.Body.(Data).MarshalBinary(); err != nil {
				return
			}
		case OFPT_HELLO:
			for _, element := range obj.Body.([]TypedData) {
				var buf []byte
				if buf, err = element.MarshalBinary(); err != nil {
					return
				}
				body = append(body, buf...)
			}
		case OFPT_ECHO_REQUEST, OFPT_ECHO_REPLY:
			body = obj.Body.([]byte)
		}
	}
	header := make([]byte, 8)
	header[0] = obj.Version
	header[1] = obj.Type
	binary.BigEndian.PutUint16(header[2:4], uint16(8+len(body)))
	binary.BigEndian.PutUint32(header[4:8], obj.Xid)
	data = append(header, body...)
	return
}

func (obj *Message) UnmarshalBinary(data []byte) (err error) {
	obj.Version = data[0]
	obj.Type = data[1]
	length := int(binary.BigEndian.Uint16(data[2:4]))
	obj.Xid = binary.BigEndian.Uint32(data[4:8])

	var body Data
	switch obj.Type {
	default:
		err = errors.New("Unknown OFPT_")
		return
	case OFPT_GET_CONFIG_REQUEST, OFPT_BARRIER_REQUEST, OFPT_BARRIER_REPLY, OFPT_GET_ASYNC_REQUEST:
		// no body
	case OFPT_HELLO:
		var elements []TypedData
		for cur := 8; cur < length; {
			// look ahead
			eType := binary.BigEndian.Uint16(data[cur : cur+2])
			eLength := int(binary.BigEndian.Uint16(data[cur+2 : cur+4]))
			payload := data[cur : cur+eLength]
			switch eType {
			default:
				err = errors.New("Unknown OFPHET_")
				return
			case OFPHET_VERSIONBITMAP:
				element := new(HelloElementVersionbitmap)
				if err = element.UnmarshalBinary(payload); err != nil {
					return
				}
				elements = append(elements, element)
			}
			cur += eLength
		}
		obj.Body = elements
	case OFPT_ERROR:
		body = new(Error)
	case OFPT_ECHO_REQUEST, OFPT_ECHO_REPLY:
		obj.Body = data[8:length]
	case OFPT_EXPERIMENTER:
		body = new(Experimenter)
	case OFPT_FEATURES_REPLY:
		body = new(SwitchFeatures)
	case OFPT_GET_CONFIG_REPLY, OFPT_SET_CONFIG:
		body = new(SwitchConfig)
	case OFPT_PACKET_IN:
		body = new(PacketIn)
	case OFPT_FLOW_REMOVED:
		body = new(FlowRemoved)
	case OFPT_PORT_STATUS:
		body = new(PortStatus)
	case OFPT_PACKET_OUT:
		body = new(PacketOut)
	case OFPT_FLOW_MOD:
		body = new(FlowMod)
	case OFPT_GROUP_MOD:
		body = new(GroupMod)
	case OFPT_PORT_MOD:
		body = new(PortMod)
	case OFPT_TABLE_MOD:
		body = new(TableMod)
	case OFPT_MULTIPART_REQUEST:
		body = new(MultipartRequest)
	case OFPT_MULTIPART_REPLY:
		body = new(MultipartReply)
	case OFPT_QUEUE_GET_CONFIG_REQUEST:
		body = new(QueueGetConfigRequest)
	case OFPT_QUEUE_GET_CONFIG_REPLY:
		body = new(QueueGetConfigReply)
	case OFPT_ROLE_REQUEST, OFPT_ROLE_REPLY:
		body = new(RoleRequest)
	case OFPT_GET_ASYNC_REPLY, OFPT_SET_ASYNC:
		body = new(AsyncConfig)
	case OFPT_METER_MOD:
		body = new(MeterMod)
	}
	if body != nil {
		if err = body.UnmarshalBinary(data[8:length]); err != nil {
			return
		}
		obj.Body = body
	}
	return
}

func (obj *Message) GetType() uint8 {
	return obj.Type
}

type HelloElementVersionbitmap struct {
	Bitmaps []uint32
}

func (obj *HelloElementVersionbitmap) MarshalBinary() (data []byte, err error) {
	length := 4 + 4*len(obj.Bitmaps)
	data = make([]byte, length)
	binary.BigEndian.PutUint16(data[0:2], OFPHET_VERSIONBITMAP)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	for i, element := range obj.Bitmaps {
		binary.BigEndian.PutUint32(data[4+4*i:8+4*i], element)
	}
	return
}

func (obj *HelloElementVersionbitmap) UnmarshalBinary(data []byte) (err error) {
	obj.Bitmaps = make([]uint32, len(data)/4-1)
	for i, _ := range obj.Bitmaps {
		obj.Bitmaps[i] = binary.BigEndian.Uint32(data[4+4*i : 8+4*i])
	}
	return
}

func (obj *HelloElementVersionbitmap) GetType() uint16 {
	return OFPHET_VERSIONBITMAP
}

type Error struct {
	Type uint16
	Code uint16
	Data []byte
}

func (obj *Error) MarshalBinary() (data []byte, err error) {
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint16(prefix[0:2], obj.Type)
	binary.BigEndian.PutUint16(prefix[2:4], obj.Code)
	return append(prefix, obj.Data...), nil
}

func (obj *Error) UnmarshalBinary(data []byte) (err error) {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	obj.Code = binary.BigEndian.Uint16(data[2:4])
	obj.Data = data[4:]
	return
}

type Junk struct {
	Data []byte
}

func (obj *Junk) MarshalBinary() (data []byte, err error) {
	return obj.Data, nil
}

func (obj *Junk) UnmarshalBinary(data []byte) (err error) {
	obj.Data = data
	return
}

type Experimenter struct {
	Experimenter uint32
	ExpType      uint32
	Data         []byte
}

func (obj *Experimenter) MarshalBinary() (data []byte, err error) {
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint32(prefix[0:4], obj.Experimenter)
	binary.BigEndian.PutUint32(prefix[4:8], obj.ExpType)
	return append(prefix, obj.Data...), nil
}

func (obj *Experimenter) UnmarshalBinary(data []byte) (err error) {
	obj.Experimenter = binary.BigEndian.Uint32(data[0:4])
	obj.ExpType = binary.BigEndian.Uint32(data[4:8])
	obj.Data = data[8:]
	return
}

type SwitchFeatures struct {
	DatapathId   uint64
	NBuffers     uint32
	NTables      uint8
	AuxiliaryId  uint8
	Capabilities uint32
}

func (obj *SwitchFeatures) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 24)
	binary.BigEndian.PutUint64(data[0:8], obj.DatapathId)
	binary.BigEndian.PutUint32(data[8:12], obj.NBuffers)
	data[12] = obj.NTables
	data[13] = obj.AuxiliaryId
	binary.BigEndian.PutUint32(data[16:20], obj.Capabilities)
	return
}

func (obj *SwitchFeatures) UnmarshalBinary(data []byte) (err error) {
	obj.DatapathId = binary.BigEndian.Uint64(data[0:8])
	obj.NBuffers = binary.BigEndian.Uint32(data[8:12])
	obj.NTables = data[12]
	obj.AuxiliaryId = data[13]
	obj.Capabilities = binary.BigEndian.Uint32(data[16:20])
	return
}

type SwitchConfig struct {
	Flags       uint16
	MissSendLen uint16
}

func (obj *SwitchConfig) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], obj.Flags)
	binary.BigEndian.PutUint16(data[2:4], obj.MissSendLen)
	return
}

func (obj *SwitchConfig) UnmarshalBinary(data []byte) (err error) {
	obj.Flags = binary.BigEndian.Uint16(data[0:2])
	obj.MissSendLen = binary.BigEndian.Uint16(data[2:4])
	return
}

type Match struct {
	Type      uint16
	OxmFields []byte
}

func (obj *Match) MarshalBinary() (data []byte, err error) {
	length := 4 + len(obj.OxmFields)
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint16(prefix[0:2], obj.Type)
	binary.BigEndian.PutUint16(prefix[2:4], uint16(length))
	suffix := make([]byte, align8(length)-length)
	data = append(append(prefix, obj.OxmFields...), suffix...)
	return
}

func (obj *Match) UnmarshalBinary(data []byte) (err error) {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	obj.OxmFields = data[4:int(binary.BigEndian.Uint16(data[2:4]))]
	return
}

type PacketIn struct {
	BufferId uint32
	TotalLen uint16
	Reason   uint8
	TableId  uint8
	Cookie   uint64
	Match    Match
	Data     []byte
}

func (obj *PacketIn) MarshalBinary() (data []byte, err error) {
	var match []byte
	if match, err = obj.Match.MarshalBinary(); err != nil {
		return
	}

	prefix := make([]byte, 16)
	binary.BigEndian.PutUint32(prefix[0:4], obj.BufferId)
	binary.BigEndian.PutUint16(prefix[4:6], obj.TotalLen)
	prefix[6] = obj.Reason
	prefix[7] = obj.TableId
	binary.BigEndian.PutUint64(prefix[8:16], obj.Cookie)

	data = append(append(prefix, match...), obj.Data...)
	return
}

func (obj *PacketIn) UnmarshalBinary(data []byte) (err error) {
	matchLength := int(binary.BigEndian.Uint16(data[18:20]))
	if err = obj.Match.UnmarshalBinary(data[16 : 16+matchLength]); err != nil {
		return
	}

	obj.BufferId = binary.BigEndian.Uint32(data[0:4])
	obj.TotalLen = binary.BigEndian.Uint16(data[4:6])
	obj.Reason = data[6]
	obj.TableId = data[7]
	obj.Cookie = binary.BigEndian.Uint64(data[8:16])

	obj.Data = data[16+align8(matchLength):]
	return
}

type FlowRemoved struct {
	Cookie       uint64
	Priority     uint16
	Reason       uint8
	TableId      uint8
	DurationSec  uint32
	DurationNsec uint32
	IdleTimeout  uint16
	HardTimeout  uint16
	PacketCount  uint64
	ByteCount    uint64
	Match        Match
}

func (obj *FlowRemoved) MarshalBinary() (data []byte, err error) {
	var match []byte
	if match, err = obj.Match.MarshalBinary(); err != nil {
		return
	}

	prefix := make([]byte, 40)
	binary.BigEndian.PutUint64(prefix[0:8], obj.Cookie)
	binary.BigEndian.PutUint16(prefix[8:10], obj.Priority)
	prefix[10] = obj.Reason
	prefix[11] = obj.TableId
	binary.BigEndian.PutUint32(prefix[12:16], obj.DurationSec)
	binary.BigEndian.PutUint32(prefix[16:20], obj.DurationNsec)
	binary.BigEndian.PutUint16(prefix[20:22], obj.IdleTimeout)
	binary.BigEndian.PutUint16(prefix[22:24], obj.HardTimeout)
	binary.BigEndian.PutUint64(prefix[24:32], obj.PacketCount)
	binary.BigEndian.PutUint64(prefix[32:40], obj.ByteCount)

	data = append(prefix, match...)
	return
}

func (obj *FlowRemoved) UnmarshalBinary(data []byte) (err error) {
	matchLength := int(binary.BigEndian.Uint16(data[42:44]))
	if err = obj.Match.UnmarshalBinary(data[40 : 40+matchLength]); err != nil {
		return
	}

	obj.Cookie = binary.BigEndian.Uint64(data[0:8])
	obj.Priority = binary.BigEndian.Uint16(data[8:10])
	obj.Reason = data[10]
	obj.TableId = data[11]
	obj.DurationSec = binary.BigEndian.Uint32(data[12:16])
	obj.DurationNsec = binary.BigEndian.Uint32(data[16:20])
	obj.IdleTimeout = binary.BigEndian.Uint16(data[20:22])
	obj.HardTimeout = binary.BigEndian.Uint16(data[22:24])
	obj.PacketCount = binary.BigEndian.Uint64(data[24:32])
	obj.ByteCount = binary.BigEndian.Uint64(data[32:40])
	return
}

type Port struct {
	PortNo     uint32
	HwAddr     [OFP_ETH_ALEN]byte
	Name       string
	Config     uint32
	State      uint32
	Curr       uint32
	Advertised uint32
	Supported  uint32
	Peer       uint32
	CurrSpeed  uint32
	MaxSpeed   uint32
}

func (obj *Port) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 64)
	binary.BigEndian.PutUint32(data[0:4], obj.PortNo)
	for i, addr := range obj.HwAddr {
		data[8+i] = addr
	}
	for i, c := range []byte(obj.Name) {
		if i < OFP_MAX_PORT_NAME_LEN {
			data[16+i] = c
		}
	}
	binary.BigEndian.PutUint32(data[32:36], obj.Config)
	binary.BigEndian.PutUint32(data[36:40], obj.State)
	binary.BigEndian.PutUint32(data[40:44], obj.Curr)
	binary.BigEndian.PutUint32(data[44:48], obj.Advertised)
	binary.BigEndian.PutUint32(data[48:52], obj.Supported)
	binary.BigEndian.PutUint32(data[52:56], obj.Peer)
	binary.BigEndian.PutUint32(data[56:60], obj.CurrSpeed)
	binary.BigEndian.PutUint32(data[60:64], obj.MaxSpeed)
	return
}

func (obj *Port) UnmarshalBinary(data []byte) (err error) {
	obj.PortNo = binary.BigEndian.Uint32(data[0:4])
	for i, addr := range data[8:14] {
		obj.HwAddr[i] = addr
	}
	obj.Name = string(data[16 : 16+OFP_MAX_PORT_NAME_LEN])
	obj.Config = binary.BigEndian.Uint32(data[32:36])
	obj.State = binary.BigEndian.Uint32(data[36:40])
	obj.Curr = binary.BigEndian.Uint32(data[40:44])
	obj.Advertised = binary.BigEndian.Uint32(data[44:48])
	obj.Supported = binary.BigEndian.Uint32(data[48:52])
	obj.Peer = binary.BigEndian.Uint32(data[52:56])
	obj.CurrSpeed = binary.BigEndian.Uint32(data[56:60])
	obj.MaxSpeed = binary.BigEndian.Uint32(data[60:64])
	return
}

type PortStatus struct {
	Reason uint8
	Desc   Port
}

func (obj *PortStatus) MarshalBinary() (data []byte, err error) {
	var desc []byte
	if desc, err = obj.Desc.MarshalBinary(); err != nil {
		return
	}
	prefix := make([]byte, 8)
	prefix[0] = obj.Reason

	data = append(prefix, desc...)
	return
}

func (obj *PortStatus) UnmarshalBinary(data []byte) (err error) {
	obj.Reason = data[0]
	obj.Desc.UnmarshalBinary(data[8:])
	return
}

type PacketOut struct {
	BufferId uint32
	InPort   uint32
	Actions  []TypedData
	Data     []byte
}

func (obj *PacketOut) MarshalBinary() (data []byte, err error) {
	var actions []byte
	for _, action := range obj.Actions {
		var buf []byte
		if buf, err = action.MarshalBinary(); err != nil {
			return
		}
		actions = append(actions, buf...)
	}

	prefix := make([]byte, 16)
	binary.BigEndian.PutUint32(prefix[0:4], obj.BufferId)
	binary.BigEndian.PutUint32(prefix[4:8], obj.InPort)
	binary.BigEndian.PutUint16(prefix[8:10], uint16(len(obj.Actions)))

	data = append(append(prefix, actions...), obj.Data...)
	return
}

func (obj *PacketOut) UnmarshalBinary(data []byte) (err error) {
	obj.BufferId = binary.BigEndian.Uint32(data[0:4])
	obj.InPort = binary.BigEndian.Uint32(data[4:8])
	actionsLen := int(binary.BigEndian.Uint16(data[8:10]))

	if obj.Actions, err = actionsUnmarshalBinary(data[16 : 16+actionsLen]); err != nil {
		return
	}
	obj.Data = data[16+actionsLen:]
	return
}

type FlowMod struct {
	Cookie       uint64
	CookieMask   uint64
	TableId      uint8
	Command      uint8
	IdleTimeout  uint16
	HardTimeout  uint16
	Priority     uint16
	BufferId     uint32
	OutPort      uint32
	OutGroup     uint32
	Flags        uint16
	Match        Match
	Instructions []TypedData
}

func (obj *FlowMod) MarshalBinary() (data []byte, err error) {
	var match []byte
	if match, err = obj.Match.MarshalBinary(); err != nil {
		return
	}
	var instructions []byte
	for _, inst := range obj.Instructions {
		var buf []byte
		if buf, err = inst.MarshalBinary(); err != nil {
			return
		}
		instructions = append(instructions, buf...)
	}
	prefix := make([]byte, 40)
	binary.BigEndian.PutUint64(prefix[0:8], obj.Cookie)
	binary.BigEndian.PutUint64(prefix[8:16], obj.CookieMask)
	prefix[16] = obj.TableId
	prefix[17] = obj.Command
	binary.BigEndian.PutUint16(prefix[18:20], obj.IdleTimeout)
	binary.BigEndian.PutUint16(prefix[20:22], obj.HardTimeout)
	binary.BigEndian.PutUint16(prefix[22:24], obj.Priority)
	binary.BigEndian.PutUint32(prefix[24:28], obj.BufferId)
	binary.BigEndian.PutUint32(prefix[28:32], obj.OutPort)
	binary.BigEndian.PutUint32(prefix[32:36], obj.OutGroup)
	binary.BigEndian.PutUint16(prefix[36:38], obj.Flags)

	data = append(append(prefix, match...), instructions...)
	return
}

func (obj *FlowMod) UnmarshalBinary(data []byte) (err error) {
	matchLength := int(binary.BigEndian.Uint16(data[42:44]))
	if err = obj.Match.UnmarshalBinary(data[40 : 40+matchLength]); err != nil {
		return
	}
	if obj.Instructions, err = instructionsUnmarshalBinary(data[40+matchLength:]); err != nil {
		return
	}
	obj.Cookie = binary.BigEndian.Uint64(data[0:8])
	obj.CookieMask = binary.BigEndian.Uint64(data[8:16])
	obj.TableId = data[16]
	obj.Command = data[17]
	obj.IdleTimeout = binary.BigEndian.Uint16(data[18:20])
	obj.HardTimeout = binary.BigEndian.Uint16(data[20:22])
	obj.Priority = binary.BigEndian.Uint16(data[22:24])
	obj.BufferId = binary.BigEndian.Uint32(data[24:28])
	obj.OutPort = binary.BigEndian.Uint32(data[28:32])
	obj.OutGroup = binary.BigEndian.Uint32(data[32:36])
	obj.Flags = binary.BigEndian.Uint16(data[36:38])
	return
}

type GroupMod struct {
	Command uint16
	Type    uint8
	GroupId uint32
	Buckets []Data
}

func (obj *GroupMod) MarshalBinary() (data []byte, err error) {
	var buckets []byte
	for _, bucket := range obj.Buckets {
		var buf []byte
		if buf, err = bucket.MarshalBinary(); err != nil {
			return
		}
		buckets = append(buckets, buf...)
	}
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint16(prefix[0:2], obj.Command)
	prefix[2] = obj.Type
	binary.BigEndian.PutUint32(prefix[4:8], obj.GroupId)
	data = append(prefix, buckets...)
	return
}

func (obj *GroupMod) UnmarshalBinary(data []byte) (err error) {
	obj.Buckets = nil
	for cur := 8; cur < len(data); {
		length := int(binary.BigEndian.Uint16(data[cur : 2+cur]))
		bucket := new(Bucket)
		if err = bucket.UnmarshalBinary(data[cur : cur+length]); err != nil {
			return
		} else {
			obj.Buckets = append(obj.Buckets, bucket)
		}
		cur += length
	}
	obj.Command = binary.BigEndian.Uint16(data[0:2])
	obj.Type = data[2]
	obj.GroupId = binary.BigEndian.Uint32(data[4:8])
	return
}

type Bucket struct {
	Weight     uint16
	WatchPort  uint32
	WatchGroup uint32
	Actions    []TypedData
}

func (obj *Bucket) MarshalBinary() (data []byte, err error) {
	var actions []byte
	for _, action := range obj.Actions {
		var buf []byte
		if buf, err = action.MarshalBinary(); err != nil {
			return
		}
		actions = append(actions, buf...)
	}
	prefix := make([]byte, 16)
	binary.BigEndian.PutUint16(prefix[0:2], uint16(16+len(actions)))
	binary.BigEndian.PutUint16(prefix[2:4], obj.Weight)
	binary.BigEndian.PutUint32(prefix[4:8], obj.WatchPort)
	binary.BigEndian.PutUint32(prefix[8:12], obj.WatchGroup)
	data = append(prefix, actions...)
	return
}

func (obj *Bucket) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[0:2]))
	if obj.Actions, err = actionsUnmarshalBinary(data[16:length]); err != nil {
		return
	}
	obj.Weight = binary.BigEndian.Uint16(data[2:4])
	obj.WatchPort = binary.BigEndian.Uint32(data[4:8])
	obj.WatchGroup = binary.BigEndian.Uint32(data[8:12])
	return
}

type PortMod struct {
	PortNo    uint32
	HwAddr    [OFP_ETH_ALEN]byte
	Config    uint32
	Mask      uint32
	Advertise uint32
}

func (obj *PortMod) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 32)
	binary.BigEndian.PutUint32(data[0:4], obj.PortNo)
	for i, addr := range obj.HwAddr {
		data[8+i] = addr
	}
	binary.BigEndian.PutUint32(data[16:20], obj.Config)
	binary.BigEndian.PutUint32(data[20:24], obj.Mask)
	binary.BigEndian.PutUint32(data[24:28], obj.Advertise)
	return
}

func (obj *PortMod) UnmarshalBinary(data []byte) (err error) {
	obj.PortNo = binary.BigEndian.Uint32(data[0:4])
	for i, _ := range obj.HwAddr {
		obj.HwAddr[i] = data[8+i]
	}
	obj.Config = binary.BigEndian.Uint32(data[16:20])
	obj.Mask = binary.BigEndian.Uint32(data[20:24])
	obj.Advertise = binary.BigEndian.Uint32(data[24:28])
	return
}

type TableMod struct {
	TableId uint8
	Config  uint32
}

func (obj *TableMod) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	data[0] = obj.TableId
	binary.BigEndian.PutUint32(data[4:8], obj.Config)
	return
}

func (obj *TableMod) UnmarshalBinary(data []byte) (err error) {
	obj.TableId = data[0]
	obj.Config = binary.BigEndian.Uint32(data[4:8])
	return
}

type QueueGetConfigRequest struct {
	Port uint32
}

func (obj *QueueGetConfigRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], obj.Port)
	return
}

func (obj *QueueGetConfigRequest) UnmarshalBinary(data []byte) (err error) {
	obj.Port = binary.BigEndian.Uint32(data[0:4])
	return
}

type QueueGetConfigReply struct {
	Port   uint32
	Queues []PacketQueue
}

func (obj *QueueGetConfigReply) MarshalBinary() (data []byte, err error) {
	var queues []byte
	for _, queue := range obj.Queues {
		var buf []byte
		if buf, err = queue.MarshalBinary(); err != nil {
			return
		}
		queues = append(queues, buf...)
	}
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint32(prefix[0:4], obj.Port)
	data = append(prefix, queues...)
	return
}

func (obj *QueueGetConfigReply) UnmarshalBinary(data []byte) (err error) {
	var queues []PacketQueue
	for cur := 16; cur < len(data); {
		length := int(binary.BigEndian.Uint16(data[8+cur : 10+cur]))
		queue := new(PacketQueue)
		if err = queue.UnmarshalBinary(data[cur : cur+length]); err != nil {
			return
		}
		queues = append(queues, *queue)
		cur += length
	}
	obj.Port = binary.BigEndian.Uint32(data[0:4])
	obj.Queues = queues
	return
}

type PacketQueue struct {
	QueueId    uint32
	Port       uint32
	Properties []TypedData
}

func (obj *PacketQueue) MarshalBinary() (data []byte, err error) {
	var properties []byte
	for _, property := range obj.Properties {
		var buf []byte
		if buf, err = property.MarshalBinary(); err != nil {
			return
		}
		properties = append(properties, buf...)
	}
	prefix := make([]byte, 16)
	binary.BigEndian.PutUint32(prefix[0:4], obj.QueueId)
	binary.BigEndian.PutUint32(prefix[4:8], obj.Port)
	binary.BigEndian.PutUint16(prefix[8:10], uint16(16+len(properties)))
	data = append(prefix, properties...)
	return
}

func (obj *PacketQueue) UnmarshalBinary(data []byte) (err error) {
	length := int(binary.BigEndian.Uint16(data[8:10]))
	if obj.Properties, err = queuePropertiesUnmarshalBinary(data[16:length]); err != nil {
		return
	}
	obj.QueueId = binary.BigEndian.Uint32(data[0:4])
	obj.Port = binary.BigEndian.Uint32(data[4:8])
	return
}

type RoleRequest struct {
	Role         uint32
	GenerationId uint64
}

func (obj *RoleRequest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 16)
	binary.BigEndian.PutUint32(data[0:4], obj.Role)
	binary.BigEndian.PutUint64(data[8:16], obj.GenerationId)
	return
}

func (obj *RoleRequest) UnmarshalBinary(data []byte) (err error) {
	obj.Role = binary.BigEndian.Uint32(data[0:4])
	obj.GenerationId = binary.BigEndian.Uint64(data[8:16])
	return
}

type AsyncConfig struct {
	PacketInMask    [2]uint32
	PortStatusMask  [2]uint32
	FlowRemovedMask [2]uint32
}

func (obj *AsyncConfig) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 24)
	for i, num := range obj.PacketInMask {
		pos := i * 4
		binary.BigEndian.PutUint32(data[pos:4+pos], num)
	}
	for i, num := range obj.PortStatusMask {
		pos := i*4 + 8
		binary.BigEndian.PutUint32(data[pos:4+pos], num)
	}
	for i, num := range obj.FlowRemovedMask {
		pos := i*4 + 16
		binary.BigEndian.PutUint32(data[pos:4+pos], num)
	}
	return
}

func (obj *AsyncConfig) UnmarshalBinary(data []byte) (err error) {
	for i, _ := range obj.PacketInMask {
		pos := i * 4
		obj.PacketInMask[i] = binary.BigEndian.Uint32(data[pos : 4+pos])
	}
	for i, _ := range obj.PortStatusMask {
		pos := i*4 + 8
		obj.PortStatusMask[i] = binary.BigEndian.Uint32(data[pos : 4+pos])
	}
	for i, _ := range obj.FlowRemovedMask {
		pos := i*4 + 16
		obj.FlowRemovedMask[i] = binary.BigEndian.Uint32(data[pos : 4+pos])
	}
	return
}

type MeterMod struct {
	Command uint16
	Flags   uint16
	MeterId uint32
	Bands   []TypedData
}

func (obj *MeterMod) MarshalBinary() (data []byte, err error) {
	var bands []byte
	for _, band := range obj.Bands {
		var buf []byte
		if buf, err = band.MarshalBinary(); err != nil {
			return
		}
		bands = append(bands, buf...)
	}
	prefix := make([]byte, 16)
	binary.BigEndian.PutUint16(prefix[0:2], obj.Command)
	binary.BigEndian.PutUint16(prefix[2:4], obj.Flags)
	binary.BigEndian.PutUint32(prefix[4:8], obj.MeterId)

	data = append(prefix, bands...)
	return
}

func (obj *MeterMod) UnmarshalBinary(data []byte) (err error) {
	if obj.Bands, err = meterBandsUnmarshalBinary(data[16:]); err != nil {
		return
	}
	obj.Command = binary.BigEndian.Uint16(data[0:2])
	obj.Flags = binary.BigEndian.Uint16(data[2:4])
	obj.MeterId = binary.BigEndian.Uint32(data[4:8])
	return
}
