package ofp4

import (
	"encoding"
	"encoding/binary"
)

/*
Body of MultipartRequest is as following.
	OFPMP_DESC           nil
	OFPMP_TABLE          nil
	OFPMP_GROUP_DESC     nil
	OFPMP_GROUP_FEATURES nil
	OFPMP_METER_FEATURES nil
	OFPMP_PORT_DESC      nil
	OFPMP_FLOW           FlowStatsRequest
	OFPMP_AGGREGATE      AggregateStatsRequest
	OFPMP_PORT_STATS     PortStatsRequest
	OFPMP_QUEUE          QueueStatsRequest
	OFPMP_GROUP          GroupStatsRequest
	OFPMP_METER          MeterMultipartRequest
	OFPMP_METER_CONFIG   MeterMultipartRequest
	OFPMP_TABLE_FEATURES Array of TableFeatures
	OFPMP_EXPERIMENTER   ExperimenterMultipart
*/
type MultipartRequest struct {
	Type  uint16
	Flags uint16
	Body  encoding.BinaryMarshaler
}

func (obj MultipartRequest) MarshalBinary() ([]byte, error) {
	var data []byte
	switch obj.Type {
	default:
		return nil, Error{OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART, nil}
	case OFPMP_DESC,
		OFPMP_FLOW,
		OFPMP_AGGREGATE,
		OFPMP_TABLE,
		OFPMP_PORT_STATS,
		OFPMP_QUEUE,
		OFPMP_GROUP,
		OFPMP_GROUP_DESC,
		OFPMP_GROUP_FEATURES,
		OFPMP_METER,
		OFPMP_METER_CONFIG,
		OFPMP_METER_FEATURES,
		OFPMP_PORT_DESC,
		OFPMP_TABLE_FEATURES,
		OFPMP_EXPERIMENTER:
		if buf, err := obj.Body.MarshalBinary(); err != nil {
			return nil, err
		} else {
			data = make([]byte, 8+len(buf))
			copy(data[8:], buf)
		}
	}
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], obj.Flags)
	// 4 padding
	return data, nil
}

func (obj *MultipartRequest) UnmarshalBinary(data []byte) error {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	obj.Flags = binary.BigEndian.Uint16(data[2:4])
	var body encoding.BinaryMarshaler
	switch obj.Type {
	default:
		return Error{OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART, nil}
	case OFPMP_DESC, OFPMP_TABLE, OFPMP_GROUP_DESC, OFPMP_GROUP_FEATURES, OFPMP_METER_FEATURES, OFPMP_PORT_DESC:
		body = nil
	case OFPMP_FLOW:
		body = new(FlowStatsRequest)
	case OFPMP_AGGREGATE:
		body = new(AggregateStatsRequest)
	case OFPMP_PORT_STATS:
		body = new(PortStatsRequest)
	case OFPMP_QUEUE:
		body = new(QueueStatsRequest)
	case OFPMP_GROUP:
		body = new(GroupStatsRequest)
	case OFPMP_METER, OFPMP_METER_CONFIG:
		body = new(MeterMultipartRequest)
	case OFPMP_TABLE_FEATURES:
		var features []encoding.BinaryMarshaler
		for cur := 8; cur < len(data); {
			entry := new(TableFeatures)
			length := int(binary.BigEndian.Uint16(data[cur:2]))
			if err := entry.UnmarshalBinary(data[cur : cur+length]); err != nil {
				return err
			}
			features = append(features, entry)
			cur += length
		}
		obj.Body = Array(features)
	case OFPMP_EXPERIMENTER:
		body = new(ExperimenterMultipart)
	}
	if body != nil {
		if err := body.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[8:]); err != nil {
			return err
		}
		obj.Body = body
	}
	return nil
}

/*
Body of MultipartReply is as following.
	OFPMP_DESC           Desc
	OFPMP_FLOW           Array of FlowStats
	OFPMP_AGGREGATE      AggregateStatsReply
	OFPMP_TABLE          Array of TableStats
	OFPMP_PORT_STATS     Array of PortStats
	OFPMP_QUEUE          Array of QueueStats
	OFPMP_GROUP          Array of GroupStats
	OFPMP_GROUP_DESC     Array of GroupDesc
	OFPMP_GROUP_FEATURES Array of GroupFeatures
	OFPMP_METER          Array of MeterStats
	OFPMP_METER_CONFIG   Array of MeterConfig
	OFPMP_METER_FEATURES MeterFeatures
	OFPMP_TABLE_FEATURES Array of TableFeatures
	OFPMP_PORT_DESC      Array of Port
	OFPMP_EXPERIMENTER   ExperimenterMultipart
*/
type MultipartReply struct {
	Type  uint16
	Flags uint16
	Body  encoding.BinaryMarshaler
}

func (obj MultipartReply) MarshalBinary() ([]byte, error) {
	var data []byte
	switch obj.Type {
	default:
		return nil, Error{OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART, nil}
	case OFPMP_DESC,
		OFPMP_AGGREGATE,
		OFPMP_GROUP_FEATURES,
		OFPMP_METER_FEATURES,
		OFPMP_EXPERIMENTER,
		OFPMP_FLOW,
		OFPMP_TABLE,
		OFPMP_PORT_STATS,
		OFPMP_QUEUE,
		OFPMP_GROUP,
		OFPMP_GROUP_DESC,
		OFPMP_METER,
		OFPMP_METER_CONFIG,
		OFPMP_TABLE_FEATURES,
		OFPMP_PORT_DESC:
		if buf, err := obj.Body.MarshalBinary(); err != nil {
			return nil, err
		} else {
			data = make([]byte, 8+len(buf))
			copy(data[8:], buf)
		}
	}
	binary.BigEndian.PutUint16(data[0:2], obj.Type)
	binary.BigEndian.PutUint16(data[2:4], obj.Flags)
	// 4 padding
	return data, nil
}

func (obj *MultipartReply) UnmarshalBinary(data []byte) error {
	obj.Type = binary.BigEndian.Uint16(data[0:2])
	obj.Flags = binary.BigEndian.Uint16(data[2:4])
	var body encoding.BinaryMarshaler
	switch obj.Type {
	default:
		return Error{OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART, nil}
	case OFPMP_DESC:
		body = new(Desc)
	case OFPMP_FLOW:
		var array []encoding.BinaryMarshaler
		for cur := 8; cur < len(data); {
			length := int(binary.BigEndian.Uint16(data[cur : 2+cur]))
			entry := new(FlowStats)
			if err := entry.UnmarshalBinary(data[cur : cur+length]); err != nil {
				return err
			}
			array = append(array, entry)
			cur += length
		}
		obj.Body = Array(array)
	case OFPMP_AGGREGATE:
		body = new(AggregateStatsReply)
	case OFPMP_TABLE:
		var array = make([]encoding.BinaryMarshaler, (len(data)-8)/24)
		for i, _ := range array {
			entry := new(TableStats)
			if err := entry.UnmarshalBinary(data[8+24*i : 32+24*i]); err != nil {
				return err
			}
			array[i] = entry
		}
		obj.Body = Array(array)
	case OFPMP_PORT_STATS:
		var array = make([]encoding.BinaryMarshaler, (len(data)-8)/112)
		for i, _ := range array {
			entry := new(PortStats)
			if err := entry.UnmarshalBinary(data[8+112*i : 120+112*i]); err != nil {
				return err
			}
			array[i] = entry
		}
		obj.Body = Array(array)
	case OFPMP_QUEUE:
		var array = make([]encoding.BinaryMarshaler, (len(data)-8)/40)
		for i, _ := range array {
			entry := new(QueueStats)
			if err := entry.UnmarshalBinary(data[8+40*i : 48+40*i]); err != nil {
				return err
			}
			array[i] = entry
		}
		obj.Body = Array(array)
	case OFPMP_GROUP:
		var array []encoding.BinaryMarshaler
		for cur := 8; cur < len(data); {
			length := int(binary.BigEndian.Uint16(data[cur : cur+2]))
			entry := new(GroupStats)
			if err := entry.UnmarshalBinary(data[cur : cur+length]); err != nil {
				return err
			}
			array = append(array, entry)
			cur += length
		}
		obj.Body = Array(array)
	case OFPMP_GROUP_DESC:
		var array []encoding.BinaryMarshaler
		for cur := 8; cur < len(data); {
			length := int(binary.BigEndian.Uint16(data[cur : cur+2]))
			entry := new(GroupDesc)
			if err := entry.UnmarshalBinary(data[cur : cur+length]); err != nil {
				return err
			}
			array = append(array, entry)
			cur += length
		}
		obj.Body = Array(array)
	case OFPMP_GROUP_FEATURES:
		body = new(GroupFeatures)
	case OFPMP_METER:
		var array []encoding.BinaryMarshaler
		for cur := 8; cur < len(data); {
			length := int(binary.BigEndian.Uint16(data[cur+4 : cur+6]))
			entry := new(MeterStats)
			if err := entry.UnmarshalBinary(data[cur : cur+length]); err != nil {
				return err
			}
			cur += length
		}
		obj.Body = Array(array)
	case OFPMP_METER_CONFIG:
		var array []encoding.BinaryMarshaler
		for cur := 8; cur < len(data); {
			length := int(binary.BigEndian.Uint16(data[cur : cur+2]))
			entry := new(MeterConfig)
			if err := entry.UnmarshalBinary(data[cur : cur+length]); err != nil {
				return err
			}
			cur += length
		}
		obj.Body = Array(array)
	case OFPMP_METER_FEATURES:
		body = new(MeterFeatures)
	case OFPMP_TABLE_FEATURES:
		var array []encoding.BinaryMarshaler
		for cur := 8; cur < len(data); {
			length := int(binary.BigEndian.Uint16(data[cur : cur+2]))
			entry := new(TableFeatures)
			if err := entry.UnmarshalBinary(data[cur : cur+length]); err != nil {
				return err
			}
			cur += length
		}
		obj.Body = Array(array)
	case OFPMP_PORT_DESC:
		var array = make([]encoding.BinaryMarshaler, (len(data)-8)/64)
		for i, _ := range array {
			entry := new(Port)
			if err := entry.UnmarshalBinary(data[8+112*i : 120+112*i]); err != nil {
				return err
			}
			array[i] = entry
		}
		obj.Body = Array(array)
	case OFPMP_EXPERIMENTER:
		body = new(ExperimenterMultipart)
	}
	if body != nil {
		if err := body.(encoding.BinaryUnmarshaler).UnmarshalBinary(data[8:]); err != nil {
			return err
		}
		obj.Body = body
	}
	return nil
}

type FlowStatsRequest struct {
	TableId    uint8
	OutPort    uint32
	OutGroup   uint32
	Cookie     uint64
	CookieMask uint64
	Match      Match
}

func (obj FlowStatsRequest) MarshalBinary() ([]byte, error) {
	match, err := obj.Match.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, 32+len(match))
	data[0] = obj.TableId
	// 3 padding
	binary.BigEndian.PutUint32(data[4:8], obj.OutPort)
	binary.BigEndian.PutUint32(data[8:12], obj.OutGroup)
	// 4 padding
	binary.BigEndian.PutUint64(data[16:24], obj.Cookie)
	binary.BigEndian.PutUint64(data[24:32], obj.CookieMask)
	copy(data[32:], match)
	return data, nil
}

func (obj *FlowStatsRequest) UnmarshalBinary(data []byte) error {
	if err := obj.Match.UnmarshalBinary(data[32:]); err != nil {
		return err
	}
	obj.TableId = data[0]
	obj.OutPort = binary.BigEndian.Uint32(data[4:8])
	obj.OutGroup = binary.BigEndian.Uint32(data[8:12])
	obj.Cookie = binary.BigEndian.Uint64(data[16:24])
	obj.CookieMask = binary.BigEndian.Uint64(data[24:32])
	return nil
}

type FlowStats struct {
	TableId      uint8
	DurationSec  uint32
	DurationNsec uint32
	Priority     uint16
	IdleTimeout  uint16
	HardTimeout  uint16
	Flags        uint16
	Cookie       uint64
	PacketCount  uint64
	ByteCount    uint64
	Match        Match
	Instructions []Instruction
}

func (obj FlowStats) MarshalBinary() ([]byte, error) {
	var match []byte
	if buf, err := obj.Match.MarshalBinary(); err != nil {
		return nil, err
	} else {
		match = buf
	}
	var insts []byte
	if buf, err := instructionList(obj.Instructions).MarshalBinary(); err != nil {
		return nil, err
	} else {
		insts = buf
	}
	data := make([]byte, 48+len(match)+len(insts))
	binary.BigEndian.PutUint16(data[0:2], uint16(len(data)))
	data[2] = obj.TableId
	binary.BigEndian.PutUint32(data[4:8], obj.DurationSec)
	binary.BigEndian.PutUint32(data[8:12], obj.DurationNsec)
	binary.BigEndian.PutUint16(data[12:14], obj.Priority)
	binary.BigEndian.PutUint16(data[14:16], obj.IdleTimeout)
	binary.BigEndian.PutUint16(data[16:18], obj.HardTimeout)
	binary.BigEndian.PutUint16(data[18:20], obj.Flags)
	binary.BigEndian.PutUint64(data[24:32], obj.Cookie)
	binary.BigEndian.PutUint64(data[32:40], obj.PacketCount)
	binary.BigEndian.PutUint64(data[40:48], obj.ByteCount)
	copy(data[48:], match)
	copy(data[48+len(match):], insts)
	return data, nil
}

func (obj *FlowStats) UnmarshalBinary(data []byte) error {
	length := int(binary.BigEndian.Uint32(data[0:2]))

	data[2] = obj.TableId
	obj.DurationSec = binary.BigEndian.Uint32(data[4:8])
	obj.DurationNsec = binary.BigEndian.Uint32(data[8:12])
	obj.Priority = binary.BigEndian.Uint16(data[12:14])
	obj.IdleTimeout = binary.BigEndian.Uint16(data[14:16])
	obj.HardTimeout = binary.BigEndian.Uint16(data[16:18])
	obj.Flags = binary.BigEndian.Uint16(data[18:20])
	obj.Cookie = binary.BigEndian.Uint64(data[24:32])
	obj.PacketCount = binary.BigEndian.Uint64(data[32:40])
	obj.ByteCount = binary.BigEndian.Uint64(data[40:48])

	mLength := int(binary.BigEndian.Uint16(data[50:52]))
	if err := obj.Match.UnmarshalBinary(data[48 : 48+mLength]); err != nil {
		return err
	}
	var instructions instructionList
	if err := instructions.UnmarshalBinary(data[48+mLength : length]); err != nil {
		return err
	} else {
		obj.Instructions = []Instruction(instructions)
	}
	return nil
}

type AggregateStatsRequest struct {
	TableId    uint8
	OutPort    uint32
	OutGroup   uint32
	Cookie     uint64
	CookieMask uint64
	Match      Match
}

func (obj AggregateStatsRequest) MarshalBinary() ([]byte, error) {
	match, err := obj.Match.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, 32+len(match))
	data[0] = obj.TableId
	// 3 padding
	binary.BigEndian.PutUint32(data[4:8], obj.OutPort)
	binary.BigEndian.PutUint32(data[8:12], obj.OutGroup)
	// 4 padding
	binary.BigEndian.PutUint64(data[16:24], obj.Cookie)
	binary.BigEndian.PutUint64(data[24:32], obj.CookieMask)
	copy(data[32:], match)
	return data, nil
}

func (obj *AggregateStatsRequest) UnmarshalBinary(data []byte) error {
	if err := obj.Match.UnmarshalBinary(data[40:]); err != nil {
		return err
	}
	obj.TableId = data[0]
	obj.OutPort = binary.BigEndian.Uint32(data[4:8])
	obj.OutGroup = binary.BigEndian.Uint32(data[8:12])
	obj.Cookie = binary.BigEndian.Uint64(data[16:24])
	obj.CookieMask = binary.BigEndian.Uint64(data[24:32])
	return nil
}

type AggregateStatsReply struct {
	PacketCount uint64
	ByteCount   uint64
	FlowCount   uint32
}

func (obj AggregateStatsReply) MarshalBinary() ([]byte, error) {
	data := make([]byte, 24)
	binary.BigEndian.PutUint64(data[0:8], obj.PacketCount)
	binary.BigEndian.PutUint64(data[8:16], obj.ByteCount)
	binary.BigEndian.PutUint32(data[16:20], obj.FlowCount)
	return data, nil
}

func (obj *AggregateStatsReply) UnmarshalBinary(data []byte) error {
	obj.PacketCount = binary.BigEndian.Uint64(data[0:8])
	obj.ByteCount = binary.BigEndian.Uint64(data[8:16])
	obj.FlowCount = binary.BigEndian.Uint32(data[16:20])
	return nil
}

type TableStats struct {
	TableId      uint8
	ActiveCount  uint32
	LookupCount  uint64
	MatchedCount uint64
}

func (obj TableStats) MarshalBinary() ([]byte, error) {
	data := make([]byte, 24)
	data[0] = obj.TableId
	binary.BigEndian.PutUint32(data[4:8], obj.ActiveCount)
	binary.BigEndian.PutUint64(data[8:16], obj.LookupCount)
	binary.BigEndian.PutUint64(data[16:24], obj.MatchedCount)
	return data, nil
}

func (obj *TableStats) UnmarshalBinary(data []byte) error {
	obj.TableId = data[0]
	// 3 padding
	obj.ActiveCount = binary.BigEndian.Uint32(data[4:8])
	obj.LookupCount = binary.BigEndian.Uint64(data[8:16])
	obj.MatchedCount = binary.BigEndian.Uint64(data[16:24])
	return nil
}

type PortStatsRequest struct {
	PortNo uint32
}

func (obj PortStatsRequest) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], obj.PortNo)
	// 4 padding
	return data, nil
}

func (obj *PortStatsRequest) UnmarshalBinary(data []byte) error {
	obj.PortNo = binary.BigEndian.Uint32(data[0:4])
	return nil
}

type PortStats struct {
	PortNo       uint32
	RxPackets    uint64
	TxPackets    uint64
	RxBytes      uint64
	TxBytes      uint64
	RxDropped    uint64
	TxDropped    uint64
	RxErrors     uint64
	TxErrors     uint64
	RxFrameErr   uint64
	RxOverErr    uint64
	RxCrcErr     uint64
	Collisions   uint64
	DurationSec  uint32
	DurationNsec uint32
}

func (obj PortStats) MarshalBinary() ([]byte, error) {
	data := make([]byte, 112)
	binary.BigEndian.PutUint32(data[0:4], obj.PortNo)
	binary.BigEndian.PutUint64(data[8:16], obj.RxPackets)
	binary.BigEndian.PutUint64(data[16:24], obj.TxPackets)
	binary.BigEndian.PutUint64(data[24:32], obj.RxBytes)
	binary.BigEndian.PutUint64(data[32:40], obj.TxBytes)
	binary.BigEndian.PutUint64(data[40:48], obj.RxDropped)
	binary.BigEndian.PutUint64(data[48:56], obj.TxDropped)
	binary.BigEndian.PutUint64(data[56:64], obj.RxErrors)
	binary.BigEndian.PutUint64(data[64:72], obj.TxErrors)
	binary.BigEndian.PutUint64(data[72:80], obj.RxFrameErr)
	binary.BigEndian.PutUint64(data[80:88], obj.RxOverErr)
	binary.BigEndian.PutUint64(data[88:96], obj.RxCrcErr)
	binary.BigEndian.PutUint64(data[96:104], obj.Collisions)
	binary.BigEndian.PutUint32(data[104:108], obj.DurationSec)
	binary.BigEndian.PutUint32(data[108:112], obj.DurationNsec)
	return data, nil
}

func (obj *PortStats) UnmarshalBinary(data []byte) error {
	obj.PortNo = binary.BigEndian.Uint32(data[0:4])
	obj.RxPackets = binary.BigEndian.Uint64(data[8:16])
	obj.TxPackets = binary.BigEndian.Uint64(data[16:24])
	obj.RxBytes = binary.BigEndian.Uint64(data[24:32])
	obj.TxBytes = binary.BigEndian.Uint64(data[32:40])
	obj.RxDropped = binary.BigEndian.Uint64(data[40:48])
	obj.TxDropped = binary.BigEndian.Uint64(data[48:56])
	obj.RxErrors = binary.BigEndian.Uint64(data[56:64])
	obj.TxErrors = binary.BigEndian.Uint64(data[64:72])
	obj.RxFrameErr = binary.BigEndian.Uint64(data[72:80])
	obj.RxOverErr = binary.BigEndian.Uint64(data[80:88])
	obj.RxCrcErr = binary.BigEndian.Uint64(data[88:96])
	obj.Collisions = binary.BigEndian.Uint64(data[96:104])
	obj.DurationSec = binary.BigEndian.Uint32(data[104:108])
	obj.DurationNsec = binary.BigEndian.Uint32(data[108:112])
	return nil
}

type QueueStatsRequest struct {
	PortNo  uint32
	QueueId uint32
}

func (obj QueueStatsRequest) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], obj.PortNo)
	binary.BigEndian.PutUint32(data[4:8], obj.QueueId)
	return data, nil
}

func (obj *QueueStatsRequest) UnmarshalBinary(data []byte) error {
	obj.PortNo = binary.BigEndian.Uint32(data[0:4])
	obj.QueueId = binary.BigEndian.Uint32(data[4:8])
	return nil
}

type QueueStats struct {
	PortNo       uint32
	QueueId      uint32
	TxBytes      uint64
	TxPackets    uint64
	TxErrors     uint64
	DurationSec  uint32
	DurationNsec uint32
}

func (obj QueueStats) MarshalBinary() ([]byte, error) {
	data := make([]byte, 40)
	binary.BigEndian.PutUint32(data[0:4], obj.PortNo)
	binary.BigEndian.PutUint32(data[4:8], obj.QueueId)
	binary.BigEndian.PutUint64(data[8:16], obj.TxBytes)
	binary.BigEndian.PutUint64(data[16:24], obj.TxPackets)
	binary.BigEndian.PutUint64(data[24:32], obj.TxErrors)
	binary.BigEndian.PutUint32(data[32:36], obj.DurationSec)
	binary.BigEndian.PutUint32(data[36:40], obj.DurationNsec)
	return data, nil
}

func (obj *QueueStats) UnmarshalBinary(data []byte) error {
	obj.PortNo = binary.BigEndian.Uint32(data[0:4])
	obj.QueueId = binary.BigEndian.Uint32(data[4:8])
	obj.TxBytes = binary.BigEndian.Uint64(data[8:16])
	obj.TxPackets = binary.BigEndian.Uint64(data[16:24])
	obj.TxErrors = binary.BigEndian.Uint64(data[24:32])
	obj.DurationSec = binary.BigEndian.Uint32(data[32:36])
	obj.DurationNsec = binary.BigEndian.Uint32(data[36:40])
	return nil
}

type GroupStatsRequest struct {
	GroupId uint32
}

func (obj GroupStatsRequest) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], obj.GroupId)
	return data, nil
}

func (obj *GroupStatsRequest) UnmarshalBinary(data []byte) error {
	obj.GroupId = binary.BigEndian.Uint32(data[0:4])
	return nil
}

type GroupStats struct {
	GroupId      uint32
	RefCount     uint32
	PacketCount  uint64
	ByteCount    uint64
	DurationSec  uint32
	DurationNsec uint32
	BucketStats  []encoding.BinaryMarshaler
}

func (obj GroupStats) MarshalBinary() ([]byte, error) {
	buckets, err := Array(obj.BucketStats).MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, 40+len(buckets))
	binary.BigEndian.PutUint16(data[0:2], uint16(len(data)))
	// 2 padding
	binary.BigEndian.PutUint32(data[4:8], obj.GroupId)
	binary.BigEndian.PutUint32(data[8:12], obj.RefCount)
	// 4 padding
	binary.BigEndian.PutUint64(data[16:24], obj.PacketCount)
	binary.BigEndian.PutUint64(data[24:32], obj.ByteCount)
	binary.BigEndian.PutUint32(data[32:36], obj.DurationSec)
	binary.BigEndian.PutUint32(data[36:40], obj.DurationNsec)
	copy(data[40:], buckets)
	return data, nil
}

func (obj *GroupStats) UnmarshalBinary(data []byte) error {
	length := int(binary.BigEndian.Uint16(data[0:2]))
	obj.GroupId = binary.BigEndian.Uint32(data[4:8])
	obj.RefCount = binary.BigEndian.Uint32(data[8:12])
	obj.PacketCount = binary.BigEndian.Uint64(data[16:24])
	obj.ByteCount = binary.BigEndian.Uint64(data[24:32])
	obj.DurationSec = binary.BigEndian.Uint32(data[32:36])
	obj.DurationNsec = binary.BigEndian.Uint32(data[36:40])
	obj.BucketStats = make([]encoding.BinaryMarshaler, (length-40)/16)
	for i, _ := range obj.BucketStats {
		entry := new(BucketCounter)
		if err := entry.UnmarshalBinary(data[40+16*i : 56+16*i]); err != nil {
			return err
		}
		obj.BucketStats[i] = entry
	}
	return nil
}

type BucketCounter struct {
	PacketCount uint64
	ByteCount   uint64
}

func (obj BucketCounter) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], obj.PacketCount)
	binary.BigEndian.PutUint64(data[8:16], obj.ByteCount)
	return data, nil
}

func (obj *BucketCounter) UnmarshalBinary(data []byte) error {
	obj.PacketCount = binary.BigEndian.Uint64(data[0:8])
	obj.ByteCount = binary.BigEndian.Uint64(data[8:16])
	return nil
}

type GroupDesc struct {
	Type    uint8
	GroupId uint32
	Buckets []encoding.BinaryMarshaler
}

func (obj GroupDesc) MarshalBinary() ([]byte, error) {
	buckets, err := Array(obj.Buckets).MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, 8+len(buckets))
	binary.BigEndian.PutUint16(data[0:2], uint16(len(data)))
	data[2] = obj.Type
	// 1 padding
	binary.BigEndian.PutUint32(data[4:8], obj.GroupId)
	copy(data[8:], buckets)
	return data, nil
}

func (obj *GroupDesc) UnmarshalBinary(data []byte) error {
	length := int(binary.BigEndian.Uint16(data[0:2]))
	obj.Type = data[2]
	obj.GroupId = binary.BigEndian.Uint32(data[4:8])
	var buckets []encoding.BinaryMarshaler
	for cur := 8; cur < length; {
		var bucket Bucket
		bLength := int(binary.BigEndian.Uint16(data[cur : cur+2]))
		if err := bucket.UnmarshalBinary(data[cur : cur+bLength]); err != nil {
			return err
		}
		buckets = append(buckets, bucket)
		cur += bLength
	}
	obj.Buckets = buckets
	return nil
}

type GroupFeatures struct {
	Types        uint32
	Capabilities uint32
	MaxGroups    [4]uint32
	Actions      [4]uint32
}

func (obj GroupFeatures) MarshalBinary() ([]byte, error) {
	data := make([]byte, 40)
	binary.BigEndian.PutUint32(data[0:4], obj.Types)
	binary.BigEndian.PutUint32(data[4:8], obj.Capabilities)
	for i, n := range obj.MaxGroups {
		binary.BigEndian.PutUint32(data[8+4*i:12+4*i], n)
	}
	for i, n := range obj.Actions {
		binary.BigEndian.PutUint32(data[24+4*i:28+4*i], n)
	}
	return data, nil
}

func (obj *GroupFeatures) UnmarshalBinary(data []byte) error {
	obj.Types = binary.BigEndian.Uint32(data[0:4])
	obj.Capabilities = binary.BigEndian.Uint32(data[4:8])
	for i, _ := range obj.MaxGroups {
		obj.MaxGroups[i] = binary.BigEndian.Uint32(data[8+4*i : 12+4*i])
	}
	for i, _ := range obj.Actions {
		obj.Actions[i] = binary.BigEndian.Uint32(data[24+4*i : 28+4*i])
	}
	return nil
}

type MeterMultipartRequest struct {
	MeterId uint32
}

func (obj MeterMultipartRequest) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], obj.MeterId)
	// 4 padding
	return data, nil
}

func (obj *MeterMultipartRequest) UnmarshalBinary(data []byte) error {
	obj.MeterId = binary.BigEndian.Uint32(data[0:4])
	return nil
}

type MeterStats struct {
	MeterId       uint32
	FlowCount     uint32
	PacketInCount uint64
	ByteInCount   uint64
	DurationSec   uint32
	DurationNsec  uint32
	BandStats     []encoding.BinaryMarshaler
}

func (obj MeterStats) MarshalBinary() ([]byte, error) {
	bands, err := Array(obj.BandStats).MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, 40+len(bands))
	binary.BigEndian.PutUint32(data[0:4], obj.MeterId)
	binary.BigEndian.PutUint16(data[4:6], uint16(len(data)))
	binary.BigEndian.PutUint32(data[12:16], obj.FlowCount)
	binary.BigEndian.PutUint64(data[16:24], obj.PacketInCount)
	binary.BigEndian.PutUint64(data[24:32], obj.ByteInCount)
	binary.BigEndian.PutUint32(data[32:36], obj.DurationSec)
	binary.BigEndian.PutUint32(data[36:40], obj.DurationNsec)
	copy(data[40:], bands)
	return data, nil
}

func (obj *MeterStats) UnmarshalBinary(data []byte) error {
	length := int(binary.BigEndian.Uint16(data[4:6]))
	obj.MeterId = binary.BigEndian.Uint32(data[0:4])
	obj.FlowCount = binary.BigEndian.Uint32(data[12:16])
	obj.PacketInCount = binary.BigEndian.Uint64(data[16:24])
	obj.ByteInCount = binary.BigEndian.Uint64(data[24:32])
	obj.DurationSec = binary.BigEndian.Uint32(data[32:36])
	obj.DurationNsec = binary.BigEndian.Uint32(data[36:40])
	obj.BandStats = make([]encoding.BinaryMarshaler, (length-40)/16)
	for i, _ := range obj.BandStats {
		entry := new(MeterBandStats)
		if err := entry.UnmarshalBinary(data[40+i*16 : 56*i*16]); err != nil {
			return err
		}
		obj.BandStats[i] = entry
	}
	return nil
}

type MeterBandStats struct {
	PacketBandCount uint64
	ByteBandCount   uint64
}

func (obj MeterBandStats) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[0:8], obj.PacketBandCount)
	binary.BigEndian.PutUint64(data[8:16], obj.ByteBandCount)
	return data, nil
}

func (obj *MeterBandStats) UnmarshalBinary(data []byte) error {
	obj.PacketBandCount = binary.BigEndian.Uint64(data[0:8])
	obj.ByteBandCount = binary.BigEndian.Uint64(data[8:16])
	return nil
}

type MeterConfig struct {
	Flags   uint16
	MeterId uint32
	Bands   []Band
}

func (obj MeterConfig) MarshalBinary() ([]byte, error) {
	bands, err := bandList(obj.Bands).MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, 8+len(bands))
	binary.BigEndian.PutUint16(data[0:2], uint16(len(data)))
	binary.BigEndian.PutUint16(data[2:4], obj.Flags)
	binary.BigEndian.PutUint32(data[4:8], obj.MeterId)
	copy(data[8:], bands)
	return data, nil
}

func (obj *MeterConfig) UnmarshalBinary(data []byte) error {
	length := int(binary.BigEndian.Uint16(data[0:2]))
	obj.Flags = binary.BigEndian.Uint16(data[2:4])
	obj.MeterId = binary.BigEndian.Uint32(data[4:8])

	var bands bandList
	if err := bands.UnmarshalBinary(data[8:length]); err != nil {
		return err
	} else {
		obj.Bands = []Band(bands)
	}
	return nil
}

type TableFeatures struct {
	TableId       uint8
	Name          string
	MetadataMatch uint64
	MetadataWrite uint64
	Config        uint32
	MaxEntries    uint32
	Properties    []encoding.BinaryMarshaler
}

func (obj TableFeatures) MarshalBinary() ([]byte, error) {
	props, err := tableFeaturePropertyList(obj.Properties).MarshalBinary()
	if err != nil {
		return nil, err
	}
	length := align8(64 + len(props))
	data := make([]byte, length)
	binary.BigEndian.PutUint16(data[0:2], uint16(length))
	data[2] = obj.TableId
	// 5 padding
	if len(obj.Name) < OFP_MAX_TABLE_NAME_LEN {
		copy(data[8:], []byte(obj.Name))
	} else {
		copy(data[8:], []byte(obj.Name)[:OFP_MAX_TABLE_NAME_LEN])
	}
	binary.BigEndian.PutUint64(data[40:48], obj.MetadataMatch)
	binary.BigEndian.PutUint64(data[48:56], obj.MetadataWrite)
	binary.BigEndian.PutUint32(data[56:60], obj.Config)
	binary.BigEndian.PutUint32(data[60:64], obj.MaxEntries)
	copy(data[64:], props)
	return data, nil
}

func (obj *TableFeatures) UnmarshalBinary(data []byte) error {
	length := int(binary.BigEndian.Uint16(data[0:2]))
	var properties tableFeaturePropertyList
	if err := properties.UnmarshalBinary(data[64:length]); err != nil {
		return err
	} else {
		obj.Properties = []encoding.BinaryMarshaler(properties)
	}
	data[2] = obj.TableId
	obj.Name = string(data[8 : 8+OFP_MAX_TABLE_NAME_LEN])
	obj.MetadataMatch = binary.BigEndian.Uint64(data[40:48])
	obj.MetadataWrite = binary.BigEndian.Uint64(data[48:56])
	obj.Config = binary.BigEndian.Uint32(data[56:60])
	obj.MaxEntries = binary.BigEndian.Uint32(data[60:64])
	return nil
}

type ExperimenterMultipart struct {
	Experimenter uint32
	ExpType      uint32
	Data         []byte
}

func (obj ExperimenterMultipart) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8+len(obj.Data))
	binary.BigEndian.PutUint32(data[0:4], obj.Experimenter)
	binary.BigEndian.PutUint32(data[4:8], obj.ExpType)
	copy(data[8:], obj.Data)
	return data, nil
}

func (obj *ExperimenterMultipart) UnmarshalBinary(data []byte) error {
	obj.Experimenter = binary.BigEndian.Uint32(data[0:4])
	obj.ExpType = binary.BigEndian.Uint32(data[4:8])
	obj.Data = data[8:]
	return nil
}

type Desc struct {
	MfrDesc   string
	HwDesc    string
	SwDesc    string
	SerialNum [SERIAL_NUM_LEN]byte
	DpDesc    string
}

func (obj Desc) MarshalBinary() ([]byte, error) {
	data := make([]byte, 1056)
	if len(obj.MfrDesc) < DESC_STR_LEN {
		copy(data[0:], []byte(obj.MfrDesc))
	} else {
		copy(data[0:], []byte(obj.MfrDesc)[:DESC_STR_LEN])
	}
	if len(obj.HwDesc) < DESC_STR_LEN {
		copy(data[DESC_STR_LEN:], []byte(obj.HwDesc))
	} else {
		copy(data[DESC_STR_LEN:], []byte(obj.HwDesc)[:DESC_STR_LEN])
	}
	if len(obj.SwDesc) < DESC_STR_LEN {
		copy(data[DESC_STR_LEN*2:], []byte(obj.SwDesc))
	} else {
		copy(data[DESC_STR_LEN*2:], []byte(obj.SwDesc)[:DESC_STR_LEN])
	}
	copy(data[DESC_STR_LEN*3:], obj.SerialNum[:])
	if len(obj.DpDesc) < DESC_STR_LEN {
		copy(data[DESC_STR_LEN*3+SERIAL_NUM_LEN:], []byte(obj.DpDesc))
	} else {
		copy(data[DESC_STR_LEN*3+SERIAL_NUM_LEN:], []byte(obj.DpDesc)[:DESC_STR_LEN])
	}
	return data, nil
}

func (obj *Desc) UnmarshalBinary(data []byte) error {
	obj.MfrDesc = string(data[0:DESC_STR_LEN])
	obj.HwDesc = string(data[DESC_STR_LEN : DESC_STR_LEN*2])
	obj.SwDesc = string(data[DESC_STR_LEN*2 : DESC_STR_LEN*3])
	for i,_ := range obj.SerialNum {
		obj.SerialNum[i] = data[DESC_STR_LEN*3+i]
	}
	obj.DpDesc = string(data[DESC_STR_LEN*3+SERIAL_NUM_LEN : DESC_STR_LEN*4+SERIAL_NUM_LEN])
	return nil
}

type MeterFeatures struct {
	MaxMeter     uint32
	BandTypes    uint32
	Capabilities uint32
	MaxBands     uint8
	MaxColor     uint8
}

func (obj MeterFeatures) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint32(data[0:4], obj.MaxMeter)
	binary.BigEndian.PutUint32(data[4:8], obj.BandTypes)
	binary.BigEndian.PutUint32(data[8:12], obj.Capabilities)
	data[12] = obj.MaxBands
	data[13] = obj.MaxColor
	// 2 padding
	return data, nil
}

func (obj *MeterFeatures) UnmarshalBinary(data []byte) error {
	obj.MaxMeter = binary.BigEndian.Uint32(data[0:4])
	obj.BandTypes = binary.BigEndian.Uint32(data[4:8])
	obj.Capabilities = binary.BigEndian.Uint32(data[8:12])
	obj.MaxBands = data[12]
	obj.MaxColor = data[13]
	return nil
}
