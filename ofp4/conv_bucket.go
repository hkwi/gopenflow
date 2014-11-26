package ofp4

import (
	"encoding/binary"
)

type Bucket []byte

/*
 * Length of the bucket in bytes, including header.
 */
func (self Bucket) Len() int {
	return int(binary.BigEndian.Uint16(self))
}

func (self Bucket) Weight() uint16 {
	return binary.BigEndian.Uint16(self[2:])
}

func (self Bucket) WatchPort() uint32 {
	return binary.BigEndian.Uint32(self[4:])
}

func (self Bucket) WatchGroup() uint32 {
	return binary.BigEndian.Uint32(self[8:])
}

func (self Bucket) Actions() ActionHeader {
	return ActionHeader(self[16:self.Len()])
}

func (self Bucket) Iter() []Bucket {
	var seq []Bucket
	for cur := 0; cur < len(self); {
		b := Bucket(self[cur:])
		seq = append(seq, b[:b.Len()])
		cur += b.Len()
	}
	return seq
}

func MakeBucket(weight uint16, watchPort, watchGroup uint32, actions ActionHeader) Bucket {
	length := 16 + len(actions)
	self := make([]byte, length)
	binary.BigEndian.PutUint16(self, uint16(length))
	binary.BigEndian.PutUint16(self[2:], weight)
	binary.BigEndian.PutUint32(self[4:], watchPort)
	binary.BigEndian.PutUint32(self[8:], watchGroup)
	copy(self[16:], actions)
	return self
}

type BucketCounter []byte

func (self BucketCounter) PacketCount() uint64 {
	return binary.BigEndian.Uint64(self)
}

func (self BucketCounter) ByteCount() uint64 {
	return binary.BigEndian.Uint64(self[8:])
}
