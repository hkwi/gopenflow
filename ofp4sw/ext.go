package ofp4sw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/hkwi/gopenflow/oxm"
	bytes2 "github.com/hkwi/suppl/bytes"
)

/*
AddInstructionHandler registers this InstructionHandler.
*/
type InstructionHandler interface {
	Order(payload []byte) int
	Execute(frame *Frame, instructionData []byte) error
}

/*
AddActionHandler registers this ActionHandler.
*/
type ActionHandler interface {
	Order([]byte) int
	Execute(frame *Frame, actionData []byte) error
}

// common oxm representation for extension API

// OxmKey is experimenter oxm key.
// This is not oxm-id which will found in ofp_table_feature_prop_oxm.
// OxmKey is intended to reduce transformation between oxm byte sequences,
// and extension may set any type of oxmkey not limited to uint64,
// as far as it satisfies the interface.
type OxmKey interface {
	Bytes(OxmPayload) []byte
	IsEmpty(OxmPayload) bool // Some field use special value for meaning as if the field was not present.
}

type OxmPayload interface{}

// oxm types for OFPXMC_OPENFLOW_BASIC.
// payload will be OxmValueMask, because its match operation
// bases on mask and compare operation.
type OxmKeyBasic uint32

type OxmValueMask struct {
	Value []byte
	Mask  []byte // 0 means don't care
}

var _ = OxmKey(OxmKeyBasic(0)) // check for implementation

func (self OxmKeyBasic) Bytes(payload OxmPayload) []byte {
	vm := payload.(OxmValueMask)
	buf := make([]byte, 4+len(vm.Value)+len(vm.Mask))

	hdr := oxm.Header(self)
	if len(vm.Mask) > 0 {
		hdr.SetMask(true)
	}
	hdr.SetLength(len(buf) - 4)
	binary.BigEndian.PutUint32(buf, uint32(hdr))

	copy(buf[4:], vm.Value)
	copy(buf[4+len(vm.Value):], vm.Mask)
	return buf
}

func (self OxmKeyBasic) IsEmpty(payload OxmPayload) bool {
	return false
}

func (self OxmValueMask) Equal(vm OxmValueMask) bool {
	return bytes.Equal(self.Value, vm.Value) && bytes.Equal(self.Mask, vm.Mask)
}

func (self *OxmValueMask) Merge(vm OxmValueMask) error {
	mask := bytes2.And(self.Mask, vm.Mask)
	if bytes.Equal(bytes2.And(self.Value, mask), bytes2.And(vm.Value, mask)) {
		value := func(o OxmValueMask) []byte {
			if len(o.Mask) > 0 {
				return bytes2.And(o.Value, o.Mask)
			} else {
				return o.Value
			}
		}
		self.Value = bytes2.Or(value(*self), value(vm))
		self.Mask = bytes2.Or(self.Mask, vm.Mask)
		return nil
	} else {
		return fmt.Errorf("conflict")
	}
}

// oxm types for OFPXMC_EXPERIMENTER

type OxmKeyExp struct {
	Experimenter uint32
	Field        uint8
	Type         uint16
}

var _ = OxmKey(OxmKeyExp{}) // check for implementation

func (self OxmKeyExp) Bytes(payload OxmPayload) []byte {
	hdr := oxm.Header(oxm.OFPXMC_EXPERIMENTER<<oxm.OXM_CLASS_SHIFT | uint32(self.Field)<<oxm.OXM_FIELD_SHIFT)
	var buf []byte
	setCommon := func(payloadLength int) {
		buf = make([]byte, 4+payloadLength)
		hdr.SetLength(payloadLength)
		binary.BigEndian.PutUint32(buf, uint32(hdr))
		binary.BigEndian.PutUint32(buf[4:], self.Experimenter)
		binary.BigEndian.PutUint16(buf[8:], self.Type)
	}
	switch p := payload.(type) {
	case OxmValueMask:
		if len(p.Mask) > 0 {
			hdr.SetMask(true)
		}
		setCommon(6 + len(p.Value) + len(p.Mask))
		copy(buf[10:], p.Value)
		copy(buf[10+len(p.Value):], p.Mask)
	case []byte:
		setCommon(6 + len(p))
		copy(buf[10:], p)
	case nil:
		setCommon(6)
	}
	return buf
}

func (self OxmKeyExp) IsEmpty(payload OxmPayload) bool {
	return false
}

// oxm helpers

type oxmKeyList []OxmKey

func (self oxmKeyList) Have(key OxmKey) bool {
	for _, k := range []OxmKey(self) {
		if k == key {
			return true
		}
	}
	return false
}

/*
AddOxmHandler registers this OxmHandler.
*/
type OxmHandler interface {
	// parses oxm bulk bytes, which may contain multiple oxm sequences
	Parse([]byte) map[OxmKey]OxmPayload
	// fixup for oxm-id
	OxmId(uint32) uint32

	// return true if target frame matches
	Match(Frame, OxmKey, OxmPayload) (bool, error)
	SetField(*Frame, OxmKey, OxmPayload) error

	// Fits returns true if narrow oxm could be matched by wide oxm.
	Fit(key OxmKey, narrow, wide OxmPayload) (bool, error)
	// Conflict will be used to check OFPFMFC_OVERLAP
	Conflict(key OxmKey, a, b OxmPayload) (bool, error)

	// used to fill up prerequisite oxm matches
	Expand(map[OxmKey]OxmPayload) error
}

type TableHandler interface {
	// XXX: TBD
}

var tableHandlers map[experimenterKey]TableHandler = make(map[experimenterKey]TableHandler)

func AddTableHandler(experimenter uint32, expType uint32, handler TableHandler) {
	key := experimenterKey{
		Experimenter: experimenter,
		ExpType:      expType,
	}
	tableHandlers[key] = handler
}

// MessageHandler will be registered via AddMessageHandler.
type MessageHandler interface {
	Execute(request []byte) (response [][]byte)
}
