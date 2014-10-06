package ofp4sw

const (
	INST_ORDER_FIRST_TO_METER = iota
	INST_ORDER_METER_TO_APPLY
	INST_ORDER_APPLY_TO_CLEAR
	INST_ORDER_CLEAR_TO_WRITE
	INST_ORDER_WRITE_TO_META
	INST_ORDER_META_TO_GOTO
	INST_ORDER_GOTO_TO_LAST
)

/*
AddInstructionHandler registers this InstructionHandler.
*/
type InstructionHandler interface {
	Order() int
	Execute(frame Frame, instructionData []byte) (Frame, error)
}

var instructionHandlers map[experimenterKey]InstructionHandler = make(map[experimenterKey]InstructionHandler)

func AddInstructionHandler(experimenter uint32, expType uint32, handle InstructionHandler) {
	expKey := experimenterKey{
		Id:   experimenter,
		Type: expType,
	}
	actionHandlers[expKey] = handle
}

type instExperimenter struct {
	experimenterKey
	Handler InstructionHandler
	Data    []byte
}
