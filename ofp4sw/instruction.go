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

var instructionHandlers map[uint32]InstructionHandler = make(map[uint32]InstructionHandler)

func AddInstructionHandler(experimenter uint32, handle InstructionHandler) {
	actionHandlers[experimenter] = handle
}

type instExperimenter struct {
	Experimenter uint32
	Data         []byte
	Handler      InstructionHandler
}
