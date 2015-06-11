package ofp4

import (
	"encoding/binary"
	"fmt"
	"github.com/hkwi/gopenflow/oxm"
	"strconv"
	"strings"
)

const (
	PHASE_MATCH = iota
	PHASE_METER
	PHASE_APPLY
	PHASE_CLEAR
	PHASE_WRITE
	PHASE_META
	PHASE_GOTO
)

func parseLabeledValue(txt string) (label, value string, eatLen int) {
	feed := txt
	if idx := strings.IndexFunc(txt, oxm.IsSeparator); idx > 0 {
		feed = txt[:idx]
	}
	trail := []rune{}
	for _, c := range txt[len(feed):] {
		if oxm.IsSeparator(c) {
			trail = append(trail, c)
		} else {
			break
		}
	}
	kv := strings.SplitN(feed, "=", 2)
	if len(kv) > 1 {
		return kv[0], kv[1], len(feed) + len(string(trail))
	} else {
		return kv[0], "", len(feed) + len(string(trail))
	}
}

func parseInt(txt string, value interface{}) error {
	bitSize := 0
	switch value.(type) {
	case *uint8, *int8:
		bitSize = 8
	case *uint16, *int16:
		bitSize = 16
	case *uint32, *int32:
		bitSize = 32
	case *uint64, *int64:
		bitSize = 64
	default:
		return fmt.Errorf("unsupported type")
	}

	switch value.(type) {
	case *int8, *int16, *int32, *int64:
		if n, err := strconv.ParseInt(txt, 0, bitSize); err != nil {
			return err
		} else {
			switch p := value.(type) {
			case *int8:
				*p = int8(n)
			case *int16:
				*p = int16(n)
			case *int32:
				*p = int32(n)
			case *int64:
				*p = n
			}
		}
	default:
		if n, err := strconv.ParseUint(txt, 0, bitSize); err != nil {
			return err
		} else {
			switch p := value.(type) {
			case *uint8:
				*p = uint8(n)
			case *uint16:
				*p = uint16(n)
			case *uint32:
				*p = uint32(n)
			case *uint64:
				*p = n
			}
		}
	}
	return nil
}

type ActionStringer interface {
	FromAction([]byte) string
	ToAction(string) ([]byte, int, error)
}

var actionStringers = map[uint32]ActionStringer{}

func ParseAction(txt string) (buf []byte, eatLen int, err error) {
	generic := func(atype uint16) {
		buf = make([]byte, 8)
		binary.BigEndian.PutUint16(buf, atype)
	}

	label, value, eatLen := parseLabeledValue(txt)
	switch label {
	case "copy_ttl_out":
		generic(OFPAT_COPY_TTL_OUT)
	case "copy_ttl_in":
		generic(OFPAT_COPY_TTL_IN)
	case "dec_mpls_ttl":
		generic(OFPAT_DEC_MPLS_TTL)
	case "pop_vlan":
		generic(OFPAT_POP_VLAN)
	case "dec_nw_ttl":
		generic(OFPAT_DEC_NW_TTL)
	case "pop_pbb":
		generic(OFPAT_POP_PBB)
	case "output":
		vs := strings.SplitN(value, ":", 2)

		var port uint32
		switch vs[0] {
		case "max":
			port = OFPP_MAX
		case "in_port":
			port = OFPP_IN_PORT
		case "table":
			port = OFPP_TABLE
		case "normal":
			port = OFPP_NORMAL
		case "flood":
			port = OFPP_FLOOD
		case "all":
			port = OFPP_ALL
		case "controller":
			port = OFPP_CONTROLLER
		case "local":
			port = OFPP_LOCAL
		case "any":
			port = OFPP_ANY
		default:
			if err = parseInt(vs[0], &port); err != nil {
				return
			}
		}

		maxLen := uint16(OFPCML_NO_BUFFER)
		if len(vs) > 1 {
			if err = parseInt(vs[1], &maxLen); err != nil {
				return
			}
		}
		buf = make([]byte, 16)
		binary.BigEndian.PutUint16(buf, OFPAT_OUTPUT)
		binary.BigEndian.PutUint32(buf[4:], port)
		binary.BigEndian.PutUint16(buf[8:], maxLen)
	case "set_mpls_ttl", "set_nw_ttl":
		var v uint8
		if err = parseInt(value, &v); err != nil {
			return
		}
		switch label {
		case "set_mpls_ttl":
			generic(OFPAT_SET_MPLS_TTL)
		case "set_nw_ttl":
			generic(OFPAT_SET_NW_TTL)
		}
		buf[4] = v
	case "push_vlan", "push_mpls", "pop_mpls", "push_pbb":
		var v uint16
		if err = parseInt(value, &v); err != nil {
			return
		}
		switch label {
		case "push_vlan":
			generic(OFPAT_PUSH_VLAN)
		case "push_mpls":
			generic(OFPAT_PUSH_MPLS)
		case "pop_mpls":
			generic(OFPAT_POP_MPLS)
		case "push_pbb":
			generic(OFPAT_PUSH_PBB)
		}
		binary.BigEndian.PutUint16(buf[4:], v)
	case "group", "set_queue":
		var v uint32
		if err = parseInt(value, &v); err != nil {
			return
		}
		switch label {
		case "group":
			generic(OFPAT_GROUP)
		case "set_queue":
			generic(OFPAT_SET_QUEUE)
		}
		binary.BigEndian.PutUint32(buf[4:], v)
	default:
		// set-field
		if strings.HasPrefix(label, "set_") {
			setLen := len("set_")
			if p, n, e := oxm.ParseOne(txt[setLen:]); e != nil {
				err = e
			} else {
				buf = make([]byte, align8(4+len(p)))
				binary.BigEndian.PutUint16(buf, OFPAT_SET_FIELD)
				copy(buf[4:], p)
				eatLen = setLen + n
			}
		} else {
			for _, handler := range actionStringers {
				if buf, eatLen, err = handler.ToAction(txt); err == nil {
					return
				}
			}
		}
	}
	if len(buf) == 0 {
		err = fmt.Errorf("unparsed")
	} else {
		binary.BigEndian.PutUint16(buf[2:], uint16(len(buf)))
	}
	return
}

func (self ActionHeader) String() string {
	seq := []byte(self)
	switch binary.BigEndian.Uint16(seq) {
	case OFPAT_OUTPUT:
		makePort := func(ports string) string {
			maxLen := binary.BigEndian.Uint16(seq[8:])
			if maxLen == OFPCML_NO_BUFFER {
				return fmt.Sprintf("output=%s",
					ports)
			} else {
				return fmt.Sprintf("output=%s:0x%x",
					ports,
					maxLen)
			}
		}
		port := binary.BigEndian.Uint32(seq[4:])
		switch port {
		case OFPP_MAX:
			return makePort("max")
		case OFPP_IN_PORT:
			return makePort("in_port")
		case OFPP_TABLE:
			return makePort("table")
		case OFPP_NORMAL:
			return makePort("normal")
		case OFPP_FLOOD:
			return makePort("flood")
		case OFPP_ALL:
			return makePort("all")
		case OFPP_CONTROLLER:
			return makePort("controller")
		case OFPP_LOCAL:
			return makePort("local")
		case OFPP_ANY:
			return makePort("any")
		default:
			return makePort(fmt.Sprintf("%d", port))
		}
	case OFPAT_COPY_TTL_OUT:
		return "copy_ttl_out"
	case OFPAT_COPY_TTL_IN:
		return "copy_ttl_in"
	case OFPAT_SET_MPLS_TTL:
		return fmt.Sprintf("set_mpls_ttl=%d", seq[4])
	case OFPAT_DEC_MPLS_TTL:
		return "dec_mpls_ttl"
	case OFPAT_PUSH_VLAN:
		return fmt.Sprintf("push_vlan=0x%04x",
			binary.BigEndian.Uint16(seq[4:]))
	case OFPAT_POP_VLAN:
		return "pop_vlan"
	case OFPAT_PUSH_MPLS:
		return fmt.Sprintf("push_mpls=0x%04x",
			binary.BigEndian.Uint16(seq[4:]))
	case OFPAT_POP_MPLS:
		return fmt.Sprintf("pop_mpls=0x%04x",
			binary.BigEndian.Uint16(seq[4:]))
	case OFPAT_SET_QUEUE:
		return fmt.Sprintf("set_queue=%d",
			binary.BigEndian.Uint32(seq[4:]))
	case OFPAT_GROUP:
		return fmt.Sprintf("group=%d",
			binary.BigEndian.Uint32(seq[4:]))
	case OFPAT_SET_NW_TTL:
		return fmt.Sprintf("set_nw_ttl=%d", seq[4])
	case OFPAT_DEC_NW_TTL:
		return "dec_nw_ttl"
	case OFPAT_SET_FIELD:
		return fmt.Sprintf("set_%v",
			oxm.Oxm(seq[4:]))
	case OFPAT_PUSH_PBB:
		return fmt.Sprintf("push_pbb=0x%04x",
			binary.BigEndian.Uint16(seq[4:]))
	case OFPAT_POP_PBB:
		return "pop_pbb"
	case OFPAT_EXPERIMENTER:
		if handler, ok := actionStringers[binary.BigEndian.Uint32(seq[4:])]; ok {
			return handler.FromAction(seq)
		}
	}
	return "?"
}

type InstructionStringer interface {
	FromInstruction([]byte) string
	ToInstruction(string) ([]byte, int, error)
}

var instructionStringers = map[uint32]InstructionStringer{}

func (self Instruction) String() string {
	var ret []string
	for _, inst := range self.Iter() {
		switch inst.Type() {
		case OFPIT_GOTO_TABLE:
			ret = append(ret, fmt.Sprintf("@goto=%d",
				InstructionGotoTable(inst).TableId()))
		case OFPIT_WRITE_METADATA:
			m := InstructionWriteMetadata(inst)
			if mask := m.MetadataMask(); mask != 0 {
				ret = append(ret, fmt.Sprintf("@metadata=0x%x/0x%x",
					m.Metadata(), mask))
			} else {
				ret = append(ret, fmt.Sprintf("@metadata=0x%x",
					m.Metadata()))
			}
		case OFPIT_WRITE_ACTIONS:
			ret = append(ret, "@write")
			for _, a := range InstructionActions(inst).Actions().Iter() {
				ret = append(ret, fmt.Sprintf("%v", a))
			}
		case OFPIT_APPLY_ACTIONS:
			ret = append(ret, "@apply")
			for _, a := range InstructionActions(inst).Actions().Iter() {
				ret = append(ret, fmt.Sprintf("%v", a))
			}
		case OFPIT_CLEAR_ACTIONS:
			ret = append(ret, "@clear")
		case OFPIT_METER:
			ret = append(ret, fmt.Sprintf("@meter=%d",
				InstructionMeter(inst).MeterId()))
		case OFPIT_EXPERIMENTER:
			if handler, ok := instructionStringers[binary.BigEndian.Uint32(inst[4:])]; ok {
				ret = append(ret, handler.FromInstruction(inst))
			} else {
				ret = append(ret, "?")
			}
		}
	}
	return strings.Join(ret, ",")
}

type flowRule struct {
	TableId      uint8
	IdleTimeout  uint16
	HardTimeout  uint16
	Priority     uint16
	BufferId     uint32
	OutPort      uint32
	OutGroup     uint32
	Cookie       uint64
	CookieMask   uint64
	Match        []byte // oxm
	Instructions []byte
}

func (self *flowRule) Parse(txt string) error {
	var actions []byte
	var delayed func() = nil
	phase := PHASE_MATCH
	for len(txt) > 0 {
		// in case value would include separator, don't use these value and just recalculate
		label, value, step := parseLabeledValue(txt)
		if label[0] == '@' && delayed != nil {
			delayed()
			delayed = nil
		}
		switch label {
		case "@meter":
			phase = PHASE_METER
			var meterId uint32
			if err := parseInt(value, &meterId); err != nil {
				return err
			}
			var inst [8]byte
			binary.BigEndian.PutUint16(inst[:], OFPIT_METER)
			binary.BigEndian.PutUint16(inst[2:], 8)
			binary.BigEndian.PutUint32(inst[4:], meterId)
			self.Instructions = append(self.Instructions, inst[:]...)
		case "@apply", "@apply_actions":
			phase = PHASE_APPLY
			delayed = func() {
				var inst [8]byte
				binary.BigEndian.PutUint16(inst[:], OFPIT_APPLY_ACTIONS)
				binary.BigEndian.PutUint16(inst[2:], uint16(len(actions)+8))
				self.Instructions = append(self.Instructions, inst[:]...)
				self.Instructions = append(self.Instructions, actions...)
				actions = actions[:0]
			}
		case "@clear", "@clear_actions":
			phase = PHASE_CLEAR
			var inst [8]byte
			binary.BigEndian.PutUint16(inst[:], OFPIT_CLEAR_ACTIONS)
			binary.BigEndian.PutUint16(inst[2:], 8)
			self.Instructions = append(self.Instructions, inst[:]...)
		case "@write", "@write_actions":
			phase = PHASE_WRITE
			delayed = func() {
				var inst [8]byte
				binary.BigEndian.PutUint16(inst[:], OFPIT_WRITE_ACTIONS)
				binary.BigEndian.PutUint16(inst[2:], uint16(len(actions)+8))
				self.Instructions = append(self.Instructions, inst[:]...)
				self.Instructions = append(self.Instructions, actions...)
				actions = actions[:0]
			}
		case "@metadata", "@write_metadata":
			phase = PHASE_META

			var v, m uint64
			vm := strings.SplitN(value, "/", 2)
			if err := parseInt(vm[0], &v); err != nil {
				return err
			}
			if len(vm) == 2 {
				if err := parseInt(vm[1], &m); err != nil {
					return err
				}
			} else {
				m = 0xFFFFFFFFFFFFFFFF
			}

			var inst [24]byte
			binary.BigEndian.PutUint16(inst[0:], OFPIT_WRITE_METADATA)
			binary.BigEndian.PutUint16(inst[2:], 24)
			binary.BigEndian.PutUint64(inst[8:], v)
			binary.BigEndian.PutUint64(inst[16:], m)
			self.Instructions = append(self.Instructions, inst[:]...)
		case "@goto", "@goto_table":
			phase = PHASE_GOTO
			var tableId uint8
			if err := parseInt(value, &tableId); err != nil {
				return err
			}
			var inst [8]byte
			binary.BigEndian.PutUint16(inst[:], OFPIT_GOTO_TABLE)
			binary.BigEndian.PutUint16(inst[2:], uint16(len(inst)))
			inst[4] = tableId
			self.Instructions = append(self.Instructions, inst[:]...)
		default:
			switch phase {
			case PHASE_MATCH:
				switch label {
				case "table":
					var v uint8
					if err := parseInt(value, &v); err != nil {
						return err
					}
					self.TableId = v
				case "priority", "idle_timeout", "hard_timeout":
					var v uint16
					if err := parseInt(value, &v); err != nil {
						return err
					}
					switch label {
					case "idle_timeout":
						self.IdleTimeout = v
					case "hard_timeout":
						self.HardTimeout = v
					case "priority":
						self.Priority = v
					}
				case "cookie":
					var v, m uint64
					vm := strings.SplitN(value, "/", 2)
					if err := parseInt(vm[0], &v); err != nil {
						return err
					}
					if len(vm) == 2 {
						if err := parseInt(vm[1], &m); err != nil {
							return err
						}
					}
					self.Cookie = v
					self.CookieMask = m
				case "out_port":
					var v uint32
					if err := parseInt(value, &v); err != nil {
						return err
					}
					self.OutPort = v
				case "out_group", "group":
					var v uint32
					if err := parseInt(value, &v); err != nil {
						return err
					}
					self.OutGroup = v
				default:
					if buf, n, err := oxm.ParseOne(txt); err != nil {
						return err
					} else {
						self.Match = append(self.Match, buf...)
						step = n
					}
				}
			case PHASE_APPLY, PHASE_WRITE:
				if buf, n, err := ParseAction(txt); err != nil {
					break
				} else {
					actions = append(actions, buf...)
					step = n
				}
			}
		}
		for i, c := range txt[step:] {
			if !oxm.IsSeparator(c) {
				step += i
				break
			}
		}
		txt = txt[step:]
	}
	if delayed != nil {
		delayed()
	}
	return nil
}

func (self *FlowMod) Parse(txt string) error {
	var f flowRule
	if cmd := self.Command(); cmd == OFPFC_DELETE || cmd == OFPFC_DELETE_STRICT {
		f.TableId = OFPTT_ALL
		f.OutPort = OFPP_ANY
		f.OutGroup = OFPG_ANY
	} else {
		f.BufferId = OFP_NO_BUFFER
	}
	if err := f.Parse(txt); err != nil {
		return err
	}
	buf := []byte(*self)[:48]
	binary.BigEndian.PutUint64(buf[8:], f.Cookie)
	binary.BigEndian.PutUint64(buf[16:], f.CookieMask)
	buf[24] = f.TableId
	binary.BigEndian.PutUint16(buf[26:], f.IdleTimeout)
	binary.BigEndian.PutUint16(buf[28:], f.HardTimeout)
	binary.BigEndian.PutUint16(buf[30:], f.Priority)
	binary.BigEndian.PutUint32(buf[32:], f.BufferId)
	binary.BigEndian.PutUint32(buf[36:], f.OutPort)
	binary.BigEndian.PutUint32(buf[40:], f.OutGroup)

	mLength := len(f.Match) + 4
	match := make([]byte, align8(mLength))
	binary.BigEndian.PutUint16(match[:], OFPMT_OXM)
	binary.BigEndian.PutUint16(match[2:], uint16(mLength))
	copy(match[4:], f.Match)

	buf = append(buf, match...)
	buf = append(buf, f.Instructions...)

	buf[0] = 4
	buf[1] = OFPT_FLOW_MOD
	binary.BigEndian.PutUint16(buf[2:], uint16(len(buf)))
	*self = buf
	return nil
}

func (self FlowMod) String() string {
	cmd := self.Command()
	comps := []string{
		fmt.Sprintf("table=%d,priority=%d", self.TableId(), self.Priority()),
	}
	if cmd == OFPFC_ADD {
		comps = append(comps, fmt.Sprintf("cookie=0x%x", self.Cookie()))
	} else if self.CookieMask() != 0 {
		comps = append(comps, fmt.Sprintf("cookie=0x%x/0x%x", self.Cookie(), self.CookieMask()))
	}
	if fields := self.Match().OxmFields(); len(fields) > 0 {
		comps = append(comps, fmt.Sprintf("%v", oxm.Oxm(fields)))
	}
	if cmd != OFPFC_DELETE && cmd != OFPFC_DELETE_STRICT {
		if n := self.BufferId(); n != OFP_NO_BUFFER {
			comps = append(comps, fmt.Sprintf("buffer=%d", n))
		}
	}
	if n := self.IdleTimeout(); n != 0 {
		comps = append(comps, fmt.Sprintf("idle_timeout=%d", n))
	}
	if n := self.IdleTimeout(); n != 0 {
		comps = append(comps, fmt.Sprintf("hard_timeout=%d", n))
	}
	if cmd == OFPFC_DELETE || cmd == OFPFC_DELETE_STRICT {
		if v := self.OutPort(); v != OFPP_ANY {
			comps = append(comps, fmt.Sprintf("out_port=%d", v))
		}
		if v := self.OutGroup(); v != OFPG_ANY {
			comps = append(comps, fmt.Sprintf("group=%d", v))
		}
	}
	if insts := self.Instructions(); len(insts) > 0 {
		comps = append(comps, fmt.Sprintf("%v", insts))
	}
	return strings.Join(comps, ",")
}

func (self *FlowStats) Parse(txt string) error {
	var f flowRule
	if err := f.Parse(txt); err != nil {
		return err
	}
	buf := []byte(*self)[:48]
	buf[2] = f.TableId
	binary.BigEndian.PutUint16(buf[12:], f.Priority)
	binary.BigEndian.PutUint16(buf[14:], f.IdleTimeout)
	binary.BigEndian.PutUint16(buf[16:], f.HardTimeout)
	binary.BigEndian.PutUint64(buf[24:], f.Cookie)

	mLength := len(f.Match) + 4
	match := make([]byte, align8(mLength))
	binary.BigEndian.PutUint16(match[:], OFPMT_OXM)
	binary.BigEndian.PutUint16(match[2:], uint16(mLength))
	copy(match[4:], f.Match)

	buf = append(buf, match...)
	buf = append(buf, f.Instructions...)

	binary.BigEndian.PutUint16(buf, uint16(len(buf)))

	*self = buf
	return nil
}

func (self FlowStats) String() string {
	comps := []string{
		fmt.Sprintf("table=%d,priority=%d", self.TableId(), self.Priority()),
	}
	if n := self.IdleTimeout(); n != 0 {
		comps = append(comps, fmt.Sprintf("idle_timeout=%d", n))
	}
	if n := self.HardTimeout(); n != 0 {
		comps = append(comps, fmt.Sprintf("hard_timeout=%d", n))
	}
	comps = append(comps, fmt.Sprintf("cookie=0x%x", self.Cookie()))
	if fields := self.Match().OxmFields(); len(fields) > 0 {
		comps = append(comps, fmt.Sprintf("%v", oxm.Oxm(fields)))
	}
	if insts := self.Instructions(); len(insts) > 0 {
		for _, inst := range insts {
			comps = append(comps, fmt.Sprintf("%v", inst))
		}
	}
	return strings.Join(comps, ",")
}
