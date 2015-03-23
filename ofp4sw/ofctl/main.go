package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
	"fmt"
	"net"
	"io"
)

var hello = string([]byte{ 4, ofp4.OFPT_HELLO, 0, 8, 255,0,0,1 })
var barrier = string([]byte{ 4, ofp4.OFPT_BARRIER_REQUEST, 0, 8, 255,0,0,2 })

func main() {
	flag.Parse()
	args := flag.Args()

	getConn := func() io.ReadWriter {
		p := strings.SplitN(args[0], ":", 2)
		if c, err := net.Dial(p[0], p[1]); err != nil {
			panic(err)
		} else if n,err:=c.Write([]byte(hello)); n!=8 || err!=nil {
			panic("hello send error")
		} else if res:=readMsg(c); res.Type()!=ofp4.OFPT_HELLO {
			panic("hello recv error")
		} else {
			return c
		}
	}
	
	switch args[1] {
	case "dump-flows":
		con := getConn()
		
		flowStatsReq := make([]byte, 32)
		flowStatsReq[0] = ofp4.OFPTT_ALL
		binary.BigEndian.PutUint32(flowStatsReq[4:], ofp4.OFPP_ANY)
		binary.BigEndian.PutUint32(flowStatsReq[8:], ofp4.OFPG_ANY)
		
		mphdr := make([]byte, 16)
		mphdr[0] = 4
		mphdr[1] = ofp4.OFPT_MULTIPART_REQUEST
		binary.BigEndian.PutUint16(mphdr[8:], ofp4.OFPMP_FLOW)
		
		msg := append(mphdr, append(flowStatsReq, ofp4.MakeMatch(nil)...)...)
		binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)))
		con.Write(msg)
		
		for {
			mp := readMsg(con)
			if mp.Type() != ofp4.OFPT_MULTIPART_REPLY {
				panic("mp error")
			}
			seq := ofp4.FlowStats(ofp4.MultipartReply(mp).Body())
			for len(seq) >= 56 {
				base := fmt.Sprintf("table=%d,priority=%d,idle_timeout=%d,hard_timeout=%d,cookie=%d",
					seq.TableId(),
					seq.Priority(),
					seq.IdleTimeout(),
					seq.HardTimeout(),
					seq.Cookie(),
					)
				for _,oxm := range seq.Match().OxmFields().Iter() {
					var ext string
					p := oxm.Body()
					switch oxm.Header().Type() {
					case ofp4.OXM_OF_IN_PORT:
						ext = fmt.Sprintf("in_port=%d",
							binary.BigEndian.Uint32(p))
					case ofp4.OXM_OF_IN_PHY_PORT:
						ext = fmt.Sprintf("in_phy_port=%d",
							binary.BigEndian.Uint32(p))
					case ofp4.OXM_OF_METADATA:
						if oxm.Header().HasMask() {
							ext = fmt.Sprintf("metadata=%d/%d",
								binary.BigEndian.Uint64(p),
								binary.BigEndian.Uint64(p[8:]))
						} else {
							ext = fmt.Sprintf("metadata=%d",
								binary.BigEndian.Uint64(p))
						}
					case ofp4.OXM_OF_ETH_DST:
						if oxm.Header().HasMask() {
							ext = fmt.Sprintf("eth_dst=%d.%d.%d.%d/%d.%d.%d.%d",
								p[0], p[1], p[2], p[3], 
								p[4], p[5], p[6], p[7])
						} else {
							ext = fmt.Sprintf("eth_dst=%d.%d.%d.%d",
								p[0], p[1], p[2], p[3])
						}
					case ofp4.OXM_OF_ETH_SRC:
						if oxm.Header().HasMask() {
							ext = fmt.Sprintf("eth_src=%x:%x:%x:%x:%x:%x/%x:%x:%x:%x:%x:%x",
								p[0], p[1], p[2], p[3], p[4], p[5], 
								p[6], p[7], p[8], p[9], p[10], p[11])
						} else {
							ext = fmt.Sprintf("eth_src=%x:%x:%x:%x:%x:%x",
								p[0], p[1], p[2], p[3], p[4], p[5])
						}
					case ofp4.OXM_OF_ETH_TYPE:
						ext = fmt.Sprintf("eth_type=%x",
							binary.BigEndian.Uint16(p))
					case ofp4.OXM_OF_VLAN_VID:
						if oxm.Header().HasMask() {
							ext = fmt.Sprintf("vlan_vid=%x/%x",
								binary.BigEndian.Uint16(p),
								binary.BigEndian.Uint16(p[2:]))
						} else {
							ext = fmt.Sprintf("vlan_vid=%x",
								binary.BigEndian.Uint16(p))
						}
					case ofp4.OXM_OF_VLAN_PCP:
						ext = fmt.Sprintf("vlan_pcp=%x",
							p[0])
					case ofp4.OXM_OF_IP_DSCP:
						ext = fmt.Sprintf("ip_dscp=%x",
							p[0])
					case ofp4.OXM_OF_IP_ECN:
						ext = fmt.Sprintf("ip_ecn=%x",
							p[0])
					case ofp4.OXM_OF_IP_PROTO:
						ext = fmt.Sprintf("ip_proto=%x",
							p[0])
					case ofp4.OXM_OF_IPV4_SRC:
						if oxm.Header().HasMask() {
							ext = fmt.Sprintf("eth_src=%d.%d.%d.%d/%d.%d.%d.%d",
								p[0], p[1], p[2], p[3],
								p[4], p[5], p[6], p[7])
						} else {
							ext = fmt.Sprintf("eth_src=%d.%d.%d.%d",
								p[0], p[1], p[2], p[3])
						}
					case ofp4.OXM_OF_TCP_SRC:
						ext = fmt.Sprintf("tcp_src=%d",
							binary.BigEndian.Uint16(p))
					case ofp4.OXM_OF_TCP_DST:
						ext = fmt.Sprintf("tcp_dst=%d",
							binary.BigEndian.Uint16(p))
					case ofp4.OXM_OF_UDP_SRC:
						ext = fmt.Sprintf("udp_src=%d",
							binary.BigEndian.Uint16(p))
					case ofp4.OXM_OF_UDP_DST:
						ext = fmt.Sprintf("udp_dst=%d",
							binary.BigEndian.Uint16(p))
					case ofp4.OXM_OF_SCTP_SRC:
						ext = fmt.Sprintf("sctp_src=%d",
							binary.BigEndian.Uint16(p))
					case ofp4.OXM_OF_SCTP_DST:
						ext = fmt.Sprintf("sctp_dst=%d",
							binary.BigEndian.Uint16(p))
					default:
						switch oxm.Header().Class() {
						case ofp4.OFPXMC_EXPERIMENTER:
							exp := ofp4.OxmExperimenterHeader(oxm)
							switch exp.Experimenter() {
							case STRATOS_EXPERIMENTER_ID:
								switch oxm.Header().Field() {
								case STRATOS_OXM_FIELD_BASIC:
									switch binary.BigEndian.Uint16(oxm[8:]){
									case STROXM_BASIC_DOT11:
										ext = fmt.Sprintf("dot11=%d", oxm[10])
									case STROXM_BASIC_DOT11_ADDR1:
										if oxm.Header().HasMask() {
											h := len(oxm[10:])/2
											ext = fmt.Sprintf("addr1=%s/%s",
												mac2str(oxm[10:10+h]),
												mac2str(oxm[10+h:]))
										} else {
											ext = fmt.Sprintf("addr1=%s",
												mac2str(oxm[10:]))
										}
									}
								}
							}
						}
					}
					if len(ext) > 0 {
						base += "," + ext
					}
				}
				for _,ins := range seq.Instructions() {
					switch ins.Type() {
					case ofp4.OFPIT_GOTO_TABLE:
						base += fmt.Sprintf(",@goto=%d",
							ofp4.InstructionGotoTable(ins).TableId())
					case ofp4.OFPIT_WRITE_METADATA:
						ins := ofp4.InstructionWriteMetadata(ins)
						base += fmt.Sprintf(",@metadata=0x%016x/0x%016x",
							ins.Metadata(), ins.MetadataMask())
					case ofp4.OFPIT_WRITE_ACTIONS:
						base += fmt.Sprintf(",@write")
						if ext,err := actionB2W(ofp4.InstructionActions(ins).Actions()); err!= nil {
							panic(err)
						}else if len(ext) > 0 {
							base += "," + ext
						}
					case ofp4.OFPIT_APPLY_ACTIONS:
						base += fmt.Sprintf(",@apply")
						if ext,err := actionB2W(ofp4.InstructionActions(ins).Actions()); err!=nil {
							panic(err)
						} else if len(ext) > 0 {
							base += "," + ext
						}
					case ofp4.OFPIT_CLEAR_ACTIONS:
						base += fmt.Sprintf(",@clear")
					case ofp4.OFPIT_METER:
						base += fmt.Sprintf(",@meter")
					}
				}
				
				log.Print(base)
				seq = seq[seq.Length():]
			}
			
			if binary.BigEndian.Uint16(mphdr[10:]) & ofp4.OFPMPF_REPLY_MORE == 0 {
				break
			}
		}
	case "add-flow":
		if msg, err := flow_mod(args[2], ofp4.OFPFC_ADD); err != nil {
			panic(err)
		} else {
			con := getConn()
			
			con.Write(msg)
			
			con.Write([]byte(barrier))
			if readMsg(con).Type() == ofp4.OFPT_ERROR {
				log.Print("error")
			}
		}
	case "del-flows":
		var filter string
		if len(args) > 2 {
			filter = args[2]
		}
		if msg, err := flow_mod(filter, ofp4.OFPFC_DELETE); err != nil {
			panic(err)
		} else {
			con := getConn()
			
			con.Write(msg)
			
			con.Write([]byte(barrier))
			
			readMsg(con)
		}
	}
}

func readMsg(con io.Reader) ofp4.Header {
	buf := make([]byte, 8)
	if n,err:=con.Read(buf); err!=nil || n!=8 {
		panic("ofp header read error")
	}
	hdr := ofp4.Header(buf)
	if hdr.Version() != 4 {
		panic("ofp4 version error")
	}
	length := hdr.Length()
	if length != 8 {
		ext := make([]byte, length)
		copy(ext, buf)
		con.Read(ext[8:])
		buf = ext
	}
	return ofp4.Header(buf)
}

type ValueMask struct {
	Value []byte
	Mask  []byte
}

func intBytes(v interface{}) []byte {
	switch n := v.(type) {
	case uint8:
		return []byte{n}
	case uint16:
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, n)
		return buf
	case uint32:
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, n)
		return buf
	case uint64:
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, n)
		return buf
	default:
		panic("unsupported number type")
	}
}

const (
	PHASE_MATCH = iota
	PHASE_METER
	PHASE_APPLY
	PHASE_CLEAR
	PHASE_WRITE
	PHASE_META
	PHASE_GOTO
)

type FlowMod struct {
	Table uint8
	OutPort uint32
	OutGroup uint32
}

func flow_mod(arg string, cmd uint8) ([]byte,error) {
	var table uint8
	var outPort, outGroup uint32
	if cmd != ofp4.OFPFC_ADD {
		table = ofp4.OFPTT_ALL
		outPort = ofp4.OFPP_ANY
		outGroup = ofp4.OFPG_ANY
	}
	cookie := ValueMask{}
	var idle_timeout, hard_timeout uint16
	var priority uint16
	var match []byte
	instructions := make(map[uint16]ofp4.Instruction)
	var write, apply ofp4.ActionHeader

	phase := 0
	scan := bufio.NewScanner(strings.NewReader(arg))
	scan.Split(ScanRule)
	for scan.Scan() {
		a := strings.SplitN(scan.Text(), "=", 2)
		switch a[0] {
		case "@goto", "@goto_table":
			phase = PHASE_GOTO
			if n, err := strconv.ParseUint(a[1], 0, 8); err != nil {
				return nil, err
			} else {
				instructions[ofp4.OFPIT_GOTO_TABLE] = ofp4.MakeInstructionGotoTable(uint8(n))
			}
		case "@metadata", "@write_metadata":
			phase = PHASE_META
			if len(a) > 1 {
				panic("invalid extra arg")
			}
		case "@write", "@write_actions":
			phase = PHASE_WRITE
			if len(a) > 1 {
				panic("invalid extra arg")
			}
		case "@apply", "@apply_actions":
			phase = PHASE_APPLY
			if len(a) > 1 {
				panic("invalid extra arg")
			}
		case "@clear", "@clear_actions":
			phase = PHASE_CLEAR
			if len(a) > 1 {
				panic("invalid extra arg")
			}
			instructions[ofp4.OFPIT_CLEAR_ACTIONS] = ofp4.MakeInstructionActions(ofp4.OFPIT_CLEAR_ACTIONS, nil)
		case "@meter":
			phase = PHASE_METER
			panic("not implemented")
		default:
			switch phase {
			case PHASE_MATCH:
				switch a[0] {
				case "table":
					if v, err := strconv.ParseUint(a[1], 0, 8); err != nil {
						return nil, err
					} else {
						table = uint8(v)
					}
				case "cookie":
					pair := strings.SplitN(a[1], "/", 2)
					if v, err := strconv.ParseUint(pair[0], 0, 64); err != nil {
						return nil, err
					} else {
						cookie.Value = intBytes(uint64(v))
					}
					if len(pair) == 2 {
						if v, err := strconv.ParseUint(pair[1], 0, 64); err != nil {
							return nil, err
						} else {
							cookie.Mask = intBytes(uint64(v))
						}
					}
				case "idle_timeout":
					if v, err := strconv.ParseUint(a[1], 0, 16); err != nil {
						return nil, err
					} else {
						idle_timeout = uint16(v)
					}
				case "hard_timeout":
					if v, err := strconv.ParseUint(a[1], 0, 16); err != nil {
						return nil, err
					} else {
						hard_timeout = uint16(v)
					}
				case "priority":
					if v, err := strconv.ParseUint(a[1], 0, 16); err != nil {
						return nil, err
					} else {
						priority = uint16(v)
					}
				case "out_port":
					if v, err := strconv.ParseUint(a[1], 0, 32); err != nil {
						return nil, err
					} else {
						outPort = uint32(v)
					}
				case "out_group", "group":
					if v, err := strconv.ParseUint(a[1], 0, 32); err != nil {
						return nil, err
					} else {
						outGroup = uint32(v)
					}
				default:
					if f := BasicW2M[a[0]]; f != nil {
						if buf,err := f(a[1]); err != nil {
							return nil, err
						} else {
							match = append(match, buf...)
						}
					}else if f:= StratosW2M[a[0]]; f!= nil {
						if buf,err := f(a[1]); err != nil {
							return nil, err
						} else {
							match = append(match, buf...)
						}
					} else {
						return nil, fmt.Errorf("unknown %s", a)
					}
				}
			case PHASE_APPLY:
				if f := ActionW2B[a[0]]; f != nil {
					if action, err := f(a[1]); err != nil {
						return nil, err
					} else {
						apply = append(apply, action...)
					}
				} else {
					panic("unknown")
				}
			case PHASE_WRITE:
				if f := ActionW2B[a[0]]; f != nil {
					if action, err := f(a[1]); err != nil {
						return nil, err
					} else {
						write = append(write, action...)
					}
				} else {
					panic("unknown")
				}
			case PHASE_GOTO:
				panic("goto does not take extra arg")
			default:
				panic("does not acccept extra arg")
			}
		}
	}
	if len(apply) > 0 {
		instructions[ofp4.OFPIT_APPLY_ACTIONS] = ofp4.MakeInstructionActions(ofp4.OFPIT_APPLY_ACTIONS, apply)
	}
	if len(write) > 0 {
		instructions[ofp4.OFPIT_WRITE_ACTIONS] = ofp4.MakeInstructionActions(ofp4.OFPIT_WRITE_ACTIONS, write)
	}
	m := ofp4.MakeMatch(match)
	var ins []byte
	for _,v := range instructions {
		ins = append(ins, v...)
	}
	buf := make([]byte, 48+len(m)+len(ins))
	buf[0] = 4
	buf[1] = ofp4.OFPT_FLOW_MOD
	binary.BigEndian.PutUint16(buf[2:], uint16(len(buf)))
	copy(buf[8:16], cookie.Value)
	copy(buf[16:24], cookie.Mask)
	buf[24] = table
	buf[25] = cmd
	binary.BigEndian.PutUint16(buf[26:], idle_timeout)
	binary.BigEndian.PutUint16(buf[28:], hard_timeout)
	binary.BigEndian.PutUint16(buf[30:], priority)
	binary.BigEndian.PutUint32(buf[32:], ofp4.OFP_NO_BUFFER)
	binary.BigEndian.PutUint32(buf[36:], outPort)
	binary.BigEndian.PutUint32(buf[40:], outGroup)
	copy(buf[48:], m)
	copy(buf[48+len(m):], ins)
	return buf, nil
}

func ScanRule(data []byte, atEOF bool) (int, []byte, error) {
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if unicode.IsSpace(r) || r == ',' {
			// skip
		} else {
			break
		}
	}
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])
		if unicode.IsSpace(r) || r == ',' {
			return i + width, data[start:i], nil
		}
	}
	if atEOF && len(data) > start {
		return len(data), data[start:], nil
	} else {
		return start, nil, nil
	}
}

var portNames = map[string]uint32{
	"IN_PORT":    ofp4.OFPP_IN_PORT,
	"TABLE":      ofp4.OFPP_TABLE,
	"NORMAL":     ofp4.OFPP_NORMAL,
	"FLOOD":      ofp4.OFPP_FLOOD,
	"ALL":        ofp4.OFPP_ALL,
	"CONTROLLER": ofp4.OFPP_CONTROLLER,
	"LOCAL":      ofp4.OFPP_LOCAL,
	"ANY":        ofp4.OFPP_ANY,
	"NONE":       0,
}
