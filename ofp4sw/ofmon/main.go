package main

import (
	"encoding/binary"
	"flag"
	"github.com/hkwi/gopenflow/ofp4"
	"log"
	"strings"
	"fmt"
	"net"
	"io"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	_ "github.com/hkwi/suppl/gopacket/layers"
)

var hello = string([]byte{ 4, ofp4.OFPT_HELLO, 0, 8, 255,0,0,1 })

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
	
	con := getConn()
	for {
		msg := readMsg(con)
		switch msg.Type(){
		case ofp4.OFPT_PACKET_IN:
			pin := ofp4.PacketIn(msg)
			
			base := fmt.Sprintf("table=%d,cookie=%d",
				pin.TableId(),
				pin.Cookie(),
				)
			for _,oxm := range pin.Match().OxmFields().Iter() {
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
							case STRATOS_OXM_FIELD_RADIOTAP:
								switch binary.BigEndian.Uint16(oxm[8:]){
								case STROXM_RADIOTAP_TSFT:
									ext = fmt.Sprintf("radiotap_tsft=%d",
										binary.BigEndian.Uint64(oxm[10:]))
								case STROXM_RADIOTAP_FLAGS:
									ext = fmt.Sprintf("radiotap_flags=%x", oxm[10])
								case STROXM_RADIOTAP_RATE:
									ext = fmt.Sprintf("radiotap_rate=%x", oxm[10])
								case STROXM_RADIOTAP_CHANNEL:
									ext = fmt.Sprintf("radiotap_channel=%d/%x",
										binary.BigEndian.Uint16(oxm[10:]),
										oxm[12])
								case STROXM_RADIOTAP_FHSS:
									ext = fmt.Sprintf("radiotap_fhss=%d/%x",
										binary.BigEndian.Uint16(oxm[10:]))
								case STROXM_RADIOTAP_DBM_ANTSIGNAL:
									ext = fmt.Sprintf("radiotap_dbm_antsignal=%d", oxm[10])
								case STROXM_RADIOTAP_DBM_ANTNOISE:
									ext = fmt.Sprintf("radiotap_dbm_antnoise=%d", oxm[10])
								case STROXM_RADIOTAP_LOCK_QUALITY:
									ext = fmt.Sprintf("radiotap_lock_quality=%d",
										binary.BigEndian.Uint16(oxm[10:]))
								case STROXM_RADIOTAP_TX_ATTENUATION:
									ext = fmt.Sprintf("radiotap_tx_attenuation=%d",
										binary.BigEndian.Uint16(oxm[10:]))
								case STROXM_RADIOTAP_DB_TX_ATTENUATION:
									ext = fmt.Sprintf("radiotap_db_tx_attenuation=%d",
										binary.BigEndian.Uint64(oxm[10:]))
								case STROXM_RADIOTAP_DBM_TX_POWER:
									ext = fmt.Sprintf("radiotap_dbm_tx_power=%d", oxm[10])
								case STROXM_RADIOTAP_ANTENNA:
									ext = fmt.Sprintf("radiotap_antenna=%d", oxm[10])
								case STROXM_RADIOTAP_DB_ANTSIGNAL:
									ext = fmt.Sprintf("radiotap_db_antsignal=%d", oxm[10])
								case STROXM_RADIOTAP_DB_ANTNOISE:
									ext = fmt.Sprintf("radiotap_db_antnoise=%d", oxm[10])
								}
							}
						}
					}
				}
				if len(ext) > 0 {
					base += "," + ext
				}
			}
			log.Print(base)
			log.Print(gopacket.NewPacket(pin.Data(), layers.LayerTypeEthernet, gopacket.Default))
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

func mac2str(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5])
}
