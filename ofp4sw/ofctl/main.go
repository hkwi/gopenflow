package main

import (
	"encoding/binary"
	"flag"
	"github.com/hkwi/gopenflow"
	"github.com/hkwi/gopenflow/ofp4"
	"io"
	"log"
	"net"
	"strings"
)

var hello = string([]byte{4, ofp4.OFPT_HELLO, 0, 8, 255, 0, 0, 1})
var barrier = string([]byte{4, ofp4.OFPT_BARRIER_REQUEST, 0, 8, 255, 0, 0, 2})

func main() {
	flag.Parse()
	args := flag.Args()

	getConn := func(spec string) io.ReadWriter {
		p := strings.SplitN(spec, ":", 2)
		if c, err := net.Dial(p[0], p[1]); err != nil {
			panic(err)
		} else if n, err := c.Write([]byte(hello)); n != 8 || err != nil {
			panic("hello send error")
		} else if res, err := gopenflow.ReadMessage(c); err != nil {
			panic(err)
		} else if res[0] != 4 {
			panic("openflow version error")
		} else if ofp4.Header(res).Type() != ofp4.OFPT_HELLO {
			panic("hello recv error")
		} else {
			return c
		}
	}

	switch args[1] {
	case "dump-flows":
		con := getConn(args[0])

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
			var seq ofp4.FlowStats
			if msg, err := gopenflow.ReadMessage(con); err != nil {
				panic(err)
			} else if ofp4.Header(msg).Type() != ofp4.OFPT_MULTIPART_REPLY {
				panic("multipart error")
			} else if mp := ofp4.MultipartReply(msg); mp.Type() != ofp4.OFPMP_FLOW {
				panic("flow_stats reply error")
			} else {
				seq = ofp4.FlowStats(mp.Body())
			}
			for _, stat := range seq.Iter() {
				log.Printf("%v", stat)
			}
			if binary.BigEndian.Uint16(mphdr[10:])&ofp4.OFPMPF_REPLY_MORE == 0 {
				break
			}
		}
	case "add-flow":
		flow := ofp4.FlowMod(make([]byte, 56))
		if err := flow.Parse(args[2]); err != nil {
			panic(err)
		} else {
			con := getConn(args[0])
			con.Write([]byte(flow))
			con.Write([]byte(barrier))
			if res, err := gopenflow.ReadMessage(con); err != nil {
				panic(err)
			} else if ofp4.Header(res).Type() == ofp4.OFPT_ERROR {
				log.Print("error")
			}
		}
	case "del-flows":
		flow := ofp4.FlowMod(make([]byte, 56))
		flow[25] = ofp4.OFPFC_DELETE
		if err := flow.Parse(args[2]); err != nil {
			panic(err)
		} else {
			con := getConn(args[0])
			con.Write([]byte(flow))
			con.Write([]byte(barrier))
			for {
				if res, err := gopenflow.ReadMessage(con); err != nil {
					panic(err)
				} else if ofp4.Header(res).Type() == ofp4.OFPT_BARRIER_REPLY {
					break
				} else {
					log.Print(res)
				}
			}
		}
	}
}
