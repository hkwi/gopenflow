package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hkwi/gopenflow/ofp4"
	_ "github.com/hkwi/suppl/gopacket/layers"
	"io"
	"log"
	"net"
	"strings"
)

var hello = string([]byte{4, ofp4.OFPT_HELLO, 0, 8, 255, 0, 0, 1})

func main() {
	flag.Parse()
	args := flag.Args()

	getConn := func() io.ReadWriter {
		p := strings.SplitN(args[0], ":", 2)
		if len(p) == 1 {
			panic("connection scheme failure %s", args[0])
		} else if c, err := net.Dial(p[0], p[1]); err != nil {
			panic(err)
		} else if n, err := c.Write([]byte(hello)); n != 8 || err != nil {
			panic("hello send error")
		} else if res := readMsg(c); res.Type() != ofp4.OFPT_HELLO {
			panic("hello recv error")
		} else {
			return c
		}
	}

	con := getConn()
	for {
		msg := readMsg(con)
		switch msg.Type() {
		case ofp4.OFPT_PACKET_IN:
			pin := ofp4.PacketIn(msg)

			comps := []string{
				fmt.Sprintf("table=%d,cookie=%d", pin.TableId(), pin.Cookie()),
			}
			if match := pin.Match().OxmFields(); len(match) > 0 {
				comps = append(comps, fmt.Sprintf("%v", match))
			}
			log.Print(strings.Join(comps, ","))
			log.Print(gopacket.NewPacket(pin.Data(), layers.LayerTypeEthernet, gopacket.Default))
		}
	}
}

func readMsg(con io.Reader) ofp4.Header {
	buf := make([]byte, 8)
	if n, err := con.Read(buf); err != nil || n != 8 {
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
