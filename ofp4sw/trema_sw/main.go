// +build linux

/*
Package trema_sw implements trema-switch like command line interface.
*/
package main

import (
	"flag"
	"github.com/hkwi/gopenflow"
	"github.com/hkwi/gopenflow/ofp4sw"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

type Wrapper struct {
	con    io.ReadWriteCloser
	Closed chan bool
}

func (self Wrapper) Close() error {
	close(self.Closed)
	return self.con.Close()
}

func (self Wrapper) Read(p []byte) (n int, err error) {
	return self.con.Read(p)
}

func (self Wrapper) Write(p []byte) (n int, err error) {
	return self.con.Write(p)
}

func main() {
	var ports string
	flag.StringVar(&ports, "e", "", "comma separated switch ports (netdev names)")
	var host string
	flag.StringVar(&host, "c", "127.0.0.1", "openflow controller host name")
	var port int
	flag.IntVar(&port, "p", 6653, "openflow controller port")
	var datapathId int64
	flag.Int64Var(&datapathId, "i", 0, "datapath id")
	flag.Parse()

	//	ofp4sw.AddOxmHandler(0xffff<<16, 0xFF00E04D, ofp4sw.StratosOxm{})

	pipe := ofp4sw.NewPipeline()
	pipe.DatapathId = uint64(datapathId)

	if pman, err := gopenflow.NewNamedPortManager(pipe); err != nil {
		log.Print(err)
		return
	} else {
		for _, e := range strings.Split(ports, ",") {
			pman.AddName(e)
		}
	}
	for {
		if addr, err := net.ResolveIPAddr("ip", host); err != nil {
			panic(err)
		} else if con, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: addr.IP, Port: port}); err != nil {
			log.Print(err)
		} else {
			ch := Wrapper{
				con:    con,
				Closed: make(chan bool),
			}
			if err := pipe.AddChannel(ch); err != nil {
				log.Print(err)
			}
			_ = <-ch.Closed
		}
		time.Sleep(5 * time.Second)
	}
}
