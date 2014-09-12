/*
Package trema_sw implements trema-switch like command line interface.
*/
package main

// +build linux

import (
	"flag"
	"github.com/hkwi/gopenflow/ofp4sw"
	"log"
	"net"
	"strings"
	"time"
)

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

	pipe := ofp4sw.NewPipeline()
	pipe.DatapathId = uint64(datapathId)
	for i, e := range strings.Split(ports, ",") {
		if err := pipe.AddPort(ofp4sw.NewNamedPort(e), uint32(i+1)); err != nil {
			panic(err)
		}
	}
	for {
		if addrs, err := net.LookupHost(host); err != nil {
			panic(err)
		} else {
			for _, addr := range addrs {
				if ip := net.ParseIP(addr); ip != nil {
					if con, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: ip, Port: port}); err != nil {
						log.Print(err)
					} else {
						channel := ofp4sw.NewIoControlChannel(con, con)
						if err := pipe.AddControl(channel); err != nil {
							log.Print(err)
						} else {
							log.Print(channel.Wait())
						}
					}
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}
