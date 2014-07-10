package ofp4sw

import (
	"encoding/binary"
	"fmt"
	"net"
)

type controlChannelCommon struct {
	transaction transaction
	ingress     chan []byte
	egress      chan []byte
}

func (p controlChannelCommon) Transaction() transaction { return p.transaction }
func (p controlChannelCommon) Ingress() <-chan []byte   { return (<-chan []byte)(p.ingress) }
func (p controlChannelCommon) Egress() chan<- []byte    { return (chan<- []byte)(p.egress) }

type ControlSource struct {
	listener net.Listener
	source   chan ControlChannel
}

type connControlChannel struct {
	controlChannelCommon
	conn net.Conn
}

func NewListenControlSource(nets, laddr string) (channels <-chan ControlChannel, err error) {
	var ln net.Listener
	if ln, err = net.Listen(nets, laddr); err == nil {
		ch := make(chan ControlChannel)
		channels = (<-chan ControlChannel)(ch)

		go func() {
			ch2 := chan<- ControlChannel(ch)
			defer ln.Close()
			for {
				if con, err := ln.Accept(); err != nil {
					break
				} else {
					ch2 <- NewConnControlChannel(con)
				}
			}
			close(ch2)
		}()
	}
	return
}

func NewConnControlChannel(con net.Conn) ControlChannel {
	port := connControlChannel{
		controlChannelCommon: controlChannelCommon{
			transaction: NewTransaction(),
			ingress:     make(chan []byte),
			egress:      make(chan []byte),
		},
		conn: con,
	}
	go func() {
		for m := range port.egress {
			if _, err := con.Write(m); err != nil {
				fmt.Println(err)
				port.ingress <- nil
			}
		}
	}()
	go func() {
		head := make([]byte, 4)
		for {
			if num, err := con.Read(head); err != nil {
				break
			} else if num != 4 {
				break
			}
			length := binary.BigEndian.Uint16(head[2:4])
			body := make([]byte, length)
			for i, c := range head {
				body[i] = c
			}
			if num, err := con.Read(body[4:]); err != nil {
				break
			} else if num != int(length)-4 {
				break
			} else {
				port.ingress <- body
			}
		}
		port.ingress <- nil
	}()
	return &port
}

func (channel connControlChannel) Close() {
	channel.conn.Close()
}
