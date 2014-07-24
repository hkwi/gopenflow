package ofp4sw

import (
	"bufio"
	"encoding/binary"
	"log"
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
	conn     net.Conn
	callback func()
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
					ch2 <- NewConnControlChannel(con, nil)
				}
			}
			close(ch2)
		}()
	}
	return
}

func NewConnControlChannel(con net.Conn, cb func()) ControlChannel {
	port := connControlChannel{
		controlChannelCommon: controlChannelCommon{
			transaction: NewTransaction(),
			ingress:     make(chan []byte),
			egress:      make(chan []byte),
		},
		conn:     con,
		callback: cb,
	}
	go func() {
		for m := range port.egress {
			if _, err := con.Write(m); err != nil {
				log.Println(err)
				port.ingress <- nil
			}
		}
	}()
	go func() {
		con2 := bufio.NewReader(con)
		head := make([]byte, 4)
		for {
			err := func() error {
				for cur := 0; cur < 4; {
					if num, err := con2.Read(head); err != nil {
						return err
					} else {
						cur += num
					}
				}
				length := int(binary.BigEndian.Uint16(head[2:4]))
				body := make([]byte, length)
				for i, c := range head {
					body[i] = c
				}
				for cur := 4; cur < length; {
					if num, err := con2.Read(body[cur:]); err != nil {
						return err
					} else {
						cur += num
					}
				}
				port.ingress <- body
				return nil
			}()
			if err != nil {
				log.Print(err)
				break
			}
		}
		port.ingress <- nil
	}()
	return &port
}

func (channel connControlChannel) Close() {
	channel.conn.Close()
	channel.callback()
	panic("Close called")
}
