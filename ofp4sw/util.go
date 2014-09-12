package ofp4sw

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
)

type MapReducable interface {
	Map() Reducable
}

type Reducable interface {
	Reduce()
}

/*
MapReduce implements a streaming map-reduce operation.

A heavy task may be splitted into Map() and Reduce(), where
Map() would be processed concurrently, and Reduce() must be
done in serial.

argument "workers" specifies the concurrency of Map() phase.

enable sync.Pool if we switch to 1.3 runtime.
*/
func MapReduce(works chan MapReducable, workers int) {
	serials := make(chan chan Reducable, workers)
	go func() {
		for work := range works {
			work := work
			serial := make(chan Reducable)
			serials <- serial
			go func() {
				serial <- work.Map()
			}()
		}
		close(serials)
	}()
	for serial := range serials {
		r := <-serial
		r.Reduce()
	}
}

type IoControlChannel struct {
	ingress chan []byte
	egress  chan []byte
	close   chan error
}

func (self IoControlChannel) Ingress() <-chan []byte {
	return self.ingress
}

func (self IoControlChannel) Egress() chan<- []byte {
	return self.egress
}

func (self IoControlChannel) Wait() error {
	return <-self.close
}

func NewIoControlChannel(reader io.Reader, writer io.Writer) *IoControlChannel {
	self := &IoControlChannel{
		ingress: make(chan []byte),
		egress:  make(chan []byte),
		close:   make(chan error, 2),
	}
	go func() {
		for msg := range self.egress {
			for len(msg) > 0 {
				if nn, err := writer.Write(msg); err != nil {
					self.close <- err
					return
				} else {
					msg = msg[nn:]
				}
			}
		}
	}()
	go func() {
		reader := bufio.NewReader(reader)
		head := make([]byte, 4)
		for {
			err := func() error {
				for cur := 0; cur < 4; {
					if num, err := reader.Read(head[cur:]); err != nil {
						return err
					} else {
						cur += num
					}
				}
				length := int(binary.BigEndian.Uint16(head[2:4]))
				body := make([]byte, length)
				copy(body, head)
				for cur := 4; cur < length; {
					if num, err := reader.Read(body[cur:]); err != nil {
						return err
					} else {
						cur += num
					}
				}
				self.ingress <- body
				return nil
			}()
			if err != nil {
				self.close <- err
				break
			}
		}
		close(self.ingress)
	}()
	return self
}

type controlChannelCommon struct {
	ingress chan []byte
	egress  chan []byte
}

func (p controlChannelCommon) Ingress() <-chan []byte {
	return p.ingress
}

func (p controlChannelCommon) Egress() chan<- []byte {
	return p.egress
}

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
			ingress: make(chan []byte),
			egress:  make(chan []byte),
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
					if num, err := con2.Read(head[cur:]); err != nil {
						return err
					} else {
						cur += num
					}
				}
				length := int(binary.BigEndian.Uint16(head[2:4]))
				body := make([]byte, length)
				copy(body, head)
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
