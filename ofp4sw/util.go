package ofp4sw

import (
	"bytes"
	"encoding/binary"
	"io"
	"sort"
	"sync"
)

func IntMin(x ...int) int {
	sort.Ints(x)
	return x[0]
}

func IntMax(x ...int) int {
	sort.Ints(x)
	return x[len(x)-1]
}

// maskBytes returns masked byte array. 0 in mask means don't care.
// mask may be nil. short mask will be applied from head.
func maskBytes(value, mask []byte) []byte {
	ret := make([]byte, IntMax(len(value), len(mask)))
	copy(ret, value)
	for i, v := range mask {
		ret[i] = ret[i] & v
	}
	return ret
}

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

/*
BytesSet is useful to remove duplicate byte sequence.

Usage:
       vat bset BytesSet
       bset.Add([]byte("test"))
       bset.Add([]byte("test"))
       log.Print([][]byte(bset))
*/
type BytesSet [][]byte

func (self *BytesSet) Add(seq []byte) {
	base := [][]byte(*self)
	for _, v := range base {
		if bytes.Equal(v, seq) {
			return
		}
	}
	base = append(base, seq)
	*self = base
}

type IoControlChannel struct {
	hint   [4]byte
	reader io.Reader
	writer io.Writer
	lock   *sync.Cond
	closed error
}

func (self IoControlChannel) Close() {
	self.lock.Broadcast()
}

func (self IoControlChannel) Ingress() ([]byte, error) {
	head := self.hint[:]
	for cur := 0; cur < 4; {
		if num, err := self.reader.Read(head[cur:]); err != nil {
			self.closed = err
			self.Close()
			return nil, err
		} else {
			cur += num
		}
	}
	length := int(binary.BigEndian.Uint16(head[2:4]))
	body := make([]byte, length)
	copy(body, head)
	for cur := 4; cur < length; {
		if num, err := self.reader.Read(body[cur:]); err != nil {
			self.closed = err
			self.Close()
			return nil, err
		} else {
			cur += num
		}
	}
	return body, nil
}

func (self IoControlChannel) Egress(msg []byte) error {
	for cur := 0; cur < len(msg); {
		if nn, err := self.writer.Write(msg); err != nil {
			self.closed = err
			self.Close()
			return err
		} else {
			cur += nn
		}
	}
	return nil
}

func (self IoControlChannel) Wait() error {
	self.lock.L.Lock()
	defer self.lock.L.Unlock()

	self.lock.Wait()
	return self.closed
}

func NewIoControlChannel(reader io.Reader, writer io.Writer) *IoControlChannel {
	self := &IoControlChannel{
		reader: reader,
		writer: writer,
		lock:   sync.NewCond(&sync.Mutex{}),
	}
	return self
}

/*
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
*/
