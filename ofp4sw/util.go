package ofp4sw

import (
	"encoding/binary"
	"github.com/hkwi/gopenflow"
	"github.com/hkwi/gopenflow/ofp4"
	"io"
	"log"
	"sort"
	"time"
)

type watchTimer struct {
	Active *time.Time
	Past   time.Duration
}

func (self watchTimer) Total() time.Duration {
	ret := self.Past
	if self.Active != nil {
		ret += time.Now().Sub(*self.Active)
	}
	return ret
}

func readOfpMessage(conn io.Reader, hint []byte) ([]byte, error) {
	if len(hint) < 4 {
		hint = make([]byte, 4)
	}
	for cur := 0; cur < 4; {
		if num, err := conn.Read(hint[cur:]); err != nil {
			return nil, err
		} else {
			cur += num
		}
	}
	length := int(binary.BigEndian.Uint16(hint[2:4]))
	body := make([]byte, length)
	copy(body, hint)
	for cur := 4; cur < length; {
		if num, err := conn.Read(body[cur:]); err != nil {
			return nil, err
		} else {
			cur += num
		}
	}
	return body, nil
}

func makeOxmBasic(oxmType uint32) []byte {
	length, mask := ofp4.OxmOfDefs(oxmType)
	if mask {
		length = length * 2
	}
	hdr := ofp4.OxmHeader(oxmType)
	hdr.SetMask(mask)
	hdr.SetLength(length)
	buf := make([]byte, 4+length)
	binary.BigEndian.PutUint32(buf, oxmType)
	return buf
}

func makePort(portNo uint32, port gopenflow.Port) ofp4.Port {
	var config uint32
	for _, conf := range port.GetConfig() {
		switch c := conf.(type) {
		case gopenflow.PortConfigPortDown:
			if bool(c) {
				config |= ofp4.OFPPC_PORT_DOWN
			}
		case gopenflow.PortConfigNoRecv:
			if bool(c) {
				config |= ofp4.OFPPC_NO_RECV
			}
		case gopenflow.PortConfigNoFwd:
			if bool(c) {
				config |= ofp4.OFPPC_NO_FWD
			}
		case gopenflow.PortConfigNoPacketIn:
			if bool(c) {
				config |= ofp4.OFPPC_NO_PACKET_IN
			}
		}
	}

	var state uint32
	for _, st := range port.State() {
		switch s := st.(type) {
		case gopenflow.PortStateLinkDown:
			if bool(s) {
				state |= ofp4.OFPPS_LINK_DOWN
			}
		case gopenflow.PortStateBlocked:
			if bool(s) {
				state |= ofp4.OFPPS_BLOCKED
			}
		case gopenflow.PortStateLive:
			if bool(s) {
				state |= ofp4.OFPPS_LIVE
			}
		}
	}

	eth, err := port.Ethernet()
	if err != nil {
		log.Print(err)
	}
	return ofp4.MakePort(portNo,
		port.HwAddr(),
		[]byte(port.Name()),
		config,
		state,
		eth.Curr,
		eth.Advertised,
		eth.Supported,
		eth.Peer,
		eth.CurrSpeed,
		eth.MaxSpeed)
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
