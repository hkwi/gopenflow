package pcap

/*
#cgo linux LDFLAGS: -lpcap
#cgo freebsd LDFLAGS: -lpcap
#cgo darwin LDFLAGS: -lpcap
#cgo windows CFLAGS: -I C:/WpdPack/Include
#cgo windows,386 LDFLAGS: -L C:/WpdPack/Lib -lwpcap
#cgo windows,amd64 LDFLAGS: -L C:/WpdPack/Lib/x64 -lwpcap
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <fcntl.h>

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

int set_fd_nonblock(pcap_t *handle, int onoff){
	int fd = pcap_get_selectable_fd(handle);
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1 ) {
		return -1;
	} else {
		if (onoff == 0) {
			flags &= ~O_NONBLOCK;
		} else {
			flags |= O_NONBLOCK;
		}
		return fcntl(fd, F_SETFL, flags);
	}
}

int select_read_write(pcap_t *handle, int timeout, int read, int write){
	int fd = pcap_get_selectable_fd(handle);
	struct timeval tm = {
		timeout/1000,
		(timeout%1000)*1000,
	};
	fd_set reads;
	FD_ZERO(&reads);
	if(read != 0){
		FD_SET(fd, &reads);
	}
	fd_set writes;
	FD_ZERO(&writes);
	if(write != 0){
		FD_SET(fd, &writes);
	}
	return select(fd+1, &reads, &writes, NULL, &tm);
}
*/
import "C"

import (
	"errors"
	"unsafe"
	"sync"
	"syscall"
)

type Handle struct {
	pcapT *C.pcap_t
	lock sync.Mutex // lock for pcapT
	Timeout int // in milliseconds
}

type Stat struct {
	PacketsRecieved uint
	PacketsDropped uint
	PacketsIfDropped uint
}

type PcapError struct {
	Code C.int
}

func (self PcapError) Error() string {
	return C.GoString(C.pcap_statustostr(self.Code))
}

type Timeout struct {}

func (self Timeout) Error() string { return "timeout" }

type EOF struct {}

func (self EOF) Error() string { return "EOF" }

func Create(source string) (*Handle, error) {
	var sourceName *C.char
	if len(source) > 0 {
		sourceName = C.CString(source)
		defer C.free(unsafe.Pointer(sourceName))
	}
	errbuf := (*C.char)(C.malloc(C.PCAP_ERRBUF_SIZE))
	defer C.free(unsafe.Pointer(errbuf))
	
	handle := C.pcap_create(sourceName, errbuf)
	if handle == nil {
		return nil, errors.New(C.GoString(errbuf))
	} else {
		return &Handle{
			pcapT: handle,
			lock: sync.Mutex{},
		}, nil
	}
}

func (self Handle) Close() {
	self.lock.Lock()
	defer self.lock.Unlock()
	
	if self.pcapT != nil {
		C.pcap_close(self.pcapT)
		self.pcapT = nil
	}
}

func (self Handle) Activate() error {
	rc := C.pcap_activate(self.pcapT)
	if rc == 0 {
		return nil
	} else {
		return PcapError{rc}
	}
}

func (self Handle) GetSnaplen() (int,error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	
	rc := C.pcap_snapshot(self.pcapT)
	switch rc {
	default:
		return int(rc), nil
	case C.PCAP_ERROR_NOT_ACTIVATED:
		return 0, PcapError{rc}
	}
}

func (self Handle) SetSnaplen(snaplen int) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	
	rc := C.pcap_set_snaplen(self.pcapT, C.int(snaplen))
	switch rc {
	case 0:
		return nil
	default:
		return PcapError{rc}
	}
}

func (self Handle) SetPromisc(onOff bool) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	
	var value C.int
	if onOff {
		value = 1
	}
	rc := C.pcap_set_promisc(self.pcapT, value)
	switch rc {
	case 0:
		return nil
	default:
		return PcapError{rc}
	}
}


// SetTimeout sets the read timeout.
func (self *Handle) SetTimeout(milliseconds int) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	
	rc := C.pcap_set_timeout(self.pcapT, C.int(milliseconds))
	switch rc {
	case 0:
		self.Timeout = milliseconds
		return nil
	default:
		return PcapError{rc}
	}
}

func (self Handle) SetBufferSize(bufferSize int) error {
	rc := C.pcap_set_buffer_size(self.pcapT, C.int(bufferSize))
	switch rc {
	case 0:
		return nil
	default:
		return PcapError{rc}
	}
}

func (self Handle) Setnonblock(nonblock bool) error {
	errbuf := (*C.char)(C.malloc(C.PCAP_ERRBUF_SIZE))
	defer C.free(unsafe.Pointer(errbuf))
	
	self.lock.Lock()
	defer self.lock.Unlock()
	
	var value C.int
	if nonblock {
		value = 1
	}
	if rc,err := C.pcap_setnonblock(self.pcapT, value, errbuf); err != nil {
		return err
	} else {
		switch rc {
		case 0:
			// ok
		case -1:
			return errors.New(C.GoString(errbuf))
		default:
			return errors.New("Unexpected")
		}
	}
	
	if rc,err := C.set_fd_nonblock(self.pcapT, value); err!=nil {
		return err
	} else {
		switch rc {
		case 0:
			// ok
		default:
			return errors.New("Unexpected")
		}
	}
	return nil
}

func (self Handle) Getnonblock() (bool, error) {
	errbuf := (*C.char)(C.malloc(C.PCAP_ERRBUF_SIZE))
	defer C.free(unsafe.Pointer(errbuf))
	
	self.lock.Lock()
	defer self.lock.Unlock()
	
	rc := C.pcap_getnonblock(self.pcapT, errbuf)
	switch rc {
	case -1:
		return false, errors.New(C.GoString(errbuf))
	case 0:
		return false, nil
	default:
		return true, nil
	}
}

func (self Handle) Next() (packetLen int, captured []byte, err error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	
	var hdr *C.struct_pcap_pkthdr
	var data *C.u_char

	rc := C.pcap_next_ex(self.pcapT, &hdr, &data)
	switch rc {
	case 1:
		return int(hdr.len), C.GoBytes(unsafe.Pointer(data), C.int(hdr.caplen)), nil
	case 0:
		return 0, nil, &Timeout{}
	case -1:
		return 0, nil, errors.New(C.GoString(C.pcap_geterr(self.pcapT)))
	case -2:
		return 0, nil, &EOF{}
	default:
		return 0, nil, errors.New("unexpected")
	}
}

func (self Handle) SelectRead() error {
	rc,err := C.select_read_write(self.pcapT, C.int(self.Timeout), 1, 0)
	switch rc {
	case -1:
		if e,ok:=err.(syscall.Errno); ok {
			if e == syscall.EINTR {
				return nil
			}
		}
		return err
	case 0:
		return &Timeout{}
	}
	return nil
}

func (self Handle) SelectWrite() error {
	rc,err := C.select_read_write(self.pcapT, C.int(self.Timeout), 0, 1)
	switch rc {
	case -1:
		if e,ok:=err.(syscall.Errno); ok {
			if e == syscall.EINTR {
				return nil
			}
		}
		return err
	case 0:
		return &Timeout{}
	}
	return nil
}

func (self Handle) Sendpacket(data []byte) error {
	payload := unsafe.Pointer(C.CString(string(data)))
	defer C.free(payload)

	self.lock.Lock()
	defer self.lock.Unlock()
	
	if rc := C.pcap_sendpacket(self.pcapT, (*C.u_char)(payload), C.int(len(data))); rc==-1 {
		return errors.New(C.GoString(C.pcap_geterr(self.pcapT)))
	} else if rc == 0 {
		return nil
	} else {
		return errors.New("Unknown error")
	}
}

func (self Handle) Stats() (Stat, error){
	self.lock.Lock()
	defer self.lock.Unlock()
	
	stat := C.struct_pcap_stat{}
	rc := C.pcap_stats(self.pcapT, &stat)
	switch rc {
	case 0:
		return Stat{
			PacketsRecieved: uint(stat.ps_recv),
			PacketsDropped: uint(stat.ps_drop),
			PacketsIfDropped: uint(stat.ps_ifdrop),
		}, nil
	case -1:
		return Stat{}, errors.New(C.GoString(C.pcap_geterr(self.pcapT)))
	default:
		return Stat{}, errors.New("Unexpected")
	}
}

func (self Handle) NextPacket() ([]byte, error) {
	for {
		for {
			if err:= self.SelectRead(); err!= nil {
				switch e:=err.(type) {
				case *Timeout:
					// continue
				default:
					return nil, e
				}
			} else {
				break
			}
		}
		if _, captured, err := self.Next(); err!=nil {
			switch e:=err.(type) {
			case *Timeout:
				// continue
			case *EOF:
				return nil, e
			default:
				return nil, e
			}
		} else {
			return captured, nil
		}
	}
}
