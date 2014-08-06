/*
Package pcap implements openflow port.
*/
package pcap

/*
#cgo linux CFLAGS: -DNONBLOCK
#cgo linux LDFLAGS: -lpcap
#cgo freebsd LDFLAGS: -lpcap
#cgo darwin LDFLAGS: -lpcap
#cgo windows CFLAGS: -I C:/WpdPack/Include
#cgo windows,386 LDFLAGS: -L C:/WpdPack/Lib -lwpcap
#cgo windows,amd64 LDFLAGS: -L C:/WpdPack/Lib/x64 -lwpcap
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <string.h>
#include <errno.h>

enum libpcap_option_flag {
	OPTION_FLAG_TIMEOUT = 1,
	OPTION_FLAG_SNAPLEN = 2,
	OPTION_FLAG_PROMISC = 4,
	OPTION_FLAG_BUFFER_SIZE = 8,
};

struct libpcap_option {
	int flags;
	int timeout; // msec
	int snaplen;
	int buffer_size;
};

int _libpcap_setopts(pcap_t *handle, struct libpcap_option opts, char* errbuf){
	if (opts.flags & OPTION_FLAG_TIMEOUT) {
		int rc = pcap_set_timeout(handle, opts.timeout);
		if (rc != 0){
			return rc;
		}
	}
	if (opts.flags & OPTION_FLAG_SNAPLEN) {
		int rc = pcap_set_snaplen(handle, opts.snaplen);
		if (rc != 0){
			return rc;
		}
	}
	if (opts.flags & OPTION_FLAG_PROMISC) {
		int rc = pcap_set_promisc(handle, 1);
		if (rc != 0){
			return rc;
		}
	}
	if (opts.flags & OPTION_FLAG_BUFFER_SIZE) {
		int rc = pcap_set_buffer_size(handle, opts.buffer_size);
		if (rc != 0){
			return rc;
		}
	}
	return pcap_activate(handle);
}

pcap_t* libpcap_open(const char *sourceName, struct libpcap_option opts, char* errbuf){
	pcap_t *handle = pcap_create(sourceName, errbuf);
	if (handle==NULL) {
		return NULL;
	}
	int ret = _libpcap_setopts(handle, opts, errbuf);
	if (ret != 0 ) {
		strcpy(errbuf, pcap_statustostr(ret));
		pcap_close(handle);
		return NULL;
	}
#ifdef NONBLOCK
	if (pcap_setnonblock(handle, 1, errbuf) != 0) {
		pcap_close(handle);
		return NULL;
	}
	// xxx: quick work around that mmap mode does not set nonblock for SENDING packet.
	int fd = pcap_get_selectable_fd(handle);
	if (fd < 0) {
		pcap_close(handle);
		return NULL;
	}
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1 ) {
		strcpy(errbuf, strerror(errno));
		pcap_close(handle);
		return NULL;
	}
	int rc = fcntl(fd, F_SETFL, flags|O_NONBLOCK);
	if (rc < 0) {
		strcpy(errbuf, strerror(errno));
		pcap_close(handle);
		return NULL;
	}
#endif
	return handle;
}

char* libpcap_get(pcap_t *handle, int msec, int *pktlen, int *caplen, const u_char **data) {
	do {
		struct pcap_pkthdr *hdr;
		switch (pcap_next_ex(handle, &hdr, data)) {
		case 1:
			*pktlen = hdr->len;
			*caplen = hdr->caplen;
			return NULL;
		case -1:
			return pcap_geterr(handle);
		case -2:
			return "EOF";
		case 0:
			break;
		default:
			return "pcap_next_ex returned unexpected";
		}
	#ifdef NONBLOCK
		int fd = pcap_get_selectable_fd(handle);
		struct pollfd fds[1] = {{ fd, POLLIN, 0 }};
		int actv = poll(fds, 1, msec);
		if (actv < 0 && errno != EINTR) {
			return strerror(errno);
		}
	#endif
	} while (1);
}
*/
import "C"

import (
	"errors"
	"reflect"
	"sync"
	"unsafe"
)

type ShortSnaplen string

func (self ShortSnaplen) Error() string {
	return string(self)
}

/*
Handle is a handle for pcap_t. Call Open() to create this object.
*/
type Handle struct {
	handle *C.struct_pcap_t
	lock   *sync.Mutex
}

type TimeoutOption int
type SnaplenOption int
type PromiscOption int
type BufferSizeOption int

func Open(name string, opts []interface{}) (*Handle, error) {
	var sourceName *C.char
	if len(name) > 0 {
		sourceName = C.CString(name)
		defer C.free(unsafe.Pointer(sourceName))
	}
	errbuf := (*C.char)(C.malloc(C.PCAP_ERRBUF_SIZE))
	defer C.free(unsafe.Pointer(errbuf))

	var copts C.struct_libpcap_option
	for _, opt := range opts {
		switch o := opt.(type) {
		case TimeoutOption:
			copts.flags |= C.OPTION_FLAG_TIMEOUT
			copts.timeout = C.int(o)
		case SnaplenOption:
			copts.flags |= C.OPTION_FLAG_SNAPLEN
			copts.snaplen = C.int(o)
		case PromiscOption:
			copts.flags |= C.OPTION_FLAG_PROMISC
		case BufferSizeOption:
			copts.flags |= C.OPTION_FLAG_BUFFER_SIZE
			copts.buffer_size = C.int(o)
		default:
			return nil, errors.New("Unknown option")
		}
	}
	self := &Handle{
		handle: C.libpcap_open(sourceName, copts, errbuf),
		lock:   &sync.Mutex{},
	}
	if self.handle == nil {
		return nil, errors.New(C.GoString(errbuf))
	}
	return self, nil
}

func (self Handle) Close() {
	self.lock.Lock()
	defer self.lock.Unlock()

	if self.handle != nil {
		C.pcap_close(self.handle)
		self.handle = nil
	}
}

type Timeout string

func (self Timeout) Error() string {
	return string(self)
}

/*
Gets a packet and stores into the buffer. The buffer size will be modified after this call.
*/
func (self Handle) Get(pkt []byte, msec int) ([]byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()

	var pktlen, caplen C.int
	var data *C.u_char
	if estr := C.libpcap_get(self.handle, C.int(msec), &pktlen, &caplen, &data); estr != nil {
		return nil, errors.New(C.GoString(estr))
	}
	if len(pkt) >= int(caplen) {
		pkt = pkt[:caplen]
	} else {
		pkt = append(pkt, make([]byte, int(caplen)-len(pkt))...)
	}
	// XXX: non-portable
	dst := (*reflect.SliceHeader)(unsafe.Pointer(&pkt)).Data
	C.memcpy(unsafe.Pointer(dst), unsafe.Pointer(data), C.size_t(caplen))
	if pktlen > caplen {
		return pkt, ShortSnaplen("packet was longer than snaplen.")
	}
	return pkt, nil
}

func (self *Handle) Put(pkt []byte) error {
	// XXX: non-portable
	data := unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&pkt)).Data)
	if rc := C.pcap_sendpacket(self.handle, (*C.u_char)(data), C.int(len(pkt))); rc == -1 {
		return errors.New(C.GoString(C.pcap_geterr(self.handle)))
	} else if rc == 0 {
		return nil
	} else {
		return errors.New("Unknown error")
	}
}
