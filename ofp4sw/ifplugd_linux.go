package ofp4sw

import (
	"bytes"
	"errors"
	"log"
	"sync"
	"syscall"
	"unsafe"
)

const IFF_LOWER_UP = 1 << 16
const IFLA_EXT_MASK = 0x1e
const RTEXT_FILTER_VF = 1

type NetdevUpdate struct {
	Type    uint16 // RTNL_NEWLINK/DELLINK
	Name    string
	Index   int32
	Mtu     uint32
	Up      bool
	LowerUp bool
	Running bool
}

type ifplugd struct {
	lock      *sync.Mutex
	fd        int
	evfd      int
	buf       []byte
	listeners []chan NetdevUpdate // This is channel for third party port implementation may register its channel with buffer.
}

var ifplug *ifplugd = &ifplugd{
	lock: &sync.Mutex{},
	fd:   -1,
	evfd: -1,
	buf:  make([]byte, syscall.Getpagesize()),
}

func (self *ifplugd) start() (err error) {
	if self.fd, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE); err != nil {
		return
	}
	if err = syscall.Bind(self.fd, &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(syscall.Getpid()),
		Groups: syscall.RTNLGRP_LINK | syscall.RTNLGRP_NOTIFY,
	}); err != nil {
		return
	}
	if self.evfd, err = syscall.EpollCreate1(0); err != nil {
		return
	}
	ev := syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(self.fd)}
	if err = syscall.EpollCtl(self.evfd, syscall.EPOLL_CTL_ADD, self.fd, &ev); err != nil {
		return
	}
	return
}

func (self *ifplugd) next() error {
	if len(self.listeners) == 0 {
		return errors.New("No listeners")
	}
	evs := make([]syscall.EpollEvent, 1)
	if n, err := syscall.EpollWait(self.evfd, evs, 1000); err != nil {
		return err
	} else if n == 0 {
		return nil
	}
	nn, _, e1 := syscall.Recvfrom(self.fd, self.buf, syscall.MSG_TRUNC)
	if e1 != nil {
		return e1
	}
	updates, _ := parseToUpdates(self.buf[:nn])
	for _, ev := range updates {
		for _, listener := range self.listeners {
			listener <- ev
		}
	}
	return nil
}

func (self *ifplugd) stop() {
	if self.evfd != -1 {
		ev := syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(self.fd)}
		if err := syscall.EpollCtl(self.evfd, syscall.EPOLL_CTL_DEL, self.fd, &ev); err != nil {
			log.Print(err)
		}
		if err := syscall.Close(self.evfd); err != nil {
			log.Print(err)
		}
		self.evfd = -1
	}
	if self.fd != -1 {
		if err := syscall.Close(self.fd); err != nil {
			log.Print(err)
		}
		self.fd = -1
	}
}

func IfplugdAddListener(listener chan NetdevUpdate) error {
	self := ifplug
	self.lock.Lock()
	defer self.lock.Unlock()
	trigger_start := len(self.listeners) == 0
	self.listeners = append(self.listeners, listener)
	if trigger_start {
		if err := self.start(); err != nil {
			return err
		}
		go func() {
			for {
				if err := self.next(); err != nil {
					break
				}
			}
			for _, c := range self.listeners {
				close(c)
			}
			self.listeners = nil
		}()
	}
	return nil
}

func IfplugdRemoveListener(listener chan NetdevUpdate) error {
	self := ifplug
	self.lock.Lock()
	defer self.lock.Unlock()
	var new_listeners []chan NetdevUpdate
	for _, l := range self.listeners {
		if l == listener {
			close(listener)
		} else {
			new_listeners = append(new_listeners, l)
		}
	}
	self.listeners = new_listeners
	if len(self.listeners) == 0 {
		self.stop()
	}
	return nil
}

func IfplugdGet() (ret []NetdevUpdate, err error) {
	var fd int
	if fd, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE); err != nil {
		return
	}

	msgLen := unsafe.Sizeof(syscall.NlMsghdr{}) + unsafe.Sizeof(syscall.IfInfomsg{})
	msg := make([]byte, 0, msgLen)
	hdr := syscall.NlMsghdr{
		Len:   uint32(msgLen),
		Type:  syscall.RTM_GETLINK,
		Flags: syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST,
	}
	msg = append(msg, (*(*[unsafe.Sizeof(hdr)]byte)(unsafe.Pointer(&hdr)))[:]...)
	info := syscall.IfInfomsg{
		Family: syscall.AF_PACKET,
	}
	msg = append(msg, (*(*[unsafe.Sizeof(info)]byte)(unsafe.Pointer(&info)))[:]...)
	attr := syscall.RtAttr{
		Len:  4,
		Type: IFLA_EXT_MASK,
	}
	msg = append(msg, (*(*[unsafe.Sizeof(attr)]byte)(unsafe.Pointer(&attr)))[:]...)
	var value uint32 = RTEXT_FILTER_VF
	msg = append(msg, (*(*[unsafe.Sizeof(value)]byte)(unsafe.Pointer(&value)))[:]...)

	if err = syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{}); err != nil {
		return
	}
	buf := make([]byte, syscall.Getpagesize())

	for {
		var nn int
		nn, _, err = syscall.Recvfrom(fd, buf, syscall.MSG_TRUNC)
		if err != nil {
			return
		}
		evs, done := parseToUpdates(buf[:nn])
		ret = append(ret, evs...)
		if done {
			break
		}
	}
	return
}

func parseToUpdates(data []byte) ([]NetdevUpdate, bool) {
	msgs, e1 := syscall.ParseNetlinkMessage(data)
	if e1 != nil {
		panic(e1)
	}
	var ret []NetdevUpdate
	var done bool = false
	for _, msg := range msgs {
		switch msg.Header.Type {
		case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
			ev := NetdevUpdate{Type: msg.Header.Type}
			info := (*syscall.IfInfomsg)(unsafe.Pointer(&msg.Data[0]))
			ev.Index = info.Index
			if info.Flags&syscall.IFF_UP != 0 {
				ev.Up = true
			}
			if info.Flags&syscall.IFF_RUNNING != 0 {
				ev.Running = true
			}
			if info.Flags&IFF_LOWER_UP != 0 {
				ev.LowerUp = true
			}
			if attrs, err := syscall.ParseNetlinkRouteAttr(&msg); err == nil {
				for _, attr := range attrs {
					switch attr.Attr.Type {
					case syscall.IFLA_IFNAME:
						ev.Name = string(bytes.Trim(attr.Value, "\x00"))
					case syscall.IFLA_MTU:
						ev.Mtu = *(*uint32)(unsafe.Pointer(&attr.Value[0]))
					}
				}
			}
			ret = append(ret, ev)
		case syscall.NLMSG_DONE:
			done = true
		}
	}
	return ret, done
}
