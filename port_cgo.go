// +build linux,cgo

package gopenflow

/*
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ethtool.h>

int ethtool_cmd_call(int fd, char *name, struct ethtool_cmd *ecmd){
	struct ifreq ifr;
	memset(ifr.ifr_name, 0, IFNAMSIZ);
	int i;
	for(i=0; i<strlen(name); i++){
		if(i<IFNAMSIZ){
			ifr.ifr_name[i] = name[i];
		}
	}
	ifr.ifr_data = (char*)ecmd;
	return ioctl(fd, SIOCETHTOOL, &ifr);
}

void* get_hwaddr(int fd, char *name, int *hwaddr_len){
	struct ifreq ifr;
	memset(ifr.ifr_name, 0, IFNAMSIZ);
	int i;
	for(i=0; i<strlen(name); i++){
		if(i<IFNAMSIZ){
			ifr.ifr_name[i] = name[i];
		}
	}
	if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		*hwaddr_len = ETH_ALEN;
		char *hwaddr = malloc(ETH_ALEN);
		memmove(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		return hwaddr;
	}
	return NULL;
}

*/
import "C"
import (
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"syscall"
	"unsafe"
)

var supportedSpeed map[C.__u32]uint32 = map[C.__u32]uint32{
	C.SUPPORTED_10baseT_Half:       10000,
	C.SUPPORTED_10baseT_Full:       10000,
	C.SUPPORTED_100baseT_Half:      100000,
	C.SUPPORTED_100baseT_Full:      100000,
	C.SUPPORTED_1000baseT_Half:     1000000,
	C.SUPPORTED_1000baseT_Full:     1000000,
	C.SUPPORTED_10000baseT_Full:    10000000,
	C.SUPPORTED_2500baseX_Full:     2500000,
	C.SUPPORTED_1000baseKX_Full:    1000000,
	C.SUPPORTED_10000baseKX4_Full:  10000000,
	C.SUPPORTED_10000baseKR_Full:   10000000,
	C.SUPPORTED_10000baseR_FEC:     10000000,
	C.SUPPORTED_20000baseMLD2_Full: 20000000,
	C.SUPPORTED_20000baseKR2_Full:  20000000,
	C.SUPPORTED_40000baseKR4_Full:  40000000,
	C.SUPPORTED_40000baseCR4_Full:  40000000,
	C.SUPPORTED_40000baseSR4_Full:  40000000,
	C.SUPPORTED_40000baseLR4_Full:  40000000,
}
var supportedConvert map[C.__u32]uint32 = map[C.__u32]uint32{
	C.SUPPORTED_10baseT_Half:       ofp4.OFPPF_10MB_HD,
	C.SUPPORTED_10baseT_Full:       ofp4.OFPPF_10MB_FD,
	C.SUPPORTED_100baseT_Half:      ofp4.OFPPF_100MB_HD,
	C.SUPPORTED_100baseT_Full:      ofp4.OFPPF_100MB_FD,
	C.SUPPORTED_1000baseT_Half:     ofp4.OFPPF_1GB_HD,
	C.SUPPORTED_1000baseT_Full:     ofp4.OFPPF_1GB_FD,
	C.SUPPORTED_Autoneg:            ofp4.OFPPF_AUTONEG,
	C.SUPPORTED_TP:                 ofp4.OFPPF_COPPER,
	C.SUPPORTED_10000baseT_Full:    ofp4.OFPPF_10GB_FD,
	C.SUPPORTED_Pause:              ofp4.OFPPF_PAUSE,
	C.SUPPORTED_Asym_Pause:         ofp4.OFPPF_PAUSE_ASYM,
	C.SUPPORTED_2500baseX_Full:     ofp4.OFPPF_OTHER,
	C.SUPPORTED_1000baseKX_Full:    ofp4.OFPPF_1GB_FD,
	C.SUPPORTED_10000baseKX4_Full:  ofp4.OFPPF_10MB_FD,
	C.SUPPORTED_10000baseKR_Full:   ofp4.OFPPF_10GB_FD,
	C.SUPPORTED_10000baseR_FEC:     ofp4.OFPPF_10GB_FD,
	C.SUPPORTED_20000baseMLD2_Full: ofp4.OFPPF_OTHER,
	C.SUPPORTED_20000baseKR2_Full:  ofp4.OFPPF_OTHER,
	C.SUPPORTED_40000baseKR4_Full:  ofp4.OFPPF_40GB_FD,
	C.SUPPORTED_40000baseCR4_Full:  ofp4.OFPPF_40GB_FD,
	C.SUPPORTED_40000baseSR4_Full:  ofp4.OFPPF_40GB_FD,
	C.SUPPORTED_40000baseLR4_Full:  ofp4.OFPPF_40GB_FD,
}
var advertisedConvert map[C.__u32]uint32 = map[C.__u32]uint32{
	C.ADVERTISED_10baseT_Half:       ofp4.OFPPF_10MB_HD,
	C.ADVERTISED_10baseT_Full:       ofp4.OFPPF_10MB_FD,
	C.ADVERTISED_100baseT_Half:      ofp4.OFPPF_100MB_HD,
	C.ADVERTISED_100baseT_Full:      ofp4.OFPPF_100MB_FD,
	C.ADVERTISED_1000baseT_Half:     ofp4.OFPPF_1GB_HD,
	C.ADVERTISED_1000baseT_Full:     ofp4.OFPPF_1GB_FD,
	C.ADVERTISED_Autoneg:            ofp4.OFPPF_AUTONEG,
	C.ADVERTISED_TP:                 ofp4.OFPPF_COPPER,
	C.ADVERTISED_10000baseT_Full:    ofp4.OFPPF_10GB_FD,
	C.ADVERTISED_Pause:              ofp4.OFPPF_PAUSE,
	C.ADVERTISED_Asym_Pause:         ofp4.OFPPF_PAUSE_ASYM,
	C.ADVERTISED_2500baseX_Full:     ofp4.OFPPF_OTHER,
	C.ADVERTISED_1000baseKX_Full:    ofp4.OFPPF_1GB_FD,
	C.ADVERTISED_10000baseKX4_Full:  ofp4.OFPPF_10MB_FD,
	C.ADVERTISED_10000baseKR_Full:   ofp4.OFPPF_10GB_FD,
	C.ADVERTISED_10000baseR_FEC:     ofp4.OFPPF_10GB_FD,
	C.ADVERTISED_20000baseMLD2_Full: ofp4.OFPPF_OTHER,
	C.ADVERTISED_20000baseKR2_Full:  ofp4.OFPPF_OTHER,
	C.ADVERTISED_40000baseKR4_Full:  ofp4.OFPPF_40GB_FD,
	C.ADVERTISED_40000baseCR4_Full:  ofp4.OFPPF_40GB_FD,
	C.ADVERTISED_40000baseSR4_Full:  ofp4.OFPPF_40GB_FD,
	C.ADVERTISED_40000baseLR4_Full:  ofp4.OFPPF_40GB_FD,
}

func (self NamedPort) Ethernet() (PortEthernetProperty, error) {
	switch self.hatype {
	case 0:
		return PortEthernetProperty{}, nil
	case syscall.ARPHRD_ETHER:
		// pass
	default:
		return PortEthernetProperty{}, fmt.Errorf("not an ether")
	}

	cname := C.CString(self.name)
	defer C.free(unsafe.Pointer(cname))

	fd := C.socket(C.AF_INET, C.SOCK_DGRAM, 0)
	defer C.close(fd)

	state := PortEthernetProperty{}

	ecmd := C.struct_ethtool_cmd{cmd: C.ETHTOOL_GSET}
	if r, err := C.ethtool_cmd_call(fd, cname, &ecmd); err != nil {
		return state, err
	} else if r != 0 {
		return state, fmt.Errorf("ethtool_cmd_call error")
	} else {
		for k, v := range supportedSpeed {
			if ecmd.supported&k != 0 && v > state.MaxSpeed {
				state.MaxSpeed = v
			}
		}
		state.Supported = 0
		for k, v := range supportedConvert {
			if ecmd.supported&k != 0 {
				state.Supported |= v
			}
		}
		state.Advertised = 0
		state.Peer = 0
		for k, v := range advertisedConvert {
			if ecmd.advertising&k != 0 {
				state.Advertised |= v
			}
			if ecmd.lp_advertising&k != 0 {
				state.Peer |= v
			}
		}

		var curr uint32
		switch C.ethtool_cmd_speed(&ecmd) {
		case C.SPEED_10:
			state.CurrSpeed = 10000
			switch ecmd.duplex {
			case C.DUPLEX_HALF:
				curr |= ofp4.OFPPF_10MB_HD
			case C.DUPLEX_FULL:
				curr |= ofp4.OFPPF_10MB_FD
			default:
				curr |= ofp4.OFPPF_OTHER
			}
		case C.SPEED_100:
			state.CurrSpeed = 100000
			switch ecmd.duplex {
			case C.DUPLEX_HALF:
				curr |= ofp4.OFPPF_100MB_HD
			case C.DUPLEX_FULL:
				curr |= ofp4.OFPPF_100MB_FD
			default:
				curr |= ofp4.OFPPF_OTHER
			}
		case C.SPEED_1000:
			state.CurrSpeed = 1000000
			switch ecmd.duplex {
			case C.DUPLEX_HALF:
				curr |= ofp4.OFPPF_1GB_HD
			case C.DUPLEX_FULL:
				curr |= ofp4.OFPPF_1GB_FD
			default:
				curr |= ofp4.OFPPF_OTHER
			}
		case C.SPEED_10000:
			state.CurrSpeed = 1000000
			switch ecmd.duplex {
			case C.DUPLEX_FULL:
				curr |= ofp4.OFPPF_10GB_FD
			default:
				curr |= ofp4.OFPPF_OTHER
			}
		default:
			curr |= ofp4.OFPPF_OTHER
		}
		switch ecmd.port {
		case C.PORT_TP:
			curr |= ofp4.OFPPF_COPPER
		case C.PORT_FIBRE:
			curr |= ofp4.OFPPF_FIBER
		}
		if ecmd.autoneg != C.AUTONEG_DISABLE {
			curr |= ofp4.OFPPF_AUTONEG
		}
		state.Curr = curr
	}
	return state, nil
}
