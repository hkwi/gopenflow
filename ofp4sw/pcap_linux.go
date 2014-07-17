package ofp4sw

// +build linux,cgo

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
		char *hwaddr = NULL;
		if ( ifr.ifr_hwaddr.sa_family == AF_PACKET ) {
			*hwaddr_len = ETH_ALEN;
			hwaddr = malloc(ETH_ALEN);
			memmove(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		}
		return hwaddr;
	}
	return NULL;
}

unsigned int get_flags(char *name) {
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	
	unsigned int flags = 0;
	
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		struct rtattr ext_req __attribute__ ((aligned(NLMSG_ALIGNTO)));
		__u32 ext_filter_mask;
	} req;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
	req.ifm.ifi_family = AF_PACKET;
	
	if (-1 != send(fd, &req, sizeof(req), 0)){
		int done = 0;
		char buf[16384];
		do {
			ssize_t sz = recv(fd, buf, sizeof(buf), 0);
			if (-1 == sz){
				break;
			}
			struct nlmsghdr *h = (struct nlmsghdr*)buf;
			int i;
			for(i=0; i<sz; i+=h->nlmsg_len){
				h = (struct nlmsghdr*)(buf+i);
				if (h->nlmsg_type == NLMSG_DONE) {
					done = 1;
					break;
				} else if (h->nlmsg_type == NLMSG_ERROR) {
					break;
				} else {
					struct ifinfomsg *ifi = (struct ifinfomsg*)(h+1);
					struct rtattr *attr = (struct rtattr*)(ifi+1);
					while ( (char*)attr < (char*)h + h->nlmsg_len ) {
						if(attr->rta_type==IFLA_IFNAME){
							if(0 == strncmp((char*)(attr+1), name, IFNAMSIZ)){
								done = 1;
								flags = ifi->ifi_flags;
								break;
							}
						}
						if ( attr->rta_len == 0 ){
							break;
						} else {
							attr = (struct rtattr*)((char*)attr + attr->rta_len);
						}
					}
				}
				if ( done != 0 ){ break; }
			}
		} while (done==0);
	}
	close(fd);
	return flags;
}

*/
import "C"
import (
	"errors"
	"unsafe"
	"github.com/hkwi/gopenflow/ofp4"
)

func getPortDetail(stat *ofp4.Port) error {
	fd := C.socket(C.AF_INET, C.SOCK_DGRAM, 0)
	defer C.close(fd)
	
	cname := C.CString(stat.Name)
	defer C.free(unsafe.Pointer(cname))
	
	stat.State = 0
	if flags,err := C.get_flags(cname); err!=nil {
		return err
	} else {
		live := true
		if flags & C.IFF_LOWER_UP == 0 {
			stat.State |= ofp4.OFPPS_LINK_DOWN
			live = false
		}
		if flags & C.IFF_UP == 0 {
			stat.State |= ofp4.OFPPS_BLOCKED
			live = false
		}
		if live {
			stat.State |= ofp4.OFPPS_LIVE
		}
	}
	
	ecmd := C.struct_ethtool_cmd{ cmd: C.ETHTOOL_GSET }
	if r,err := C.ethtool_cmd_call(fd, cname, &ecmd); err!=nil {
		return err
	} else if r!=0{
		return errors.New("ethtool_cmd_call error")
	} else {
		supportedConvert := map[C.__u32]uint32{
			C.SUPPORTED_10baseT_Half: ofp4.OFPPF_10MB_HD,
			C.SUPPORTED_10baseT_Full: ofp4.OFPPF_10MB_FD,
			C.SUPPORTED_100baseT_Half: ofp4.OFPPF_100MB_HD,
			C.SUPPORTED_100baseT_Full: ofp4.OFPPF_100MB_FD,
			C.SUPPORTED_1000baseT_Half: ofp4.OFPPF_1GB_HD,
			C.SUPPORTED_1000baseT_Full: ofp4.OFPPF_1GB_FD,
			C.SUPPORTED_Autoneg: ofp4.OFPPF_AUTONEG,
			C.SUPPORTED_TP: ofp4.OFPPF_COPPER,
			C.SUPPORTED_10000baseT_Full: ofp4.OFPPF_10GB_FD,
			C.SUPPORTED_Pause: ofp4.OFPPF_PAUSE,
			C.SUPPORTED_Asym_Pause: ofp4.OFPPF_PAUSE_ASYM,
			C.SUPPORTED_2500baseX_Full: ofp4.OFPPF_OTHER,
			C.SUPPORTED_1000baseKX_Full: ofp4.OFPPF_1GB_FD,
			C.SUPPORTED_10000baseKX4_Full: ofp4.OFPPF_10MB_FD,
			C.SUPPORTED_10000baseKR_Full: ofp4.OFPPF_10GB_FD,
			C.SUPPORTED_10000baseR_FEC: ofp4.OFPPF_10GB_FD,
			C.SUPPORTED_20000baseMLD2_Full: ofp4.OFPPF_OTHER,
			C.SUPPORTED_20000baseKR2_Full: ofp4.OFPPF_OTHER,
			C.SUPPORTED_40000baseKR4_Full: ofp4.OFPPF_40GB_FD,
			C.SUPPORTED_40000baseCR4_Full: ofp4.OFPPF_40GB_FD,
			C.SUPPORTED_40000baseSR4_Full: ofp4.OFPPF_40GB_FD,
			C.SUPPORTED_40000baseLR4_Full: ofp4.OFPPF_40GB_FD,
		}
		stat.Supported = 0
		for k,v := range supportedConvert {
			if ecmd.supported & k != 0 {
				stat.Supported |= v
			}
		}
		advertisedConvert := map[C.__u32]uint32{
			C.ADVERTISED_10baseT_Half: ofp4.OFPPF_10MB_HD,
			C.ADVERTISED_10baseT_Full: ofp4.OFPPF_10MB_FD,
			C.ADVERTISED_100baseT_Half: ofp4.OFPPF_100MB_HD,
			C.ADVERTISED_100baseT_Full: ofp4.OFPPF_100MB_FD,
			C.ADVERTISED_1000baseT_Half: ofp4.OFPPF_1GB_HD,
			C.ADVERTISED_1000baseT_Full: ofp4.OFPPF_1GB_FD,
			C.ADVERTISED_Autoneg: ofp4.OFPPF_AUTONEG,
			C.ADVERTISED_TP: ofp4.OFPPF_COPPER,
			C.ADVERTISED_10000baseT_Full: ofp4.OFPPF_10GB_FD,
			C.ADVERTISED_Pause: ofp4.OFPPF_PAUSE,
			C.ADVERTISED_Asym_Pause: ofp4.OFPPF_PAUSE_ASYM,
			C.ADVERTISED_2500baseX_Full: ofp4.OFPPF_OTHER,
			C.ADVERTISED_1000baseKX_Full: ofp4.OFPPF_1GB_FD,
			C.ADVERTISED_10000baseKX4_Full: ofp4.OFPPF_10MB_FD,
			C.ADVERTISED_10000baseKR_Full: ofp4.OFPPF_10GB_FD,
			C.ADVERTISED_10000baseR_FEC: ofp4.OFPPF_10GB_FD,
			C.ADVERTISED_20000baseMLD2_Full: ofp4.OFPPF_OTHER,
			C.ADVERTISED_20000baseKR2_Full: ofp4.OFPPF_OTHER,
			C.ADVERTISED_40000baseKR4_Full: ofp4.OFPPF_40GB_FD,
			C.ADVERTISED_40000baseCR4_Full: ofp4.OFPPF_40GB_FD,
			C.ADVERTISED_40000baseSR4_Full: ofp4.OFPPF_40GB_FD,
			C.ADVERTISED_40000baseLR4_Full: ofp4.OFPPF_40GB_FD,
		}
		stat.Advertised = 0
		stat.Peer = 0
		for k,v := range advertisedConvert {
			if ecmd.advertising & k != 0 {
				stat.Advertised |= v
			}
			if ecmd.lp_advertising & k != 0 {
				stat.Peer |= v
			}
		}
		
		var curr uint32
		switch C.ethtool_cmd_speed(&ecmd) {
		case C.SPEED_10:
			switch ecmd.duplex {
				case C.DUPLEX_HALF:
					curr |= ofp4.OFPPF_10MB_HD
				case C.DUPLEX_FULL:
					curr |= ofp4.OFPPF_10MB_FD
				default:
					curr |= ofp4.OFPPF_OTHER
			}
		case C.SPEED_100:
			switch ecmd.duplex {
				case C.DUPLEX_HALF:
					curr |= ofp4.OFPPF_100MB_HD
				case C.DUPLEX_FULL:
					curr |= ofp4.OFPPF_100MB_FD
				default:
					curr |= ofp4.OFPPF_OTHER
			}
		case C.SPEED_1000:
			switch ecmd.duplex {
				case C.DUPLEX_HALF:
					curr |= ofp4.OFPPF_1GB_HD
				case C.DUPLEX_FULL:
					curr |= ofp4.OFPPF_1GB_FD
				default:
					curr |= ofp4.OFPPF_OTHER
			}
		case C.SPEED_10000:
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
		stat.Curr = curr
	}
	var cHwaddrLen C.int
	if cHwaddr,err := C.get_hwaddr(fd, cname, &cHwaddrLen); err!=nil {
		return err
	} else {
		hwAddr := C.GoBytes(unsafe.Pointer(cHwaddr), cHwaddrLen)
		for i,_ := range stat.HwAddr {
			if i < int(cHwaddrLen) {
				stat.HwAddr[i] = hwAddr[i]
			}
		}
		C.free(cHwaddr)
	}
	return nil
}

