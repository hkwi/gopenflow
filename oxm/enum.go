package oxm

const (
	OFPP_MAX        = 0xffffff00
	OFPP_UNSET      = 0xfffffff7
	OFPP_IN_PORT    = 0xfffffff8
	OFPP_TABLE      = 0xfffffff9
	OFPP_NORMAL     = 0xfffffffa
	OFPP_FLOOD      = 0xfffffffb
	OFPP_ALL        = 0xfffffffc
	OFPP_CONTROLLER = 0xfffffffd
	OFPP_LOCAL      = 0xfffffffe
	OFPP_ANY        = 0xffffffff
)

const (
	OFPVID_PRESENT = 0x1000
	OFPVID_NONE    = 0x0000
)

const (
	OFPIEH_NONEXT = 1 << iota
	OFPIEH_ESP
	OFPIEH_AUTH
	OFPIEH_DEST
	OFPIEH_FRAG
	OFPIEH_ROUTER
	OFPIEH_HOP
	OFPIEH_UNREP
	OFPIEH_UNSEQ
)
