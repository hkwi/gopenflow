package main

import (
	"fmt"
	"github.com/hkwi/gopenflow/ofp4"
	"strconv"
	"strings"
)

func actionB2W(action ofp4.ActionHeader) (string, error) {
	var ret []string
	for _,act := range action.Iter() {
		var ext string
		switch act.Type() {
		case ofp4.OFPAT_OUTPUT:
			a:=ofp4.ActionOutput(act)
			switch a.Port() {
			case ofp4.OFPP_CONTROLLER:
				ext = "output=CONTROLLER"
			default:
				ext = fmt.Sprintf("output=%d",
					a.Port())
			}
			if a.MaxLen() != ofp4.OFPCML_NO_BUFFER {
				ext += fmt.Sprintf("/%d",
					a.MaxLen())
			}
		}
		if len(ext) > 0 {
			ret = append(ret, ext)
		}
	}
	return strings.Join(ret, ","), nil
}

var ActionW2B = map[string]func(string) ([]byte, error){
	"output": func(arg string) ([]byte, error) {
		var port uint32
		var maxLen = uint16(ofp4.OFPCML_NO_BUFFER)
		p := strings.SplitN(arg, "/", 2)
		if v, ok := portNames[strings.ToUpper(p[0])]; ok {
			port = v
		} else if v, err := strconv.ParseUint(p[0], 0, 32); err != nil {
			return nil, err
		} else {
			port = uint32(v)
		}
		if len(p) > 1 {
			if n, err := strconv.ParseUint(p[1], 0, 16); err != nil {
				return nil, err
			} else {
				maxLen = uint16(n)
			}
		}
		return ofp4.MakeActionOutput(port, maxLen), nil
	},
	"copy_ttl_out": action_unsupported,
	"copy_ttl_in":  action_unsupported,
	"set_mpls_ttl": action_unsupported,
	"dec_mpls_ttl": action_unsupported,
	"push_vlan":    action_unsupported,
	"pop_vlan":     action_unsupported,
	"push_mpls":    action_unsupported,
	"pop_mpls":     action_unsupported,
	"set_queue":    action_unsupported,
	"group":        action_unsupported,
	"set_nw_ttl":   action_unsupported,
	"dec_nw_ttl":   action_unsupported,
	"set_field":    action_unsupported,
	"push_pbb":     action_unsupported,
	"pop_pbb":      action_unsupported,
}

func action_unsupported(arg string) ([]byte, error) {
	return nil, fmt.Errorf("unsupported")
}
