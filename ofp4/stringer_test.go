package ofp4

import (
	"fmt"
	"testing"
)

func TestParseAction(t *testing.T) {
	strs := []string{
		"output=10",
		"output=5:0xffe4",
		"set_mpls_ttl=3",
		"set_nw_ttl=2",
		"push_vlan=0x8100",
		"push_mpls=0x8847",
		"pop_mpls=0x0800",
		"push_pbb=0x88e7",
		"group=7",
		"set_queue=9",
		"set_eth_src=01:02:03:04:05:06",
		"set_ipv4_dst=192.168.1.1",
	}
	for _, s := range strs {
		if buf, eatLen, err := ParseAction(s); err != nil {
			t.Error(err)
		} else if eatLen != len(s) {
			t.Error("no consume")
		} else if s != fmt.Sprintf("%v", ActionHeader(buf)) {
			t.Errorf("encode decode error %s", s)
		}
	}
}

func TestParseFlowMod(t *testing.T) {
	strs := []string{
		"table=2,priority=8,cookie=0x5",
		"table=2,priority=8,cookie=0x5,@apply,output=1,@meter=1",
		"table=2,priority=8,cookie=0x5,in_port=1,eth_dst=ff:ff:ff:ff:ff:ff,@apply,output=1,@meter=1",
	}
	for _, s := range strs {
		if buf, eatLen, err := parseFlowMod(s); err != nil {
			t.Error(err)
		} else if eatLen != len(s) {
			t.Error("no consume")
		} else if s != fmt.Sprintf("%v", FlowMod(buf)) {
			t.Errorf("encode decode error %s", s)
		}
	}
}

func TestParseFlowStats(t *testing.T) {
	strs := []string{
		"table=2,priority=8,cookie=0x5",
		"table=2,priority=8,cookie=0x5,@apply,output=1,@meter=1",
		"table=2,priority=8,cookie=0x5,in_port=1,eth_dst=ff:ff:ff:ff:ff:ff,@apply,output=1,@meter=1",
	}
	for _, s := range strs {
		if buf, eatLen, err := parseFlowStats(s); err != nil {
			t.Error(err)
		} else if eatLen != len(s) {
			t.Error("no consume")
		} else if s != fmt.Sprintf("%v", FlowStats(buf)) {
			t.Logf("%v", FlowStats(buf))
			t.Errorf("encode decode error %s", s)
		}
	}
}
