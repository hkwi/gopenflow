package oxm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestStrings(t *testing.T) {
	tokens := []string{
		"in_port=any",
		"in_port=10",
		"in_phy_port=10",
		"metadata=0x5/0xff",
		"eth_src=00:00:00:00:00:00",
		"eth_src=00:00:00:00:00:00/01:00:00:00:00:00",
		"ipv4_src=192.168.0.1",
		"ipv4_src=192.168.0.1/255.255.255.0",
		"ipv4_src=192.168.0.1/255.0.255.255",
		"ipv6_src=::/ffff::",
		"vlan_vid=0x5",
		"vlan_vid=0x1000/0x1000",
		"pbb_isid=0x5",
		"packet_type=0x2:0x3",
	}
	for _, token := range tokens {
		if o, n, err := ParseOne(token); err != nil {
			t.Error(err)
		} else if n != len(token) {
			t.Errorf("consumed length error %d for %s len=%d", n, token, len(token))
		} else if token != Oxm(o).String() {
			t.Errorf("stringer %s != %s", token, Oxm(o).String())
		}
	}
	all := strings.Join(tokens, ",")
	if o, _, err := Parse(all); err != nil {
		t.Error(err)
	} else {
		var v []string
		for _, x := range Oxm(o).Iter() {
			v = append(v, fmt.Sprintf("%v", x))
		}
		if all != strings.Join(v, ",") {
			t.Error("join failed")
		}
	}
}

func TestToOxm(t *testing.T) {
	token := "ipv4_src=192.168.0.1/24"
	suffix := []byte{192, 168, 0, 1, 255, 255, 255, 0}
	if o, n, err := ParseOne(token); err != nil {
		t.Error(err)
	} else if n != len(token) {
		t.Errorf("consumed length error %d for %s len=%d", n, token, len(token))
	} else if !bytes.Equal(o[len(o)-len(suffix):], suffix) {
		t.Errorf("stringer suffix error %v %v", o[len(o)-len(suffix):], suffix)
	}
}
