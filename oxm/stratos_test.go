package oxm

import (
	"testing"
)

func TestDot11Strings(t *testing.T) {
	tokens := []string{
		"dot11=0",
		"dot11=1",
		"dot11_frame_ctrl=0000",
		"dot11_frame_ctrl=0000/fff0",
		"dot11_addr1=ff:ff:ff:ff:ff:ff",
		"dot11_addr1=01:00:00:00:00:00/01:00:00:00:00:00", // broadcast,multicast
		"dot11_ssid=stratos1",
		"dot11_ssid=stratos/ffffffffffffff00000000",
		"dot11_action_category=03",
		"dot11_action_category=7f00e04d", // vendor action
		"dot11_public_action=10",         // GAS initial
		"dot11_tag=0",
		"dot11_tag_vendor=00e04d",
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
}

func TestRadiotapStrings(t *testing.T) {
	tokens := []string{
		"radiotap_tsft=1",
		"radiotap_flags=0x00",
		"radiotap_rate=500.0K",
		"radiotap_rate=11.0M",
		"radiotap_channel=2412:0x1234",
		"radiotap_channel=2412:0x1234/:0x00ff",
		"radiotap_fhss=0102",
		"radiotap_dbm_antsignal=-80",
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
}
