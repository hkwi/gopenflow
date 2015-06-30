package ofp4ext

import (
	"github.com/hkwi/gopenflow/ofp4sw"
	"github.com/hkwi/gopenflow/oxm"
	"testing"
)

func TestDot11(t *testing.T) {
	k := OxmKeyStratos{
		Type:  oxm.STROXM_BASIC_DOT11,
		Field: oxm.STRATOS_OXM_FIELD_BASIC,
	}
	vZero := ofp4sw.OxmValueMask{Value: []byte{0}}
	vOne := ofp4sw.OxmValueMask{Value: []byte{1}}
	vTwo := ofp4sw.OxmValueMask{Value: []byte{2}}
	mZero := map[ofp4sw.OxmKey]ofp4sw.OxmPayload{k: vZero}
	mOne := map[ofp4sw.OxmKey]ofp4sw.OxmPayload{k: vOne}
	mTwo := map[ofp4sw.OxmKey]ofp4sw.OxmPayload{k: vTwo}

	stratos := StratosOxm{}
	if ok, err := stratos.Match(ofp4sw.Frame{}, k, vZero); err != nil || !ok {
		t.Errorf("pkt empty / match zero")
	}
	if ok, err := stratos.Match(ofp4sw.Frame{Oob: mZero}, k, vZero); err != nil || !ok {
		t.Errorf("pkt zero / match zero")
	}
	if ok, err := stratos.Match(ofp4sw.Frame{Oob: mOne}, k, vZero); err != nil || !ok {
		t.Errorf("pkt one / match zero")
	}
	if ok, err := stratos.Match(ofp4sw.Frame{Oob: mTwo}, k, vZero); err != nil || !ok {
		t.Errorf("pkt two / match zero")
	}

	if ok, err := stratos.Match(ofp4sw.Frame{}, k, vOne); err != nil || ok {
		t.Errorf("pkt empty / match one")
	}
	if ok, err := stratos.Match(ofp4sw.Frame{Oob: mZero}, k, vOne); err != nil || ok {
		t.Errorf("pkt zero / match one")
	}
	if ok, err := stratos.Match(ofp4sw.Frame{Oob: mOne}, k, vOne); err != nil || !ok {
		t.Errorf("pkt one / match one")
	}
	if ok, err := stratos.Match(ofp4sw.Frame{Oob: mTwo}, k, vOne); err != nil || ok {
		t.Errorf("pkt two / match one")
	}

	if ok, err := stratos.Match(ofp4sw.Frame{}, k, vTwo); err != nil || !ok {
		t.Errorf("pkt empty / match two")
	}
	if ok, err := stratos.Match(ofp4sw.Frame{Oob: mZero}, k, vTwo); err != nil || !ok {
		t.Errorf("pkt zero / match two")
	}
	if ok, err := stratos.Match(ofp4sw.Frame{Oob: mOne}, k, vTwo); err != nil || ok {
		t.Errorf("pkt one / match two")
	}
	if ok, err := stratos.Match(ofp4sw.Frame{Oob: mTwo}, k, vTwo); err != nil || !ok {
		t.Errorf("pkt two / match two")
	}
}
