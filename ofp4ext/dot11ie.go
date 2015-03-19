package ofp4ext

type Dot11InformationElement struct {
	Id   uint8
	Info []byte
}

func (self Dot11InformationElement) MarshalBinary() ([]byte, error) {
	length := len(self.Info)
	buf := make([]byte, 2+length)
	buf[0] = self.Id
	buf[1] = uint8(length)
	copy(buf[2:], self.Info)
	return buf, nil
}

func (self *Dot11InformationElement) UnmarshalBinary(buf []byte) error {
	self.Id = buf[0]
	self.Info = buf[2 : 2+int(buf[1])]
	return nil
}

type Dot11InformationElementList []Dot11InformationElement

func (self Dot11InformationElementList) MarshalBinary() ([]byte, error) {
	var ret []byte
	for _, el := range []Dot11InformationElement(self) {
		if buf, err := el.MarshalBinary(); err != nil {
			return nil, err
		} else {
			ret = append(ret, buf...)
		}
	}
	return ret, nil
}

func (self *Dot11InformationElementList) UnmarshalBinary(buf []byte) error {
	var ret []Dot11InformationElement
	for len(buf) > 2 {
		el := Dot11InformationElement{}
		if err := el.UnmarshalBinary(buf); err != nil {
			return err
		}
		ret = append(ret, el)
	}
	*self = Dot11InformationElementList(ret)
	return nil
}
