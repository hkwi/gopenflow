package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
	"math"
	"sync"
)

type bucket struct {
	weight     uint16
	watchPort  uint32
	watchGroup uint32
	actionSet  actionSet
}

func (self bucket) MarshalBinary() ([]byte, error) {
	if actions, err := self.actionSet.MarshalBinary(); err != nil {
		return nil, err
	} else {
		return ofp4.MakeBucket(self.weight, self.watchPort, self.watchGroup, actions), nil
	}
}

func (self *bucket) UnmarshalBinary(data []byte) error {
	msg := ofp4.Bucket(data)
	self.weight = msg.Weight()
	self.watchPort = msg.WatchPort()
	self.watchGroup = msg.WatchGroup()
	self.actionSet = makeActionSet()

	if err := self.actionSet.UnmarshalBinary(msg.Actions()); err != nil {
		return err
	}
	return nil
}

type bucketList []bucket

func (self *bucketList) UnmarshalBinary(data []byte) error {
	var buckets []bucket
	for cur := 0; cur < len(data); {
		msg := ofp4.Bucket(data[cur:])
		var b bucket
		if err := b.UnmarshalBinary(msg); err != nil {
			return err
		}
		buckets = append(buckets, b)
		cur += msg.Len()
	}
	*self = buckets
	return nil
}

func (self bucketList) MarshalBinary() ([]byte, error) {
	var buckets []byte
	for _, b := range []bucket(self) {
		if bin, err := b.MarshalBinary(); err != nil {
			return nil, err
		} else {
			buckets = append(buckets, bin...)
		}
	}
	return buckets, nil
}

type group struct {
	lock      *sync.RWMutex
	groupType uint8
	buckets   []bucket
}

func (g *group) process(data *Frame, pipe Pipeline) (pouts []outputToPort, gouts []outputToGroup) {
	buckets := make([]bucket, 0, len(g.buckets))
	func() {
		g.lock.RLock()
		defer g.lock.RUnlock()
		buckets = append(buckets, g.buckets...)
	}()

	switch g.groupType {
	case ofp4.OFPGT_ALL, ofp4.OFPGT_INDIRECT:
		for _, b := range buckets {
			p, g := actionSet(b.actionSet).Process(data)
			pouts = append(pouts, p...)
			gouts = append(gouts, g...)
		}
	case ofp4.OFPGT_SELECT:
		weightSum := float64(0)
		for _, b := range buckets {
			weightSum += float64(b.weight)
		}
		step := weightSum * float64(data.hash()) / float64(math.MaxUint32)
		weightSum = 0.0
		for _, b := range buckets {
			weightSum += float64(b.weight)
			if step <= weightSum {
				p, g := actionSet(b.actionSet).Process(data)
				pouts = append(pouts, p...)
				gouts = append(gouts, g...)
				break
			}
		}
	case ofp4.OFPGT_FF:
		for _, b := range buckets {
			live := false
			if b.watchPort != ofp4.OFPP_ANY {
				live = func() bool {
					pipe.lock.RLock()
					defer pipe.lock.RUnlock()

					if pipe.watchPort(b.watchPort) {
						return true
					}
					return false
				}()
			}
			if b.watchGroup != ofp4.OFPG_ANY {
				live = func() bool {
					pipe.lock.RLock()
					defer pipe.lock.RUnlock()

					if pipe.watchGroup(b.watchGroup) {
						return true
					}
					return false
				}()
			}
			if live {
				fdata := data.clone()
				p, g := actionSet(b.actionSet).Process(&fdata)
				pouts = append(pouts, p...)
				gouts = append(gouts, g...)
				break
			}
		}
	}
	return
}

func (pipe *Pipeline) addGroup(req ofp4.GroupMod) error {
	var buckets []bucket
	for _, msg := range req.Buckets().Iter() {
		var b bucket
		if err := b.UnmarshalBinary(msg); err != nil {
			return err
		}
		buckets = append(buckets, b)
	}

	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	if _, exists := pipe.groups[req.GroupId()]; exists {
		return ofp4.MakeErrorMsg(ofp4.OFPET_GROUP_MOD_FAILED, ofp4.OFPGMFC_GROUP_EXISTS)
	} else {
		pipe.groups[req.GroupId()] = &group{
			lock:      &sync.RWMutex{},
			groupType: req.Type(),
			buckets:   buckets,
		}
	}
	return nil
}

func (pipe *Pipeline) deleteGroupInside(groupId uint32) error {
	if _, exists := pipe.groups[groupId]; exists {
		for _, chainId := range pipe.groupChains(groupId, nil) {
			if _, exists := pipe.groups[chainId]; exists {
				delete(pipe.groups, chainId)
			}
			pipe.filterFlowsInside(flowFilter{
				opUnregister: true,
				outPort:      ofp4.OFPP_ANY,
				outGroup:     chainId,
			})
		}
	} else {
		return ofp4.MakeErrorMsg(ofp4.OFPET_GROUP_MOD_FAILED, ofp4.OFPGMFC_GROUP_EXISTS)
	}
	return nil
}

// call within pipeline transaction
func (pipe Pipeline) groupChains(groupId uint32, seen []uint32) []uint32 {
	seen = append(seen, groupId)
	for chainId, g := range pipe.groups {
		for _, b := range g.buckets {
			chains := func() bool {
				if b.watchGroup != 0 && b.watchGroup != ofp4.OFPG_ANY {
					if b.watchGroup == groupId {
						return true
					}
				}
				if act, ok := b.actionSet.hash[uint16(ofp4.OFPAT_GROUP)]; ok {
					if act.(actionGroup).GroupId == groupId {
						return true
					}
				}
				return false
			}()
			if chains {
				seen = func() []uint32 {
					for _, idx := range seen {
						if idx == chainId {
							return seen
						}
					}
					return pipe.groupChains(chainId, seen)
				}()
			}
		}
	}
	return seen
}
