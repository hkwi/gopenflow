package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
	"math"
	"sync"
)

type groupOut struct {
	groupId uint32
	data    frame
}

type bucket struct {
	weight     uint16
	watchPort  uint32
	watchGroup uint32
	actionSet  map[uint16]action // Ignore Actions
}

func (b *bucket) fromMessage(msg ofp4.Bucket) error {
	b.weight = msg.Weight
	b.watchPort = msg.WatchPort
	b.watchGroup = msg.WatchGroup

	var actions actionSet
	if err := actions.fromMessage(msg.Actions); err != nil {
		return err
	} else {
		b.actionSet = map[uint16]action(actions)
	}
	return nil
}

func (b bucket) toMessage() (ofp4.Bucket, error) {
	var msg ofp4.Bucket
	if actions, err := actionSet(b.actionSet).toMessage(); err != nil {
		return msg, err
	} else {
		msg.Weight = b.weight
		msg.WatchPort = b.watchPort
		msg.WatchGroup = b.watchGroup
		msg.Actions = actions
		return msg, nil
	}
}

type group struct {
	lock      *sync.Mutex
	groupType uint8
	buckets   []bucket
}

func (g *group) process(data *frame, pipe Pipeline) flowEntryResult {
	var result flowEntryResult

	buckets := make([]bucket, 0, len(g.buckets))
	func() {
		g.lock.Lock()
		defer g.lock.Unlock()
		buckets = append(buckets, g.buckets...)
	}()

	switch g.groupType {
	case ofp4.OFPGT_ALL, ofp4.OFPGT_INDIRECT:
		for _, b := range buckets {
			fdata := data.clone()
			ret := actionSet(b.actionSet).process(fdata, pipe)
			result.outputs = append(result.outputs, ret.outputs...)
			result.groups = append(result.groups, ret.groups...)
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
				fdata := data.clone()
				ret := actionSet(b.actionSet).process(fdata, pipe)
				result.outputs = append(result.outputs, ret.outputs...)
				result.groups = append(result.groups, ret.groups...)
				break
			}
		}
	case ofp4.OFPGT_FF:
		for _, b := range buckets {
			live := false
			if b.watchPort != ofp4.OFPP_ANY {
				live = func() bool {
					pipe.lock.Lock()
					defer pipe.lock.Unlock()

					if pipe.watchPort(b.watchPort) {
						return true
					}
					return false
				}()
			}
			if b.watchGroup != ofp4.OFPG_ANY {
				live = func() bool {
					pipe.lock.Lock()
					defer pipe.lock.Unlock()

					if pipe.watchGroup(b.watchGroup) {
						return true
					}
					return false
				}()
			}
			if live {
				fdata := data.clone()
				ret := actionSet(b.actionSet).process(fdata, pipe)
				result.outputs = append(result.outputs, ret.outputs...)
				result.groups = append(result.groups, ret.groups...)
				break
			}
		}
	}
	return result
}

func (pipe *Pipeline) addGroup(req ofp4.GroupMod) error {
	buckets := make([]bucket, len(req.Buckets))
	for i, _ := range buckets {
		buckets[i].fromMessage(req.Buckets[i])
	}

	pipe.lock.Lock()
	defer pipe.lock.Unlock()

	if _, exists := pipe.groups[req.GroupId]; exists {
		return &ofp4.Error{ofp4.OFPET_GROUP_MOD_FAILED, ofp4.OFPGMFC_GROUP_EXISTS, nil}
	} else {
		pipe.groups[req.GroupId] = &group{
			lock:      &sync.Mutex{},
			groupType: req.Type,
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
		return &ofp4.Error{ofp4.OFPET_GROUP_MOD_FAILED, ofp4.OFPGMFC_GROUP_EXISTS, nil}
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
				if act, ok := b.actionSet[ofp4.OFPAT_GROUP]; ok {
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
