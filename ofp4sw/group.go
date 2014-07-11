package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
	"math"
)

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
	commands  chan func()
	groupType uint8
	buckets   []bucket
}

func (g *group) process(data *frame, p Pipeline) flowEntryResult {
	ch := make(chan flowEntryResult)
	g.commands <- func() {
		ch <- func() (result flowEntryResult) {
			switch g.groupType {
			case ofp4.OFPGT_ALL, ofp4.OFPGT_INDIRECT:
				for _, b := range g.buckets {
					fdata := data.clone()
					ret := actionSet(b.actionSet).process(fdata, p)
					result.outputs = append(result.outputs, ret.outputs...)
					result.groups = append(result.groups, ret.groups...)
					data.errors = append(data.errors, fdata.errors...)
				}
			case ofp4.OFPGT_SELECT:
				weightSum := float64(0)
				for _, b := range g.buckets {
					weightSum += float64(b.weight)
				}
				step := weightSum * float64(data.hash()) / float64(math.MaxUint32)
				weightSum = 0.0
				for _, b := range g.buckets {
					weightSum += float64(b.weight)
					if step <= weightSum {
						fdata := data.clone()
						ret := actionSet(b.actionSet).process(fdata, p)
						result.outputs = append(result.outputs, ret.outputs...)
						result.groups = append(result.groups, ret.groups...)
						data.errors = append(data.errors, fdata.errors...)
						break
					}
				}
			case ofp4.OFPGT_FF:
				for _, b := range g.buckets {
					live := false
					if b.watchPort != ofp4.OFPP_ANY {
						ch := make(chan bool)
						p.commands <- func() {
							ch <- func() bool {
								if p.watchPort(b.watchPort) {
									return true
								}
								return false
							}()
						}
						if <-ch {
							live = true
						}
					}
					if b.watchGroup != ofp4.OFPG_ANY {
						ch := make(chan bool)
						p.commands <- func() {
							ch <- func() bool {
								if p.watchGroup(b.watchGroup) {
									return true
								}
								return false
							}()
						}
						if <-ch {
							live = true
						}
					}
					if live {
						fdata := data.clone()
						ret := actionSet(b.actionSet).process(fdata, p)
						result.outputs = append(result.outputs, ret.outputs...)
						result.groups = append(result.groups, ret.groups...)
						data.errors = append(data.errors, fdata.errors...)
						break
					}
				}
			}
			return
		}()
		close(ch)
	}
	return <-ch
}

func (pipe *Pipeline) addGroup(req ofp4.GroupMod) error {
	buckets := make([]bucket, len(req.Buckets))
	for i, _ := range buckets {
		buckets[i].fromMessage(req.Buckets[i])
	}
	grp := group{
		commands:  make(chan func()),
		groupType: req.Type,
		buckets:   buckets,
	}
	ch := make(chan error)
	pipe.commands <- func() {
		ch <- func() error {
			if _, exists := pipe.groups[req.GroupId]; exists {
				return &ofp4.Error{ofp4.OFPET_GROUP_MOD_FAILED, ofp4.OFPGMFC_GROUP_EXISTS, nil}
			} else {
				pipe.groups[req.GroupId] = &grp
			}
			return nil
		}()
		close(ch)
	}
	if err := <-ch; err != nil {
		return err
	} else {
		go func() {
			for cmd := range grp.commands {
				if cmd != nil {
					cmd()
				} else {
					break
				}
			}
		}()
	}
	return nil
}

func (pipe *Pipeline) deleteGroupInside(groupId uint32) error {
	if _, exists := pipe.groups[groupId]; exists {
		for _, chainId := range pipe.groupChains(groupId, nil) {
			if grp, exists := pipe.groups[chainId]; exists {
				delete(pipe.groups, chainId)
				grp.commands <- nil
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
