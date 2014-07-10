package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
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
			case ofp4.OFPGT_ALL:
				for _, b := range g.buckets {
					fdata := data.clone()
					ret := actionSet(b.actionSet).process(fdata, p)
					result.outputs = append(result.outputs, ret.outputs...)
					result.groups = append(result.groups, ret.groups...)
					data.errors = append(data.errors, fdata.errors...)
				}
				// XXX: more to implement
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

func (pipe *Pipeline) deleteGroup(req ofp4.GroupMod) error {
	ch := make(chan error)
	pipe.commands <- func() {
		ch <- func() error {
			if grp, exists := pipe.groups[req.GroupId]; exists {
				delete(pipe.groups, req.GroupId)
				grp.commands <- nil
			} else {
				return &ofp4.Error{ofp4.OFPET_GROUP_MOD_FAILED, ofp4.OFPGMFC_GROUP_EXISTS, nil}
			}
			return nil
		}()
		close(ch)
	}
	return <-ch
}
