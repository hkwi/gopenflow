package ofp4sw

import (
	"github.com/hkwi/gopenflow/ofp4"
	"hash/fnv"
	"log"
	"time"
)

type flowTask struct {
	Frame
	// ref
	pipe    *Pipeline
	tableId uint8
	// frame specific actionset not in frame, because
	// 1. action set will be processed before group
	// 2. actionSet will be processed by standard instruction
	actionSet actionSet
	// results
	// output will be set only by standard action
	outputs   []outputToPort
	nextTable uint8
}

func (self *flowTask) Map() Reducable {
	// clear
	self.outputs = self.outputs[:0]
	self.nextTable = 0

	// lookup phase
	var entry *flowEntry
	var priority uint16
	table := self.pipe.getFlowTable(self.tableId)

	if table == nil {
		return self
	}
	func() {
		table.lock.Lock()
		defer table.lock.Unlock()
		table.lookupCount++
	}()
	func() {
		table.lock.RLock()
		defer table.lock.RUnlock()
		for _, prio := range table.priorities {
			entry, priority = func() (*flowEntry, uint16) {
				hasher := fnv.New32()
				prio.lock.RLock()
				defer prio.lock.RUnlock()
				for hashKey, hashPayload := range prio.hash {
					basicKey := hashKey.(OxmKeyBasic)
					basicPayload := hashPayload.(OxmValueMask)
					if buf, err := self.getValue(uint32(basicKey)); err != nil {
						log.Println(err)
						return nil, 0
					} else {
						hasher.Write(maskBytes(buf, basicPayload.Mask))
					}
				}
				if flows, ok := prio.flows[hasher.Sum32()]; ok {
					for _, flow := range flows {
						if flow.fields.Match(self.Frame) {
							return flow, prio.priority
						}
					}
				}
				return nil, 0
			}()
			if entry != nil {
				return
			}
		}
		return
	}()
	// execution
	var groups []outputToGroup
	if entry != nil {
		func() {
			table.lock.Lock()
			defer table.lock.Unlock()
			table.matchCount++
		}()
		func() {
			entry.lock.Lock()
			defer entry.lock.Unlock()
			if entry.flags&ofp4.OFPFF_NO_PKT_COUNTS == 0 {
				entry.packetCount++
			}
			if entry.flags&ofp4.OFPFF_NO_BYT_COUNTS == 0 {
				if eth, err := self.Serialized(); err != nil {
					log.Print(err)
				} else {
					entry.byteCount += uint64(len(eth))
				}
			}
			entry.touched = time.Now()
		}()

		instExp := func(pos int) error {
			for _, exp := range entry.instExp[pos] {
				if err := exp.Handler.Execute(&self.Frame, exp.Data); err != nil {
					return err
				}
			}
			return nil
		}

		if err := instExp(INST_ORDER_FIRST_TO_METER); err != nil {
			log.Print(err)
			return self
		}

		pipe := self.pipe
		if entry.instMeter != 0 {
			if meter := pipe.getMeter(entry.instMeter); meter != nil {
				if err := meter.process(&self.Frame); err != nil {
					if _, ok := err.(*packetDrop); ok {
						// no log
					} else {
						log.Println(err)
					}
					return self
				}
			}
		}

		if err := instExp(INST_ORDER_METER_TO_APPLY); err != nil {
			log.Print(err)
			return self
		}

		for _, act := range entry.instApply {
			if pout, gout, err := act.Process(&self.Frame); err != nil {
				log.Print(err)
			} else {
				if pout != nil {
					pout.tableId = self.tableId
					if priority == 0 && len(entry.fields) == 0 {
						pout.tableMiss = true
					}
					self.outputs = append(self.outputs, *pout)
				}
				if gout != nil {
					groups = append(groups, *gout)
				}
			}
			if self.isInvalid() {
				return self
			}
		}

		if err := instExp(INST_ORDER_APPLY_TO_CLEAR); err != nil {
			log.Print(err)
			return self
		}

		if entry.instClear {
			self.actionSet.Clear()
		}

		if err := instExp(INST_ORDER_CLEAR_TO_WRITE); err != nil {
			log.Print(err)
			return self
		}

		if entry.instWrite.Len() != 0 {
			self.actionSet.Write(entry.instWrite)
		}

		if err := instExp(INST_ORDER_WRITE_TO_META); err != nil {
			log.Print(err)
			return self
		}

		if entry.instMetadata != nil {
			self.metadata = entry.instMetadata.apply(self.metadata)
		}

		if err := instExp(INST_ORDER_META_TO_GOTO); err != nil {
			log.Print(err)
			return self
		}

		if entry.instGoto != 0 {
			self.nextTable = entry.instGoto
		} else {
			pouts, gouts := actionSet(self.actionSet).Process(&self.Frame)
			self.outputs = append(self.outputs, pouts...)
			groups = append(groups, gouts...)
		}

		if err := instExp(INST_ORDER_GOTO_TO_LAST); err != nil {
			log.Print(err)
			return self
		}
	}
	// process groups if any
	if len(groups) > 0 {
		self.outputs = append(self.outputs, self.pipe.groupToOutput(groups, nil)...)
	}
	return self
}

/* groupToOutput is for recursive call */
func (self Pipeline) groupToOutput(groups []outputToGroup, processed []uint32) []outputToPort {
	var result []outputToPort
	for _, gout := range groups {
		for _, gid := range processed {
			if gid == gout.groupId {
				log.Printf("group loop detected")
				return nil
			}
		}
		if group := self.getGroup(gout.groupId); group != nil {
			p, g := group.process(&gout.Frame, self)
			processed := append(processed, gout.groupId)
			result = append(result, p...)
			result = append(result, self.groupToOutput(g, processed)...)
		}
	}
	return result
}

func (self *flowTask) Reduce() {
	// packet out for a specific table execution should be in-order.
	for _, output := range self.outputs {
		if err := self.pipe.sendOutput(output); err != nil {
			log.Print(err)
		}
	}
	if self.nextTable != 0 {
		self.tableId = self.nextTable
		self.nextTable = 0
		go func() {
			self.pipe.datapath <- self
		}()
	} else {
		// atexit
	}
}
