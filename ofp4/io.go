package ofp4

import (
	"encoding/binary"
	"errors"
)

func parseMatch(input []byte) (OfpMatchIf, error) {
	length := binary.BigEndian.Uint16(input[2:4])
	return &OfpMatchEx{OfpMatch{binary.BigEndian.Uint16(input[0:2]), length},
		input[4:length]}, nil
}

func parseAction(input []byte) (OfpActionIf, error) {
	atype := binary.BigEndian.Uint16(input[0:2])
	length := binary.BigEndian.Uint16(input[2:4])
	switch atype {
	default:
		return nil, errors.New("unknown action type")
	case OFPAT_COPY_TTL_OUT,
		OFPAT_COPY_TTL_IN,
		OFPAT_DEC_MPLS_TTL,
		OFPAT_POP_VLAN,
		OFPAT_DEC_NW_TTL,
		OFPAT_POP_PBB:
		return &OfpActionHeader{Type: atype,
			Len: length}, nil
	case OFPAT_OUTPUT:
		return &OfpActionOutput{Type: atype,
			Len:    length,
			Port:   binary.BigEndian.Uint32(input[4:8]),
			MaxLen: binary.BigEndian.Uint16(input[8:10])}, nil
	case OFPAT_SET_MPLS_TTL:
		return &OfpActionMplsTtl{Type: atype,
			Len:     length,
			MplsTtl: input[4]}, nil
	case OFPAT_PUSH_VLAN,
		OFPAT_PUSH_MPLS,
		OFPAT_PUSH_PBB:
		return &OfpActionPush{Type: atype,
			Len:       length,
			Ethertype: binary.BigEndian.Uint16(input[4:6])}, nil
	case OFPAT_POP_MPLS:
		return &OfpActionPopMpls{Type: atype,
			Len:       length,
			Ethertype: binary.BigEndian.Uint16(input[4:6])}, nil
	case OFPAT_SET_QUEUE:
		return &OfpActionSetQueue{atype,
			length,
			binary.BigEndian.Uint32(input[4:8])}, nil
	case OFPAT_GROUP:
		return &OfpActionGroup{atype,
			length,
			binary.BigEndian.Uint32(input[4:8])}, nil
	case OFPAT_SET_NW_TTL:
		return &OfpActionNwTtl{Type: atype,
			Len:   length,
			NwTtl: input[4]}, nil
	case OFPAT_SET_FIELD:
		return &OfpActionSetFieldEx{OfpActionSetField{atype, length},
			input[4:length]}, nil
	case OFPAT_EXPERIMENTER:
		return &OfpActionExperimenterHeaderEx{OfpActionExperimenterHeader{atype,
			length,
			binary.BigEndian.Uint32(input[4:8])},
			input[8:length]}, nil
	}
}

func parseInstruction(input []byte) (OfpInstructionIf, error) {
	itype := binary.BigEndian.Uint16(input[0:2])
	length := binary.BigEndian.Uint16(input[2:4])
	switch itype {
	default:
		return nil, errors.New("unknown instruction type")
	case OFPIT_GOTO_TABLE:
		return &OfpInstructionGotoTable{Type: itype,
			Len:     length,
			TableId: input[4]}, nil
	case OFPIT_WRITE_METADATA:
		return &OfpInstructionWriteMetadata{Type: itype,
			Len:          length,
			Metadata:     binary.BigEndian.Uint64(input[8:16]),
			MetadataMask: binary.BigEndian.Uint64(input[16:24])}, nil
	case OFPIT_WRITE_ACTIONS,
		OFPIT_APPLY_ACTIONS,
		OFPIT_CLEAR_ACTIONS:
		var actions []OfpActionIf
		for cur := 8; cur < int(length); {
			if action, err := parseAction(input[cur:]); err != nil {
				return nil, err
			} else {
				actions = append(actions, action)
				cur += int(action.GetLen())
			}
		}
		return &OfpInstructionActionsEx{OfpInstructionActions{Type: itype,
			Len: length},
			actions}, nil
	case OFPIT_METER:
		return &OfpInstructionMeter{itype,
			length,
			binary.BigEndian.Uint32(input[4:8])}, nil
	case OFPIT_EXPERIMENTER:
		return &OfpInstructionExperimenterEx{OfpInstructionExperimenter{itype,
			length,
			binary.BigEndian.Uint32(input[4:8])},
			input[4:length]}, nil
	}
}

func parseBucket(input []byte) (OfpBucketIf, error) {
	length := binary.BigEndian.Uint16(input[0:2])
	var actions []OfpActionIf
	for cur := 16; cur < int(length); {
		if action, err := parseAction(input[cur:]); err != nil {
			return nil, err
		} else {
			actions = append(actions, action)
			cur += int(action.GetLen())
		}
	}
	return &OfpBucketEx{OfpBucket{Len: length,
		Weight:     binary.BigEndian.Uint16(input[2:4]),
		WatchPort:  binary.BigEndian.Uint32(input[4:8]),
		WatchGroup: binary.BigEndian.Uint32(input[8:12])},
		actions}, nil
}

func parseTableFeatures(input []byte) (*OfpTableFeaturesEx, error) {
	length := binary.BigEndian.Uint16(input[0:2])

	var name [32]byte
	for i, _ := range name {
		name[i] = input[8+i]
	}

	var properties []OfpTableFeaturePropIf
	for cur := 64; cur < int(length); {
		if property, err := parseTableFeatureProperty(input[cur:]); err != nil {
			return nil, err
		} else {
			properties = append(properties, property)
			cur += align8(int(property.GetLength()))
		}
	}
	return &OfpTableFeaturesEx{
		OfpTableFeatures{
			Length:        length,
			TableId:       input[2],
			Name:          name,
			MetadataMatch: binary.BigEndian.Uint64(input[40:48]),
			MetadataWrite: binary.BigEndian.Uint64(input[48:56]),
			Config:        binary.BigEndian.Uint32(input[56:60]),
			MaxEntries:    binary.BigEndian.Uint32(input[60:64]),
		},
		properties,
	}, nil
}

func parseTableFeatureProperty(input []byte) (OfpTableFeaturePropIf, error) {
	pType := binary.BigEndian.Uint16(input[0:2])
	length := binary.BigEndian.Uint16(input[2:4])
	switch pType {
	default:
		return nil, errors.New("unknown OFPTFPT_")
	case OFPTFPT_INSTRUCTIONS,
		OFPTFPT_INSTRUCTIONS_MISS:
		var instructions []OfpInstructionIf
		for cur := 4; cur < int(length); {
			if instruction, err := parseInstruction(input[cur:]); err != nil {
				return nil, err
			} else {
				instructions = append(instructions, instruction)
				cur += int(instruction.GetLen())
			}
		}
		return &OfpTableFeaturePropInstructionsEx{OfpTableFeaturePropInstructions{pType,
			length},
			instructions}, nil
	case OFPTFPT_NEXT_TABLES,
		OFPTFPT_NEXT_TABLES_MISS:
		return &OfpTableFeaturePropNextTablesEx{OfpTableFeaturePropNextTables{pType,
			length},
			input[4:length]}, nil
	case OFPTFPT_WRITE_ACTIONS,
		OFPTFPT_WRITE_ACTIONS_MISS,
		OFPTFPT_APPLY_ACTIONS,
		OFPTFPT_APPLY_ACTIONS_MISS:
		var actions []OfpActionIf
		for cur := 4; cur < int(length); {
			if action, err := parseAction(input[4:]); err != nil {
				return nil, err
			} else {
				actions = append(actions, action)
				cur += int(action.GetLen())
			}
		}
		return &OfpTableFeaturePropActionsEx{
			OfpTableFeaturePropActions{
				pType,
				length,
			},
			actions,
		}, nil
	case OFPTFPT_MATCH,
		OFPTFPT_WILDCARDS,
		OFPTFPT_WRITE_SETFIELD,
		OFPTFPT_WRITE_SETFIELD_MISS:
		oxmIds := make([]uint32, length/4-1)
		for i, _ := range oxmIds {
			off := 4 + i*4
			oxmIds[i] = binary.BigEndian.Uint32(input[off : 4+off])
		}
		return &OfpTableFeaturePropOxmEx{
			OfpTableFeaturePropOxm{
				pType,
				length,
			},
			oxmIds,
		}, nil
	case OFPTFPT_EXPERIMENTER,
		OFPTFPT_EXPERIMENTER_MISS:
		return &OfpTableFeaturePropExperimenterEx{
			OfpTableFeaturePropExperimenter{
				pType,
				length,
				binary.BigEndian.Uint32(input[4:8]),
				binary.BigEndian.Uint32(input[8:12]),
			},
			input[12:length],
		}, nil
	}
}

func parseFlowStats(input []byte) (*OfpFlowStatsEx, error) {
	length := binary.BigEndian.Uint16(input[0:2])
	match, err := parseMatch(input[48:])
	if err != nil {
		return nil, err
	}

	var instructions []OfpInstructionIf
	for cur := 48 + align8(int(match.GetLength())); cur < int(length); {
		if instruction, err := parseInstruction(input[cur:]); err != nil {
			return nil, err
		} else {
			instructions = append(instructions, instruction)
			cur += int(instruction.GetLen())
		}
	}

	return &OfpFlowStatsEx{
		length,
		input[2],
		binary.BigEndian.Uint32(input[4:8]),
		binary.BigEndian.Uint32(input[8:12]),
		binary.BigEndian.Uint16(input[12:14]),
		binary.BigEndian.Uint16(input[14:16]),
		binary.BigEndian.Uint16(input[16:18]),
		binary.BigEndian.Uint16(input[18:20]),
		binary.BigEndian.Uint64(input[24:32]),
		binary.BigEndian.Uint64(input[32:40]),
		binary.BigEndian.Uint64(input[40:48]),
		match,
		instructions,
	}, nil
}

func parseQueueProp(input []byte) (OfpQueuePropIf, error) {
	property := binary.BigEndian.Uint16(input[0:2])
	length := binary.BigEndian.Uint16(input[2:4])
	switch property {
	default:
		return nil, errors.New("unknown OFPQT_")
	case OFPQT_MIN_RATE:
		return &OfpQueuePropMinRate{
			PropHeader: OfpQueuePropHeader{
				Property: property,
				Len:      length,
			},
			Rate: binary.BigEndian.Uint16(input[8:10]),
		}, nil
	case OFPQT_MAX_RATE:
		return &OfpQueuePropMaxRate{
			PropHeader: OfpQueuePropHeader{
				Property: property,
				Len:      length,
			},
			Rate: binary.BigEndian.Uint16(input[8:10]),
		}, nil
	case OFPQT_EXPERIMENTER:
		return &OfpQueuePropExperimenterEx{
			OfpQueuePropExperimenter{
				PropHeader: OfpQueuePropHeader{
					Property: property,
					Len:      length,
				},
				Experimenter: binary.BigEndian.Uint32(input[8:12]),
			},
			input[16:length],
		}, nil
	}
}

func Parse(input []byte) (interface{}, error) {
	header := OfpHeader{input[0],
		input[1],
		binary.BigEndian.Uint16(input[2:4]),
		binary.BigEndian.Uint32(input[4:8])}
	if header.Version != 4 {
		return nil, errors.New("openflow version mismatch")
	}

	switch header.Type {
	default:
		return nil, errors.New("unknown OFPT")
	case OFPT_FEATURES_REQUEST,
		OFPT_GET_CONFIG_REQUEST,
		OFPT_BARRIER_REQUEST,
		OFPT_BARRIER_REPLY,
		OFPT_GET_ASYNC_REQUEST:
		if header.Length != 8 {
			return nil, errors.New("length must be 8 by specification")
		}
		return &header, nil
	case OFPT_HELLO:
		var elements []interface{}
		for cur := 8; cur < int(header.Length); {
			elementHeader := OfpHelloElemHeader{
				binary.BigEndian.Uint16(input[cur : cur+2]),
				binary.BigEndian.Uint16(input[cur+2 : cur+4])}
			end := cur + int(elementHeader.Length)
			switch elementHeader.Type {
			default:
				return nil, errors.New("unknown hello_element type")
			case OFPHET_VERSIONBITMAP:
				bitmaps := make([]uint32, int(elementHeader.Length)/4-1)
				for i, _ := range bitmaps {
					bitmaps[i] = binary.BigEndian.Uint32(input[cur+4+i*4 : cur+8+i*4])
				}
				elements = append(elements, OfpHelloElemVersionbitmapEx{
					OfpHelloElemVersionbitmap(elementHeader),
					[]uint32(bitmaps)})
			}
			cur = end
		}
		return &OfpHelloEx{OfpHello{header}, elements}, nil
	case OFPT_ERROR:
		etype := binary.BigEndian.Uint16(input[8:10])
		switch etype {
		default:
			return &OfpErrorMsgEx{OfpErrorMsg{header,
				etype,
				binary.BigEndian.Uint16(input[10:12])},
				input[12:int(header.Length)]}, nil
		case OFPET_EXPERIMENTER:
			return &OfpErrorExperimenterMsgEx{OfpErrorExperimenterMsg{header,
				etype,
				binary.BigEndian.Uint16(input[10:12]),
				binary.BigEndian.Uint32(input[12:16])},
				input[16:int(header.Length)]}, nil
		}
	case OFPT_ECHO_REQUEST, OFPT_ECHO_REPLY:
		return &OfpHeaderEx{header, input[8:int(header.Length)]}, nil
	case OFPT_EXPERIMENTER:
		return &OfpExperimenterHeaderEx{OfpExperimenterHeader{header,
			binary.BigEndian.Uint32(input[8:12]),
			binary.BigEndian.Uint32(input[12:16])},
			input[16:int(header.Length)]}, nil
	case OFPT_FEATURES_REPLY:
		return &OfpSwitchFeatures{Header: header,
			DatapathId:   binary.BigEndian.Uint64(input[8:16]),
			NBuffers:     binary.BigEndian.Uint32(input[16:20]),
			NTables:      input[20],
			AuxiliaryId:  input[21],
			Capabilities: binary.BigEndian.Uint32(input[24:28]),
			Reserved:     binary.BigEndian.Uint32(input[28:32])}, nil
	case OFPT_GET_CONFIG_REPLY, OFPT_SET_CONFIG:
		return &OfpSwitchConfig{header,
			binary.BigEndian.Uint16(input[8:10]),
			binary.BigEndian.Uint16(input[10:12])}, nil
	case OFPT_PACKET_IN:
		if match, err := parseMatch(input[24:]); err != nil {
			return nil, err
		} else {
			return &OfpPacketInEx{
				header,
				binary.BigEndian.Uint32(input[8:12]),
				binary.BigEndian.Uint16(input[12:14]),
				input[14],
				input[15],
				binary.BigEndian.Uint64(input[16:24]),
				match,
				input[24+align8(int(match.GetLength())) : int(header.Length)]}, nil
		}
	case OFPT_FLOW_REMOVED:
		if match, err := parseMatch(input[48:]); err != nil {
			return nil, err
		} else {
			return &OfpFlowRemovedEx{header,
				binary.BigEndian.Uint64(input[8:16]),
				binary.BigEndian.Uint16(input[16:18]),
				input[18],
				input[19],
				binary.BigEndian.Uint32(input[20:24]),
				binary.BigEndian.Uint32(input[24:28]),
				binary.BigEndian.Uint16(input[28:30]),
				binary.BigEndian.Uint16(input[30:32]),
				binary.BigEndian.Uint64(input[32:40]),
				binary.BigEndian.Uint64(input[40:48]),
				match}, nil
		}
	case OFPT_PORT_STATUS:
		var hwAddr [6]byte
		for i, _ := range hwAddr {
			hwAddr[i] = input[24+i]
		}
		var name [16]byte
		for i, _ := range name {
			name[i] = input[32+i]
		}
		return &OfpPortStatus{Header: header,
			Reason: input[8],
			Desc: OfpPort{
				PortNo:     binary.BigEndian.Uint32(input[16:20]),
				HwAddr:     hwAddr,
				Name:       name,
				Config:     binary.BigEndian.Uint32(input[48:52]),
				State:      binary.BigEndian.Uint32(input[52:56]),
				Curr:       binary.BigEndian.Uint32(input[56:60]),
				Advertised: binary.BigEndian.Uint32(input[60:64]),
				Supported:  binary.BigEndian.Uint32(input[64:68]),
				Peer:       binary.BigEndian.Uint32(input[68:72]),
				CurrSpeed:  binary.BigEndian.Uint32(input[72:76]),
				MaxSpeed:   binary.BigEndian.Uint32(input[76:80])}}, nil
	case OFPT_PACKET_OUT:
		var actions []OfpActionIf
		actionsLen := binary.BigEndian.Uint16(input[16:18])
		actionsEnd := 24 + int(actionsLen)
		for cur := 24; cur < actionsEnd; {
			action, _ := parseAction(input[cur:actionsEnd])
			actions = append(actions, action)
			cur += int(action.GetLen())
		}
		return &OfpPacketOutEx{OfpPacketOut{Header: header,
			BufferId:   binary.BigEndian.Uint32(input[8:12]),
			InPort:     binary.BigEndian.Uint32(input[12:16]),
			ActionsLen: actionsLen},
			actions,
			input[actionsEnd:int(header.Length)]}, nil
	case OFPT_FLOW_MOD:
		match, err := parseMatch(input[48:])
		if err != nil {
			return nil, err
		}
		var instructions []OfpInstructionIf
		for cur := align8(48 + int(match.GetLength())); cur < int(header.Length); {
			if instruction, err := parseInstruction(input[cur:]); err != nil {
				return nil, err
			} else {
				instructions = append(instructions, instruction)
				cur += int(instruction.GetLen())
			}
		}
		return &OfpFlowModEx{header,
			binary.BigEndian.Uint64(input[8:16]),
			binary.BigEndian.Uint64(input[16:24]),
			input[24],
			input[25],
			binary.BigEndian.Uint16(input[26:28]),
			binary.BigEndian.Uint16(input[28:30]),
			binary.BigEndian.Uint16(input[30:32]),
			binary.BigEndian.Uint32(input[32:36]),
			binary.BigEndian.Uint32(input[36:40]),
			binary.BigEndian.Uint32(input[40:44]),
			binary.BigEndian.Uint16(input[44:46]),
			match,
			instructions}, nil
	case OFPT_GROUP_MOD:
		var buckets []OfpBucketIf
		for cur := 16; cur < int(header.Length); {
			if bucket, err := parseBucket(input[16:]); err != nil {
				return nil, err
			} else {
				buckets = append(buckets, bucket)
				cur += int(bucket.GetLen())
			}
		}
		return &OfpGroupModEx{OfpGroupMod{Header: header,
			Command: binary.BigEndian.Uint16(input[8:10]),
			Type:    input[10],
			GroupId: binary.BigEndian.Uint32(input[12:16])},
			buckets}, nil
	case OFPT_PORT_MOD:
		var hwAddr [6]byte
		for i, _ := range hwAddr {
			hwAddr[i] = input[16+i]
		}
		return &OfpPortMod{Header: header,
			PortNo:    binary.BigEndian.Uint32(input[8:12]),
			HwAddr:    hwAddr,
			Config:    binary.BigEndian.Uint32(input[24:28]),
			Mask:      binary.BigEndian.Uint32(input[28:32]),
			Advertise: binary.BigEndian.Uint32(input[32:36])}, nil
	case OFPT_TABLE_MOD:
		return &OfpTableMod{Header: header,
			TableId: input[8],
			Config:  binary.BigEndian.Uint32(input[12:16])}, nil
	case OFPT_MULTIPART_REQUEST:
		mpType := binary.BigEndian.Uint16(input[8:10])
		flags := binary.BigEndian.Uint16(input[10:12])
		switch mpType {
		default:
			return nil, errors.New("unknown OFPMP_")
		case OFPMP_DESC,
			OFPMP_TABLE,
			OFPMP_GROUP_DESC,
			OFPMP_GROUP_FEATURES,
			OFPMP_METER_FEATURES,
			OFPMP_PORT_DESC:
			return &OfpMultipartRequest{Header: header,
				Type:  mpType,
				Flags: flags}, nil
		case OFPMP_FLOW:
			if match, err := parseMatch(input[48:]); err != nil {
				return nil, err
			} else {
				return &OfpMultipartRequestEx{
					OfpMultipartRequest{
						Header: header,
						Type:   mpType,
						Flags:  flags,
					},
					OfpFlowStatsRequestEx{
						input[16],
						binary.BigEndian.Uint32(input[20:24]),
						binary.BigEndian.Uint32(input[24:28]),
						binary.BigEndian.Uint64(input[32:40]),
						binary.BigEndian.Uint64(input[40:48]),
						match,
					},
				}, nil
			}
		case OFPMP_AGGREGATE:
			if match, err := parseMatch(input[48:]); err != nil {
				return nil, err
			} else {
				return &OfpMultipartRequestEx{OfpMultipartRequest{Header: header,
					Type:  mpType,
					Flags: flags,
				},
					OfpAggregateStatsRequestEx{
						input[16],
						binary.BigEndian.Uint32(input[20:24]),
						binary.BigEndian.Uint32(input[24:28]),
						binary.BigEndian.Uint64(input[32:40]),
						binary.BigEndian.Uint64(input[40:48]),
						match,
					},
				}, nil
			}

		case OFPMP_PORT_STATS:
			return &OfpMultipartRequestEx{OfpMultipartRequest{Header: header,
				Type:  mpType,
				Flags: flags},
				OfpPortStatsRequest{PortNo: binary.BigEndian.Uint32(input[16:20])}}, nil
		case OFPMP_QUEUE:
			return &OfpMultipartRequestEx{OfpMultipartRequest{Header: header,
				Type:  mpType,
				Flags: flags},
				OfpQueueStatsRequest{binary.BigEndian.Uint32(input[16:20]),
					binary.BigEndian.Uint32(input[20:24])}}, nil
		case OFPMP_GROUP:
			return &OfpMultipartRequestEx{OfpMultipartRequest{Header: header,
				Type:  mpType,
				Flags: flags},
				OfpGroupStatsRequest{GroupId: binary.BigEndian.Uint32(input[16:20])}}, nil
		case OFPMP_METER,
			OFPMP_METER_CONFIG:
			return &OfpMultipartRequestEx{
				OfpMultipartRequest{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				OfpMeterMultipartRequest{
					MeterId: binary.BigEndian.Uint32(input[16:20]),
				},
			}, nil
		case OFPMP_TABLE_FEATURES:
			var features []OfpTableFeaturesEx
			for cur := 4; cur < int(header.Length); {
				if feature, err := parseTableFeatures(input[cur:]); err != nil {
					return nil, err
				} else {
					features = append(features, *feature)
					cur += int(feature.Length)
				}
			}
			return &OfpMultipartRequestEx{
				OfpMultipartRequest{
					Header: header,
					Type:   mpType,
					Flags:  flags},
				features,
			}, nil
		case OFPMP_EXPERIMENTER:
			return &OfpMultipartRequestEx{
				OfpMultipartRequest{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				OfpExperimenterMultipartHeaderEx{
					OfpExperimenterMultipartHeader{binary.BigEndian.Uint32(input[16:20]),
						binary.BigEndian.Uint32(input[20:24])},
					input[24:int(header.Length)],
				},
			}, nil
		}
	case OFPT_MULTIPART_REPLY:
		mpType := binary.BigEndian.Uint16(input[8:10])
		flags := binary.BigEndian.Uint16(input[10:12])
		switch mpType {
		default:
			return nil, errors.New("unknown OFPMP_")
		case OFPMP_DESC:
			desc := OfpDesc{}
			for i, _ := range desc.MfrDesc {
				desc.MfrDesc[i] = input[16+i]
			}
			for i, _ := range desc.HwDesc {
				desc.HwDesc[i] = input[16+256+i]
			}
			for i, _ := range desc.SwDesc {
				desc.SwDesc[i] = input[16+512+i]
			}
			for i, _ := range desc.SerialNum {
				desc.SerialNum[i] = input[16+768+i]
			}
			for i, _ := range desc.DpDesc {
				desc.DpDesc[i] = input[64+768+i]
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				desc,
			}, nil
		case OFPMP_FLOW:
			var stats []OfpFlowStatsEx
			for cur := 16; cur < int(header.Length); {
				if stat, err := parseFlowStats(input[cur:]); err != nil {
					return nil, err
				} else {
					stats = append(stats, *stat)
					cur += int(stat.Length)
				}
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_AGGREGATE:
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				OfpAggregateStatsReply{
					PacketCount: binary.BigEndian.Uint64(input[16:24]),
					ByteCount:   binary.BigEndian.Uint64(input[24:32]),
					FlowCount:   binary.BigEndian.Uint32(input[32:36]),
				},
			}, nil
		case OFPMP_TABLE:
			stats := make([]OfpTableStats, (int(header.Length)-16)/24)
			for i, _ := range stats {
				off := 24 * i
				stats[i] = OfpTableStats{TableId: input[16+off],
					ActiveCount:  binary.BigEndian.Uint32(input[20+off : 24+off]),
					LookupCount:  binary.BigEndian.Uint64(input[24+off : 32+off]),
					MatchedCount: binary.BigEndian.Uint64(input[32+off : 40+off])}
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_PORT_STATS:
			stats := make([]OfpPortStats, (int(header.Length)-16)/112)
			for i, _ := range stats {
				off := 112 * i
				stats[i] = OfpPortStats{
					PortNo:       binary.BigEndian.Uint32(input[16+off : 20+off]),
					RxPackets:    binary.BigEndian.Uint64(input[24+off : 32+off]),
					TxPackets:    binary.BigEndian.Uint64(input[32+off : 40+off]),
					RxBytes:      binary.BigEndian.Uint64(input[40+off : 48+off]),
					TxBytes:      binary.BigEndian.Uint64(input[48+off : 56+off]),
					RxDropped:    binary.BigEndian.Uint64(input[56+off : 64+off]),
					TxDropped:    binary.BigEndian.Uint64(input[64+off : 72+off]),
					RxErrors:     binary.BigEndian.Uint64(input[72+off : 80+off]),
					TxErrors:     binary.BigEndian.Uint64(input[80+off : 88+off]),
					RxFrameErr:   binary.BigEndian.Uint64(input[88+off : 96+off]),
					RxOverErr:    binary.BigEndian.Uint64(input[96+off : 104+off]),
					RxCrcErr:     binary.BigEndian.Uint64(input[104+off : 112+off]),
					Collisions:   binary.BigEndian.Uint64(input[112+off : 120+off]),
					DurationSec:  binary.BigEndian.Uint32(input[120+off : 124+off]),
					DurationNsec: binary.BigEndian.Uint32(input[124+off : 128+off]),
				}
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_QUEUE:
			stats := make([]OfpQueueStats, (int(header.Length)-16)/40)
			for i, _ := range stats {
				off := 16 + 40*i
				stats[i] = OfpQueueStats{
					binary.BigEndian.Uint32(input[16+off : 20+off]),
					binary.BigEndian.Uint32(input[20+off : 24+off]),
					binary.BigEndian.Uint64(input[24+off : 32+off]),
					binary.BigEndian.Uint64(input[32+off : 40+off]),
					binary.BigEndian.Uint64(input[40+off : 48+off]),
					binary.BigEndian.Uint32(input[48+off : 52+off]),
					binary.BigEndian.Uint32(input[52+off : 56+off]),
				}
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_GROUP:
			var stats []OfpGroupStatsEx
			for cur := 16; cur < int(header.Length); {
				length := binary.BigEndian.Uint16(input[0+cur : 2+cur])
				bucketStats := make([]OfpBucketCounter, (int(length)-40)/16)
				for i, _ := range bucketStats {
					bucketStats[i] = OfpBucketCounter{
						binary.BigEndian.Uint64(input[40+cur+16*i : 48+cur+16*i]),
						binary.BigEndian.Uint64(input[48+cur+16*i : 56+cur+16*i]),
					}
				}
				stat := OfpGroupStatsEx{
					OfpGroupStats{
						Length:       length,
						GroupId:      binary.BigEndian.Uint32(input[4+cur : 8+cur]),
						RefCount:     binary.BigEndian.Uint32(input[8+cur : 12+cur]),
						PacketCount:  binary.BigEndian.Uint64(input[16+cur : 24+cur]),
						ByteCount:    binary.BigEndian.Uint64(input[24+cur : 32+cur]),
						DurationSec:  binary.BigEndian.Uint32(input[32+cur : 36+cur]),
						DurationNsec: binary.BigEndian.Uint32(input[36+cur : 40+cur]),
					},
					bucketStats,
				}
				stats = append(stats, stat)
				cur += int(length)
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_GROUP_DESC:
			var stats []OfpGroupDescEx
			for cur := 16; cur < int(header.Length); {
				length := binary.BigEndian.Uint16(input[0+cur : 2+cur])
				var buckets []OfpBucketIf
				for pos := cur + 8; pos < int(length); {
					if bucket, err := parseBucket(input[pos:]); err != nil {
						return nil, err
					} else {
						buckets = append(buckets, bucket)
						pos += int(bucket.GetLen())
					}
				}
				stat := OfpGroupDescEx{
					OfpGroupDesc{
						Length:  length,
						Type:    input[2+cur],
						GroupId: binary.BigEndian.Uint32(input[4+cur : 8+cur]),
					},
					buckets,
				}
				stats = append(stats, stat)
				cur += int(stat.Length)
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_GROUP_FEATURES:
			stats := make([]OfpGroupFeatures, (int(header.Length)-16)/40)
			for i, _ := range stats {
				off := 16 + i*40
				stats[i] = OfpGroupFeatures{
					Types:        binary.BigEndian.Uint32(input[off : 4+off]),
					Capabilities: binary.BigEndian.Uint32(input[4+off : 8+off]),
				}
				for j, _ := range stats[i].MaxGroups {
					off2 := 8 + off + 4*j
					stats[i].MaxGroups[j] = binary.BigEndian.Uint32(input[off2 : 4+off2])
				}
				for j, _ := range stats[i].Actions {
					off2 := 24 + off + 4*j
					stats[i].MaxGroups[j] = binary.BigEndian.Uint32(input[off2 : 4+off2])
				}
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_METER:
			var stats []OfpMeterStatsEx
			for cur := 16; cur < int(header.Length); {
				length := binary.BigEndian.Uint16(input[4+cur : 6+cur])
				bandStats := make([]OfpMeterBandStats, (int(length)-40)/16)
				for i, _ := range bandStats {
					off := cur + 40 + 16*i
					bandStats[i] = OfpMeterBandStats{
						binary.BigEndian.Uint64(input[off : 8+off]),
						binary.BigEndian.Uint64(input[8+cur : 16+off]),
					}
				}
				stat := OfpMeterStatsEx{
					OfpMeterStats{
						MeterId:       binary.BigEndian.Uint32(input[0+cur : 4+cur]),
						Len:           length,
						FlowCount:     binary.BigEndian.Uint32(input[12+cur : 16+cur]),
						PacketInCount: binary.BigEndian.Uint64(input[16+cur : 24+cur]),
						ByteInCount:   binary.BigEndian.Uint64(input[24+cur : 32+cur]),
						DurationSec:   binary.BigEndian.Uint32(input[32+cur : 36+cur]),
						DurationNsec:  binary.BigEndian.Uint32(input[36+cur : 40+cur]),
					},
					bandStats,
				}
				stats = append(stats, stat)
				cur += int(length)
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_METER_CONFIG:
			var stats []OfpMeterConfigEx
			for cur := 16; cur < int(header.Length); {
				length := binary.BigEndian.Uint16(input[0+cur : 2+cur])
				bands := make([]OfpMeterBandHeader, (int(length)-8)/12)
				for i, _ := range bands {
					off := cur + 8 + i*12
					bands[i] = OfpMeterBandHeader{
						binary.BigEndian.Uint16(input[off : 2+off]),
						binary.BigEndian.Uint16(input[2+off : 4+off]),
						binary.BigEndian.Uint32(input[4+off : 8+off]),
						binary.BigEndian.Uint32(input[8+off : 12+off]),
					}
				}
				stat := OfpMeterConfigEx{
					OfpMeterConfig{
						length,
						binary.BigEndian.Uint16(input[2+cur : 4+cur]),
						binary.BigEndian.Uint32(input[4+cur : 8+cur]),
					},
					bands,
				}
				stats = append(stats, stat)
				cur += int(length)
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_METER_FEATURES:
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				OfpMeterFeatures{
					MaxMeter:     binary.BigEndian.Uint32(input[16:20]),
					BandTypes:    binary.BigEndian.Uint32(input[20:24]),
					Capabilities: binary.BigEndian.Uint32(input[24:28]),
					MaxBands:     input[28],
					MaxColor:     input[29],
				},
			}, nil
		case OFPMP_TABLE_FEATURES:
			var stats []OfpTableFeaturesEx
			for cur := 16; cur < int(header.Length); {
				length := binary.BigEndian.Uint16(input[0+cur : 2+cur])
				var properties []OfpTableFeaturePropIf
				for pos := 64; pos < int(length); {
					if property, err := parseTableFeatureProperty(input[cur+pos:]); err != nil {
						return nil, err
					} else {
						properties = append(properties, property)
						pos += int(property.GetLength())
					}
				}
				stat := OfpTableFeaturesEx{
					OfpTableFeatures{
						Length:        length,
						TableId:       input[2+cur],
						MetadataMatch: binary.BigEndian.Uint64(input[40+cur : 48+cur]),
						MetadataWrite: binary.BigEndian.Uint64(input[48+cur : 56+cur]),
						Config:        binary.BigEndian.Uint32(input[56+cur : 60+cur]),
						MaxEntries:    binary.BigEndian.Uint32(input[56+cur : 64+cur]),
					},
					properties,
				}
				for i, _ := range stat.Name {
					stat.Name[i] = input[cur+8+i]
				}
				stats = append(stats, stat)
				cur += int(length)
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_PORT_DESC:
			stats := make([]OfpPort, (int(header.Length)-16)/64)
			for i, _ := range stats {
				off := 16 + i*64
				stats[i] = OfpPort{
					PortNo:     binary.BigEndian.Uint32(input[off : 4+off]),
					Config:     binary.BigEndian.Uint32(input[32+off : 36+off]),
					State:      binary.BigEndian.Uint32(input[36+off : 40+off]),
					Curr:       binary.BigEndian.Uint32(input[40+off : 44+off]),
					Advertised: binary.BigEndian.Uint32(input[44+off : 48+off]),
					Supported:  binary.BigEndian.Uint32(input[48+off : 52+off]),
					Peer:       binary.BigEndian.Uint32(input[52+off : 56+off]),
					CurrSpeed:  binary.BigEndian.Uint32(input[56+off : 60+off]),
					MaxSpeed:   binary.BigEndian.Uint32(input[60+off : 64+off]),
				}
			}
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				stats,
			}, nil
		case OFPMP_EXPERIMENTER:
			return &OfpMultipartReplyEx{
				OfpMultipartReply{
					Header: header,
					Type:   mpType,
					Flags:  flags,
				},
				OfpExperimenterMultipartHeaderEx{
					OfpExperimenterMultipartHeader{binary.BigEndian.Uint32(input[16:20]),
						binary.BigEndian.Uint32(input[20:24])},
					input[24:int(header.Length)],
				},
			}, nil
		}
	case OFPT_QUEUE_GET_CONFIG_REQUEST:
		return &OfpQueueGetConfigRequest{
			Header: header,
			Port:   binary.BigEndian.Uint32(input[8:12]),
		}, nil
	case OFPT_QUEUE_GET_CONFIG_REPLY:
		var queues []OfpPacketQueueEx
		for cur := 16; cur < int(header.Length); {
			length := binary.BigEndian.Uint16(input[8+cur : 10+cur])
			var properties []OfpQueuePropIf
			for pos := 16; pos < int(length); {
				if property, err := parseQueueProp(input[cur+pos:]); err != nil {
					return nil, err
				} else {
					properties = append(properties, property)
					pos += int(property.GetLen())
				}
			}
			queue := OfpPacketQueueEx{
				OfpPacketQueue{
					QueueId: binary.BigEndian.Uint32(input[cur : 4+cur]),
					Port:    binary.BigEndian.Uint32(input[4+cur : 8+cur]),
					Len:     length,
				},
				properties,
			}
			queues = append(queues, queue)
			cur += int(length)
		}
		return &OfpQueueGetConfigReplyEx{
			OfpQueueGetConfigReply{
				Header: header,
				Port:   binary.BigEndian.Uint32(input[8:12]),
			},
			queues,
		}, nil
	case OFPT_ROLE_REQUEST,
		OFPT_ROLE_REPLY:
		return &OfpRoleRequest{
			Header:       header,
			Role:         binary.BigEndian.Uint32(input[8:12]),
			GenerationId: binary.BigEndian.Uint64(input[16:24]),
		}, nil
	case OFPT_GET_ASYNC_REPLY,
		OFPT_SET_ASYNC:
		ret := &OfpAsyncConfig{
			Header: header,
		}
		for i, _ := range ret.PacketInMask {
			off := 8 + 4*i
			ret.PacketInMask[i] = binary.BigEndian.Uint32(input[off : 4+off])
		}
		for i, _ := range ret.PortStatusMask {
			off := 16 + 4*i
			ret.PortStatusMask[i] = binary.BigEndian.Uint32(input[off : 4+off])
		}
		for i, _ := range ret.FlowRemovedMask {
			off := 24 + 4*i
			ret.FlowRemovedMask[i] = binary.BigEndian.Uint32(input[off : 4+off])
		}
		return ret, nil
	case OFPT_METER_MOD:
		bands := make([]OfpMeterBandHeader, (int(header.Length)-16)/12)
		for i, _ := range bands {
			off := 16 + 12*i
			bands[i] = OfpMeterBandHeader{
				binary.BigEndian.Uint16(input[off : 2+off]),
				binary.BigEndian.Uint16(input[2+off : 4+off]),
				binary.BigEndian.Uint32(input[4+off : 8+off]),
				binary.BigEndian.Uint32(input[8+off : 12+off]),
			}
		}
		return &OfpMeterModEx{
			OfpMeterMod{
				header,
				binary.BigEndian.Uint16(input[8:10]),
				binary.BigEndian.Uint16(input[10:12]),
				binary.BigEndian.Uint32(input[12:16]),
			},
			bands,
		}, nil
	}
}
