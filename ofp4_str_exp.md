Openflow 1.3 extension

Experimenter ID: 0xFF00E04D

OXM
===
`stratos_oxm` experimenter oxm use following packing structure.
Note that exp_type is uint16_t, unlike the other ofp_experimenter_header.
This is because of published openflow 1.3 extension ext256.

```
 struct stratos_oxm {
 	struct ofp_oxm_experimenter_header {
 		uint32_t oxm_header;
 		uint32_t experimenter; // 0xFF00E04D
 	}
 	uint16_t exp_type;
 	uint8_t  data[0];
 }
```

Bit fields for oxm_header is as following.

```
 +-----------+-----------+----+------------+
 | oxm_class | oxm_field | HM | oxm_length |
 +-----------+-----------+----+------------+
```

oxm_class is always OFPXMC_EXPERIMENTER (0xFFFF), as defined in openflow specification.

```
 enum stratos_oxm_field_type {
 	STRATOS_OXM_FIELD_BASIC = 0,
 	STRATOS_OXM_FIELD_RADIOTAP = 1,
 }

 enum stratos_basic_exp_type {
 	STROXM_BASIC_DOT11,
 	STROXM_BASIC_DOT11_FRAME_CTRL,
 	STROXM_BASIC_DOT11_BSSID,
 	STROXM_BASIC_DOT11_TAG,
 	STROXM_BASIC_SSID,
 }

 enum stratos_radiotap_exp_type {
 	STROXM_RADIOTAP_TSFT = 0,
 	STROXM_RADIOTAP_FLAGS
 	STROXM_RADIOTAP_RATE
 	STROXM_RADIOTAP_CHANNEL
 	STROXM_RADIOTAP_FHSS
 	STROXM_RADIOTAP_DBM_ANTSIGNAL
 	STROXM_RADIOTAP_DBM_ANTNOISE
 	STROXM_RADIOTAP_LOCK_QUALITY
 	STROXM_RADIOTAP_TX_ATTENUATION
 	STROXM_RADIOTAP_DBM_TX_POWER
 	STROXM_RADIOTAP_ANTENNA
 	STROXM_RADIOTAP_DB_ANTSIGNAL
 	STROXM_RADIOTAP_DB_ANTNOISE
 	STROXM_RADIOTAP_RX_FLAGS
 	STROXM_RADIOTAP_TX_FLAGS
 	STROXM_RADIOTAP_RTS_RETRIES
 	STROXM_RADIOTAP_DATA_RETRIES
 	STROXM_RADIOTAP_MCS
 	STROXM_RADIOTAP_AMPDU_STATUS
 }
```

STRATOS_OXM_FIELD_BASIC
-----------------------

STRATOS_OXM_FIELD_BASIC is used for usual frame matching.

### STROXM_BASIC_DOT11
Bit 1 indicates that the frame is handled as 802.11 frame at the port.
Packets with this field is always an LWAPP L2 frame.

- mask : No
- length : 1 byte

### STROXM_BASIC_DOT11_FRAME_CTRL
802.11 frame control field that contains protocol+type+subtype.
Use this field to filter management,control,data type or each subtypes.

- mask : maskable
- length : 2 bytes (+ 2 bytes)

### STROXM_BASIC_DOT11_BSSID
The value is 48bit 802.11 wireless BSSID. Non-WDS frames will match.
- mask : maskable
- length : 6 bytes (+ 6 bytes)

### STROXM_BASIC_SSID
Management frame that contains SSID information element will match.
- mask : maskable
- length : 32 bytes (+ 32 bytes)
- prerequisite : STRATOS_BASIC_DOT11_TAG=0

### STROXM_BASIC_ACTION_CATEGORY
implies STRATOS_BASIC_DOT11_FRAME_CTRL=\xC0\x00/\xFC\x00

### STROXM_BASIC_PUBLIC_ACTION
implies ACTION_CATEGORY=4

### STROXM_BASIC_GAS
implies PUBLIC_ACTION=(10, 11, 12 or 13)

### STROXM_BASIC_ANQP
implies GAS


STRATOS_OXM_FIELD_RADIOTAP
--------------------------
STRATOS_OXM_FIELD_RADIOTAP is used to match for detailed wireless information.
Note that this field will be only available at the very port that handles the 
wireless frame. PACKET_IN message may contain these fields in match.


ACTION
======

```
 struct stratos_action {
 	struct ofp_action_experimenter_header {
 		uint16_t type;
 		uint16_t len;
 		uint32_t experimenter; // 0xFF00E04D
 	}
 	uint16_t exp_type;
 	uint8_t  data[0];
 }

 enum stratos_action_exp_type {
 	STRACT_PUSH_LWAPP
 	STRACT_POP_LWAPP
 	STRACT_PUSH_CAPWAP
 	STRACT_POP_CAPWAP
 }
```


