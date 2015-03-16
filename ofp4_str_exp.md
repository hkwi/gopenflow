Openflow 1.3 extension

Experimenter ID: STRATOS_EXPERIMENTER_ID = 0xFF00E04D

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
 	// default
 	STROXM_BASIC_UNKNOWN = 0,
 	
 	// match, oob, set
 	STROXM_BASIC_DOT11,
 	
 	// match, set
 	STROXM_BASIC_DOT11_FRAME_CTRL,
 	STROXM_BASIC_DOT11_ADDR1,
 	STROXM_BASIC_DOT11_ADDR2,
 	STROXM_BASIC_DOT11_ADDR3,
 	STROXM_BASIC_DOT11_ADDR4,
 	STROXM_BASIC_DOT11_TAG,
 	STROXM_BASIC_DOT11_SSID,
 	STROXM_BASIC_DOT11_ACTION_CATEGORY
 	STROXM_BASIC_DOT11_PUBLIC_ACTION
 }

 enum stratos_radiotap_exp_type {
 	STROXM_RADIOTAP_TSFT = 0,
 	STROXM_RADIOTAP_FLAGS = 1,
 	STROXM_RADIOTAP_RATE = 2,
 	STROXM_RADIOTAP_CHANNEL = 3,
 	STROXM_RADIOTAP_FHSS = 4,
 	STROXM_RADIOTAP_DBM_ANTSIGNAL = 5,
 	STROXM_RADIOTAP_DBM_ANTNOISE = 6,
 	STROXM_RADIOTAP_LOCK_QUALITY = 7,
 	STROXM_RADIOTAP_TX_ATTENUATION = 8,
 	STROXM_RADIOTAP_DB_TX_ATTENUATION = 9,
 	STROXM_RADIOTAP_DBM_TX_POWER = 10,
 	STROXM_RADIOTAP_ANTENNA = 11,
 	STROXM_RADIOTAP_DB_ANTSIGNAL = 12,
 	STROXM_RADIOTAP_DB_ANTNOISE = 13,
 	STROXM_RADIOTAP_RX_FLAGS = 14,
 	STROXM_RADIOTAP_TX_FLAGS = 15,
 	STROXM_RADIOTAP_RTS_RETRIES = 16,
 	STROXM_RADIOTAP_DATA_RETRIES = 17,
 	
 	STROXM_RADIOTAP_MCS = 19,
 	STROXM_RADIOTAP_AMPDU_STATUS = 20,
 }
```

STRATOS_OXM_FIELD_BASIC
-----------------------

STRATOS_OXM_FIELD_BASIC is used for usual frame matching.

### STROXM_BASIC_UNKNOWN
We don't use this value for normal use for now. 0 will be reserved.

### STROXM_BASIC_DOT11
Bit 1 indicates that operations on that LWAPP L2 frame is done as 802.11 frame. 
Packets with this field is always an LWAPP L2 frame.
Switch port emits 802.11 raw frame in the LWAPP payload if this is 1.
Switch will set this 1 when sending packet_in message with raw 802.11 frame.

- mask : No
- length : 1 byte

### STROXM_BASIC_DOT11_FRAME_CTRL
802.11 frame control field that contains protocol+type+subtype.
Use this field to filter management,control,data type or each subtypes.

- mask : maskable
- length : 2 bytes (+ 2 bytes)

### STROXM_BASIC_DOT11_ADDR1
The value is 48bit 802.11 mac.
- mask : maskable
- length : 6 bytes (+ 6 bytes)

### STROXM_BASIC_DOT11_ADDR2
The value is 48bit 802.11 mac.

- mask : maskable
- length : 6 bytes (+ 6 bytes)

### STROXM_BASIC_DOT11_ADDR3
The value is 48bit 802.11 mac.

- mask : maskable
- length : 6 bytes (+ 6 bytes)

### STROXM_BASIC_DOT11_ADDR4
The value is 48bit 802.11 mac.

- mask : maskable
- length : 6 bytes (+ 6 bytes)

### STROXM_BASIC_DOT11_TAG
Matches with management frame information element ID and OUI (ID=221).
Set-field is not supported.

- mask : no
- length : 1 or 5 bytes

### STROXM_BASIC_DOT11_SSID
Management frame that contains SSID information element will match.

- mask : maskable
- length : 32 bytes (+ 32 bytes)
- prerequisite : STRATOS_BASIC_DOT11_TAG=0

### STROXM_BASIC_DOT11_ACTION_CATEGORY
Represents "Action field" in Action frame.
Set-field is not supported.
Only non-ROBUST frames are supported for now.

- mask : no
- length : 1
- prerequisite : STROXM_BASIC_DOT11_FRAME_CTRL=\xC0\x00/\xFC\x00

### STROXM_BASIC_DOT11_PUBLIC_ACTION
Represents "Public Action field value" in the Pulic Action frame.
Set-field is not supported.

- mask : no
- length : 1
- prerequisite : STROXM_BASIC_ACTION_CATEGORY=4


Special rules
-------------
Flow rules that have stratosphere experimenter match with `OXM_OF_IN_PORT` will try to hook 
enable 802.11 management frame capture. In this case, the application have the responsibility 
of handling those captured management frames, and sending response frames if required.


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


