Openflow 1.3 extension

Experimenter ID: STRATOS_EXPERIMENTER_ID = 0xFF00E04D

OXM
===
Stratosphere `oxm_class` definition follows:

```
 enum stratos_oxm_class {
 	// match, oob, set
 	STROXM_BASIC_DOT11 = 2,
 	
 	// match, set
 	STROXM_BASIC_DOT11_FRAME_CTRL = 3,
 	STROXM_BASIC_DOT11_ADDR1,
 	STROXM_BASIC_DOT11_ADDR2,
 	STROXM_BASIC_DOT11_ADDR3,
 	STROXM_BASIC_DOT11_ADDR4,
 	STROXM_BASIC_DOT11_SSID,
 	STROXM_BASIC_DOT11_ACTION_CATEGORY
 	STROXM_BASIC_DOT11_PUBLIC_ACTION
 	
 	// match
 	STROXM_BASIC_DOT11_TAG = 11
 	STROXM_BASIC_DOT11_TAG_VENDOR
 	
 	STROXM_RADIOTAP_TSFT = 16,
 	STROXM_RADIOTAP_FLAGS = 17,
 	STROXM_RADIOTAP_RATE = 18,
 	STROXM_RADIOTAP_CHANNEL = 19,
 	STROXM_RADIOTAP_FHSS = 20,
 	STROXM_RADIOTAP_DBM_ANTSIGNAL = 21,
 	STROXM_RADIOTAP_DBM_ANTNOISE = 22,
 	STROXM_RADIOTAP_LOCK_QUALITY = 23,
 	STROXM_RADIOTAP_TX_ATTENUATION = 24,
 	STROXM_RADIOTAP_DB_TX_ATTENUATION = 25,
 	STROXM_RADIOTAP_DBM_TX_POWER = 26,
 	STROXM_RADIOTAP_ANTENNA = 27,
 	STROXM_RADIOTAP_DB_ANTSIGNAL = 28,
 	STROXM_RADIOTAP_DB_ANTNOISE = 29,
 	STROXM_RADIOTAP_RX_FLAGS = 30,
 	STROXM_RADIOTAP_TX_FLAGS = 31,
 	STROXM_RADIOTAP_RTS_RETRIES = 32,
 	STROXM_RADIOTAP_DATA_RETRIES = 33,
 	
 	STROXM_RADIOTAP_MCS = 35,
 	STROXM_RADIOTAP_AMPDU_STATUS = 36,
 	STROXM_RADIOTAP_VHT = 37,
 }
```

STROXM_BASIC
-----------------------
STROXM_BASIC is used for usual frame matching.

### STROXM_BASIC_UNKNOWN
We don't use this value for normal use for now. 0 will be reserved.

### STROXM_BASIC_DOT11
Value 1 indicates that the frame is an 802.11 frame in LWAPP L2 frame.
Packet with this field 1 is always an LWAPP L2 frame.
Switch port emits 802.11 raw frame in the LWAPP payload if this is 1.
Switch will set this 1 when sending packet_in message with raw 802.11 frame.

Value 0 indicates DONT-CARE. Flow rules that have 0 will match both 802.11 and
non-802.11 frame.

Value 2 indicates that the frame not an 802.11 frame explicitly.
Flow rule with this field 2 does not match 802.11 frame.
Setting 2 for this fields means that the packet is a normal ethernet frame of LWAPP,
and switch will behave as if the field was missing. This approach is different from
OFPVID_PRESENT. This is for making dot11 frame as a normal LWAPP ethernet frame.

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

### STROXM_BASIC_DOT11_SSID
Management frame that contains SSID information element will match.
To match prefix, use mask. Without mask, exact match will be performed.

- mask : maskable
- length : 32 bytes (+ 32 bytes)
- prerequisite : STROXM_BASIC_DOT11_FRAME_CTRL=\x00\x00/\x0C\x00

### STROXM_BASIC_DOT11_ACTION_CATEGORY
Represents "Action field" in Action frame. Vendor specific action will want 
additional bytes for match, so length is defined as variable, prefix match.
Set-field is not supported.
Only non-ROBUST frames are supported for now (depends on the implementation).

- mask : no
- length : variable
- prerequisite : STROXM_BASIC_DOT11_FRAME_CTRL=\xD0\x00/\xFC\x00 or \xE0\x00/\xFC\x00

### STROXM_BASIC_DOT11_PUBLIC_ACTION
Represents "Public Action field value" in the Pulic Action frame.
Set-field is not supported.

- mask : no
- length : 1
- prerequisite : STROXM_BASIC_ACTION_CATEGORY=4

### STROXM_BASIC_DOT11_TAG
Matches to information element ID. 
Multiple oxm may present in flow match condition(AND).
Set-field is not supported.

- mask : no
- length : 1

### STROXM_BASIC_DOT11_TAG_VENDOR
Matches to vendor information element Origanization indentifier.
Set-field is not supported.

- mask : no
- length : 3 to 257
- prerequisite : STROXM_BASIC_DOT11_TAG=221


Special rules
-------------
Flow rules that have both `STROXM_BASIC_DOT11_ACTION_CATEGORY` and `OXM_OF_IN_PORT` will try to 
enable 802.11 management frame capture. In this case, depending on the port type, the application 
might be responsibile for handling those captured management frames, and sending response frames 
if required.

With nl80211 non-monotir netdev, when some other program already handles that dot11_action frame, 
mod_flow may fail because kernel will return EALREADY for that case.


STROXM_RADIOTAP
--------------------------
STROXM_RADIOTAP is used to match for detailed wireless information.
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


