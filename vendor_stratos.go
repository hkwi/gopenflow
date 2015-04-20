package gopenflow

type MgmtFramePrefix []byte

// NL80211_ATTR_FRAME_MATCH - contents are "Frame Body", right after HT Control
type MgmtFrameAdd MgmtFramePrefix
type MgmtFrameRemove MgmtFramePrefix
