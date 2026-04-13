package models

import (
	"net"
	"time"
)

// SIPEvent is the normalized output from all ingesters.
type SIPEvent struct {
	Timestamp    time.Time
	SourceIP     net.IP
	Method       string // REGISTER, INVITE, OPTIONS, etc.
	UserAgent    string
	FromUser     string
	ToUser       string
	CallID       string
	ResponseCode int    // 0 if this is a request
	Source       string // "log" or "pcap"
}

// Threat is emitted by a detector when a threshold is breached.
type Threat struct {
	Timestamp   time.Time
	SourceIP    net.IP
	Detector    string // which detector flagged it
	Severity    string // "low", "medium", "high"
	Description string
	EventCount  int
	Window      time.Duration
}

// BanAction is sent from the decision engine to the action layer.
type BanAction struct {
	IP       net.IP
	Duration time.Duration // 0 = permanent
	Reason   string
	Detector string
	Severity string
	BanCount int
}

// BanEntry represents a ban record from the store or enforcer.
type BanEntry struct {
	ID        int64
	IP        string
	Detector  string
	Reason    string
	Severity  string
	BannedAt  time.Time
	Duration  time.Duration
	ExpiresAt *time.Time // nil if permanent
	BanCount  int
	Status    string // "active", "expired", "manual"
}

// NotifyEvent is passed to notifiers on ban/unban.
type NotifyEvent struct {
	Type      string // "ban", "unban"
	IP        string
	Detector  string
	Severity  string
	Duration  time.Duration
	Reason    string
	Timestamp time.Time
}

// WhitelistEntry represents a whitelist record.
type WhitelistEntry struct {
	ID        int64
	IPCIDR    string
	Comment   string
	Source    string // "static", "dynamic"
	CreatedAt time.Time
}
