package models

import (
	"encoding/json"
	"net"
	"time"
)

// SIPEvent is the normalized output from all ingesters.
type SIPEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	SourceIP     net.IP    `json:"source_ip"`
	Method       string    `json:"method"`     // REGISTER, INVITE, OPTIONS, etc.
	UserAgent    string    `json:"user_agent"`
	FromUser     string    `json:"from_user"`
	ToUser       string    `json:"to_user"`
	CallID       string    `json:"call_id"`
	ResponseCode int       `json:"response_code"` // 0 if this is a request
	Source       string    `json:"source"`        // "log" or "pcap"
	// Rejected is true when the SIP server itself explicitly rejected this
	// request (e.g. "non-whitelisted source", "denied", "forbidden"). This is
	// a much higher-confidence signal than a raw request count.
	Rejected     bool   `json:"rejected"`
	RejectReason string `json:"reject_reason"`
}

// Threat is emitted by a detector when a threshold is breached.
type Threat struct {
	Timestamp   time.Time     `json:"timestamp"`
	SourceIP    net.IP        `json:"source_ip"`
	Detector    string        `json:"detector"` // which detector flagged it
	Severity    string        `json:"severity"` // "low", "medium", "high"
	Description string        `json:"description"`
	EventCount  int           `json:"event_count"`
	Window      time.Duration `json:"-"` // surfaced as integer seconds via MarshalJSON
}

// MarshalJSON renders Window as integer seconds rather than the default
// nanoseconds, matching the public BanEntry contract.
func (t Threat) MarshalJSON() ([]byte, error) {
	type alias Threat
	return json.Marshal(struct {
		alias
		WindowSeconds int64 `json:"window_seconds"`
	}{
		alias:         alias(t),
		WindowSeconds: int64(t.Window.Seconds()),
	})
}

// BanAction is sent from the decision engine to the action layer.
// Internal-only — never crosses the HTTP boundary, so JSON tags are
// nice-to-have but not load-bearing.
type BanAction struct {
	IP       net.IP        `json:"ip"`
	Duration time.Duration `json:"duration"` // 0 = permanent
	Reason   string        `json:"reason"`
	Detector string        `json:"detector"`
	Severity string        `json:"severity"`
	BanCount int           `json:"ban_count"`
}

// BanEntry represents a ban record from the store or enforcer.
//
// Wire contract: see README.md `## API`. `duration` is integer seconds
// (NOT Go's default time.Duration nanoseconds) — see MarshalJSON below.
type BanEntry struct {
	ID        int64         `json:"id"`
	IP        string        `json:"ip"`
	Detector  string        `json:"detector"`
	Reason    string        `json:"reason"`
	Severity  string        `json:"severity"`
	BannedAt  time.Time     `json:"banned_at"`
	Duration  time.Duration `json:"-"` // surfaced via MarshalJSON as integer seconds
	ExpiresAt *time.Time    `json:"expires_at"` // nil if permanent
	BanCount  int           `json:"ban_count"`
	Status    string        `json:"status"` // "active", "expired", "manual", "dry_run"
}

// MarshalJSON serialises Duration as integer seconds.
//
// Go's encoding/json treats time.Duration as int64 nanoseconds by default,
// which would emit `"duration": 3600000000000` for a 1-hour ban — surprising
// for any consumer reading the README. We override here so the wire shape
// is `"duration": 3600`.
func (b BanEntry) MarshalJSON() ([]byte, error) {
	type alias BanEntry
	return json.Marshal(struct {
		alias
		Duration int64 `json:"duration"`
	}{
		alias:    alias(b),
		Duration: int64(b.Duration.Seconds()),
	})
}

// UnmarshalJSON accepts integer seconds (the public wire format) and
// converts to a time.Duration so internal Go code keeps working.
func (b *BanEntry) UnmarshalJSON(data []byte) error {
	type alias BanEntry
	aux := struct {
		*alias
		Duration int64 `json:"duration"`
	}{alias: (*alias)(b)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	b.Duration = time.Duration(aux.Duration) * time.Second
	return nil
}

// NotifyEvent is passed to notifiers on ban/unban.
type NotifyEvent struct {
	Type      string        `json:"type"` // "ban", "unban"
	IP        string        `json:"ip"`
	Detector  string        `json:"detector"`
	Severity  string        `json:"severity"`
	Duration  time.Duration `json:"-"` // surfaced via MarshalJSON as integer seconds
	Reason    string        `json:"reason"`
	Timestamp time.Time     `json:"timestamp"`
}

// MarshalJSON emits Duration as integer seconds (see BanEntry rationale).
func (n NotifyEvent) MarshalJSON() ([]byte, error) {
	type alias NotifyEvent
	return json.Marshal(struct {
		alias
		Duration int64 `json:"duration"`
	}{
		alias:    alias(n),
		Duration: int64(n.Duration.Seconds()),
	})
}

// WhitelistEntry represents a whitelist record.
type WhitelistEntry struct {
	ID        int64     `json:"id"`
	IPCIDR    string    `json:"ip_cidr"`
	Comment   string    `json:"comment"`
	Source    string    `json:"source"` // "static", "dynamic"
	CreatedAt time.Time `json:"created_at"`
}
