package action

import (
	"net"
	"time"
)

// BanEntry represents an active ban in the enforcer.
type BanEntry struct {
	IP       string
	Duration time.Duration
}

// Enforcer enforces bans at the network level.
type Enforcer interface {
	Name() string
	Ban(ip net.IP, duration time.Duration, reason string) error
	Unban(ip net.IP) error
	List() ([]BanEntry, error)
}
