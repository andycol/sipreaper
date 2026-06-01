package action

import (
	"errors"
	"net"
	"strings"
	"time"
)

// CompositeEnforcer fans Ban/Unban out to several backing enforcers so a ban
// is applied by all of them (e.g. iptables/ipset AND XDP). This makes the XDP
// rollout purely additive: the proven iptables path stays as a safety net
// while XDP runs alongside, and only after the benchmark proves parity does
// XDP optionally stand alone.
//
// Ban/Unban are best-effort across members: one backend failing must not block
// the other, so errors are collected and joined rather than short-circuited.
// List returns member[0]'s view — by convention the iptables/ipset/DB-backed
// base — so the user-facing ban list stays single-sourced and never shows
// doubled rows. The XDP map view is surfaced separately via /xdp/status.
type CompositeEnforcer struct {
	members []Enforcer
}

func NewCompositeEnforcer(members ...Enforcer) *CompositeEnforcer {
	return &CompositeEnforcer{members: members}
}

// Members exposes the backing enforcers for reconcile and diagnostics.
func (c *CompositeEnforcer) Members() []Enforcer { return c.members }

func (c *CompositeEnforcer) Name() string {
	names := make([]string, len(c.members))
	for i, m := range c.members {
		names[i] = m.Name()
	}
	return "composite(" + strings.Join(names, ",") + ")"
}

func (c *CompositeEnforcer) Ban(ip net.IP, d time.Duration, reason string) error {
	var errs []error
	for _, m := range c.members {
		if err := m.Ban(ip, d, reason); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *CompositeEnforcer) Unban(ip net.IP) error {
	var errs []error
	for _, m := range c.members {
		if err := m.Unban(ip); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *CompositeEnforcer) List() ([]BanEntry, error) {
	if len(c.members) == 0 {
		return nil, nil
	}
	return c.members[0].List()
}
