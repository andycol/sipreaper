//go:build !linux

// Package banner's non-Linux stub. XDP is a Linux-kernel facility, so on
// darwin (developer machines) and any other GOOS the enforcer is inert: every
// constructor/preflight reports unavailability and the daemon stays on its
// iptables/ipset base enforcer. This file exists so the whole module — daemon,
// CLI, tests — still compiles and runs cross-platform.
package banner

import (
	"errors"
	"net"
	"time"

	"github.com/andycol/sipreaper/internal/action"
)

var errUnsupported = errors.New("xdp enforcer requires linux")

// XdpEnforcer is the stub type. It satisfies action.Enforcer so the daemon can
// hold a concrete *XdpEnforcer handle uniformly across platforms.
type XdpEnforcer struct{}

var _ action.Enforcer = (*XdpEnforcer)(nil)

// Preflight always reports XDP unavailable off Linux.
func Preflight(iface string) string { return "xdp requires linux" }

// NewXdpEnforcer always fails off Linux; the daemon falls open to its base
// enforcer.
func NewXdpEnforcer(iface, mode string) (*XdpEnforcer, error) { return nil, errUnsupported }

func (e *XdpEnforcer) Name() string                                     { return "xdp" }
func (e *XdpEnforcer) Init() error                                      { return errUnsupported }
func (e *XdpEnforcer) Ban(net.IP, time.Duration, string) error          { return errUnsupported }
func (e *XdpEnforcer) Unban(net.IP) error                               { return errUnsupported }
func (e *XdpEnforcer) List() ([]action.BanEntry, error)                 { return nil, nil }
func (e *XdpEnforcer) Close() error                                     { return nil }
func (e *XdpEnforcer) Attached() bool                                   { return false }
func (e *XdpEnforcer) Mode() string                                     { return "" }
func (e *XdpEnforcer) MapEntries() (v4 int, v6 int, err error)          { return 0, 0, errUnsupported }
func (e *XdpEnforcer) Stats() (passed uint64, dropped uint64, e2 error) { return 0, 0, errUnsupported }
