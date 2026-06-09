//go:build !linux || !xdp

// Package banner's stub keeps the default build free of generated eBPF
// bindings. XDP is available only in Linux builds compiled with -tags xdp; all
// other builds report unavailability and the daemon stays on its iptables/ipset
// base enforcer.
package banner

import (
	"errors"
	"net"
	"time"

	"github.com/andycol/sipreaper/internal/action"
)

var errUnsupported = errors.New("xdp enforcer requires linux and a binary built with -tags xdp")

// XdpEnforcer is the stub type. It satisfies action.Enforcer so the daemon can
// hold a concrete *XdpEnforcer handle uniformly across platforms.
type XdpEnforcer struct{}

var _ action.Enforcer = (*XdpEnforcer)(nil)

// Preflight reports XDP unavailable when this binary was not built with XDP
// support.
func Preflight(iface string) string { return errUnsupported.Error() }

// NewXdpEnforcer always fails without XDP build support; the daemon falls open
// to its base enforcer.
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
