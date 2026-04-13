package whitelist

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/andycol/sipreaper/internal/config"
	"github.com/andycol/sipreaper/internal/store"
)

type Whitelist struct {
	mu      sync.RWMutex
	static  []*net.IPNet
	dynamic []*net.IPNet
	store   *store.Store
}

func New(staticEntries []config.StaticWhitelistEntry, s *store.Store) (*Whitelist, error) {
	wl := &Whitelist{store: s}

	if err := wl.ReloadStatic(staticEntries); err != nil {
		return nil, err
	}
	if err := wl.ReloadDynamic(); err != nil {
		return nil, err
	}

	return wl, nil
}

func (wl *Whitelist) Contains(ip net.IP) bool {
	wl.mu.RLock()
	defer wl.mu.RUnlock()

	for _, n := range wl.static {
		if n.Contains(ip) {
			return true
		}
	}
	for _, n := range wl.dynamic {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (wl *Whitelist) ReloadStatic(entries []config.StaticWhitelistEntry) error {
	nets, err := parseEntries(entries)
	if err != nil {
		return fmt.Errorf("parsing static whitelist: %w", err)
	}

	wl.mu.Lock()
	wl.static = nets
	wl.mu.Unlock()
	return nil
}

func (wl *Whitelist) ReloadDynamic() error {
	entries, err := wl.store.ListWhitelist()
	if err != nil {
		return fmt.Errorf("loading dynamic whitelist: %w", err)
	}

	var nets []*net.IPNet
	for _, e := range entries {
		n, err := parseCIDR(e.IPCIDR)
		if err != nil {
			return fmt.Errorf("parsing dynamic entry %q: %w", e.IPCIDR, err)
		}
		nets = append(nets, n)
	}

	wl.mu.Lock()
	wl.dynamic = nets
	wl.mu.Unlock()
	return nil
}

func parseEntries(entries []config.StaticWhitelistEntry) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, e := range entries {
		n, err := parseCIDR(e.IP)
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", e.IP, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func parseCIDR(s string) (*net.IPNet, error) {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", s)
		}
		if ip.To4() != nil {
			s = s + "/32"
		} else {
			s = s + "/128"
		}
	}
	_, n, err := net.ParseCIDR(s)
	return n, err
}
