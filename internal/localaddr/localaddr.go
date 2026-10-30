// Package localaddr tracks the IP addresses bound to this host's interfaces.
//
// sipreaper runs on the SIP server itself, so any packet whose source is one
// of these addresses is the server's own traffic (forwarded INVITEs, nathelper
// OPTIONS pings, replies to carriers) — never an attacker. The set is
// refreshed periodically so VIPs moved in by keepalived etc. are picked up.
package localaddr

import (
	"net"
	"sync"
)

type Set struct {
	mu    sync.RWMutex
	ips   map[string]struct{}
	addrs func() ([]net.Addr, error)
}

func New() *Set {
	return &Set{ips: map[string]struct{}{}, addrs: net.InterfaceAddrs}
}

// Refresh re-reads the interface addresses. On error the previous set is kept.
func (s *Set) Refresh() error {
	addrs, err := s.addrs()
	if err != nil {
		return err
	}
	ips := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil {
			ips[ip.String()] = struct{}{}
		}
	}
	s.mu.Lock()
	s.ips = ips
	s.mu.Unlock()
	return nil
}

func (s *Set) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.ips[ip.String()]
	return ok
}

// List returns the current addresses, for logging.
func (s *Set) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.ips))
	for ip := range s.ips {
		out = append(out, ip)
	}
	return out
}
