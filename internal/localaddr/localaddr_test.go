package localaddr

import (
	"errors"
	"net"
	"testing"
)

func TestSetContainsInterfaceAddrsAndLoopback(t *testing.T) {
	s := New()
	s.addrs = func() ([]net.Addr, error) {
		_, n, _ := net.ParseCIDR("203.0.113.10/24")
		n.IP = net.ParseIP("203.0.113.10")
		return []net.Addr{n, &net.IPAddr{IP: net.ParseIP("2001:db8::1")}}, nil
	}
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}

	for _, ip := range []string{"203.0.113.10", "2001:db8::1", "127.0.0.1", "::1"} {
		if !s.Contains(net.ParseIP(ip)) {
			t.Errorf("Contains(%s) = false, want true", ip)
		}
	}
	// Same subnet is NOT local — only the host's own address is.
	if s.Contains(net.ParseIP("203.0.113.11")) {
		t.Error("Contains(203.0.113.11) = true, want false")
	}
	if s.Contains(nil) {
		t.Error("Contains(nil) = true, want false")
	}
}

func TestSetRefreshErrorKeepsPreviousSet(t *testing.T) {
	s := New()
	s.addrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPAddr{IP: net.ParseIP("203.0.113.10")}}, nil
	}
	s.Refresh()
	s.addrs = func() ([]net.Addr, error) { return nil, errors.New("boom") }
	if err := s.Refresh(); err == nil {
		t.Fatal("expected error")
	}
	if !s.Contains(net.ParseIP("203.0.113.10")) {
		t.Error("previous set lost after failed refresh")
	}
}
