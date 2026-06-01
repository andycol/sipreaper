package action

import (
	"errors"
	"net"
	"testing"
	"time"
)

type fakeEnforcer struct {
	name     string
	banned   map[string]bool
	banErr   error
	unbanErr error
}

func newFake(name string) *fakeEnforcer {
	return &fakeEnforcer{name: name, banned: map[string]bool{}}
}

func (f *fakeEnforcer) Name() string { return f.name }
func (f *fakeEnforcer) Ban(ip net.IP, _ time.Duration, _ string) error {
	if f.banErr != nil {
		return f.banErr
	}
	f.banned[ip.String()] = true
	return nil
}
func (f *fakeEnforcer) Unban(ip net.IP) error {
	if f.unbanErr != nil {
		return f.unbanErr
	}
	delete(f.banned, ip.String())
	return nil
}
func (f *fakeEnforcer) List() ([]BanEntry, error) {
	var out []BanEntry
	for ip := range f.banned {
		out = append(out, BanEntry{IP: ip})
	}
	return out, nil
}

func TestCompositeFansOut(t *testing.T) {
	a, b := newFake("iptables"), newFake("xdp")
	c := NewCompositeEnforcer(a, b)

	ip := net.ParseIP("1.2.3.4")
	if err := c.Ban(ip, time.Minute, "x"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !a.banned["1.2.3.4"] || !b.banned["1.2.3.4"] {
		t.Fatal("ban did not reach both members")
	}
	if err := c.Unban(ip); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if a.banned["1.2.3.4"] || b.banned["1.2.3.4"] {
		t.Fatal("unban did not reach both members")
	}
}

// TestCompositeJoinsErrorsBestEffort: one member failing must not stop the
// other from being applied; both errors surface.
func TestCompositeJoinsErrorsBestEffort(t *testing.T) {
	a, b := newFake("iptables"), newFake("xdp")
	a.banErr = errors.New("iptables boom")
	c := NewCompositeEnforcer(a, b)

	err := c.Ban(net.ParseIP("5.6.7.8"), 0, "")
	if err == nil {
		t.Fatal("expected error from failing member")
	}
	if !b.banned["5.6.7.8"] {
		t.Fatal("second member should still have been applied despite first failing")
	}
}

// TestCompositeListIsMemberZero: the user-facing list is member[0] only.
func TestCompositeListIsMemberZero(t *testing.T) {
	a, b := newFake("iptables"), newFake("xdp")
	a.banned["1.1.1.1"] = true
	b.banned["2.2.2.2"] = true
	c := NewCompositeEnforcer(a, b)

	entries, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].IP != "1.1.1.1" {
		t.Fatalf("List = %+v, want only member[0]'s 1.1.1.1", entries)
	}
}

func TestCompositeName(t *testing.T) {
	c := NewCompositeEnforcer(newFake("iptables"), newFake("xdp"))
	if got := c.Name(); got != "composite(iptables,xdp)" {
		t.Fatalf("Name = %q", got)
	}
}
