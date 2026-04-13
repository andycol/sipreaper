package whitelist

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/andycol/sipreaper/internal/config"
	"github.com/andycol/sipreaper/internal/store"
)

func newTestWhitelist(t *testing.T) (*Whitelist, *store.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	cfg := []config.StaticWhitelistEntry{
		{IP: "10.0.0.0/8", Comment: "internal"},
		{IP: "192.168.1.1", Comment: "single ip"},
	}

	wl, err := New(cfg, s)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return wl, s
}

func TestStaticWhitelistCIDR(t *testing.T) {
	wl, _ := newTestWhitelist(t)

	if !wl.Contains(net.ParseIP("10.0.0.1")) {
		t.Error("10.0.0.1 should be whitelisted (10.0.0.0/8)")
	}
	if !wl.Contains(net.ParseIP("10.255.255.255")) {
		t.Error("10.255.255.255 should be whitelisted (10.0.0.0/8)")
	}
	if wl.Contains(net.ParseIP("11.0.0.1")) {
		t.Error("11.0.0.1 should not be whitelisted")
	}
}

func TestStaticWhitelistSingleIP(t *testing.T) {
	wl, _ := newTestWhitelist(t)

	if !wl.Contains(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 should be whitelisted")
	}
	if wl.Contains(net.ParseIP("192.168.1.2")) {
		t.Error("192.168.1.2 should not be whitelisted")
	}
}

func TestDynamicWhitelist(t *testing.T) {
	wl, s := newTestWhitelist(t)

	s.AddWhitelist("172.16.0.0/12", "dynamic test", "dynamic")

	if err := wl.ReloadDynamic(); err != nil {
		t.Fatalf("ReloadDynamic() error: %v", err)
	}

	if !wl.Contains(net.ParseIP("172.16.5.10")) {
		t.Error("172.16.5.10 should be whitelisted after dynamic add")
	}
}

func TestReloadStatic(t *testing.T) {
	wl, _ := newTestWhitelist(t)

	newStatic := []config.StaticWhitelistEntry{
		{IP: "203.0.113.0/24", Comment: "new range"},
	}

	if err := wl.ReloadStatic(newStatic); err != nil {
		t.Fatalf("ReloadStatic() error: %v", err)
	}

	if wl.Contains(net.ParseIP("10.0.0.1")) {
		t.Error("10.0.0.1 should no longer be whitelisted after reload")
	}
	if !wl.Contains(net.ParseIP("203.0.113.50")) {
		t.Error("203.0.113.50 should be whitelisted after reload")
	}
}
