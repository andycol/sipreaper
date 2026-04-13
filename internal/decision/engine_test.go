package decision

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/config"
	"github.com/andycol/sipreaper/internal/models"
	"github.com/andycol/sipreaper/internal/store"
	"github.com/andycol/sipreaper/internal/whitelist"
)

func newTestEngine(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	wl, err := whitelist.New([]config.StaticWhitelistEntry{
		{IP: "192.168.1.0/24", Comment: "internal"},
	}, s)
	if err != nil {
		t.Fatal(err)
	}

	durations := []time.Duration{5 * time.Minute, 30 * time.Minute, 2 * time.Hour}
	eng := New(s, wl, durations, 48*time.Hour)
	return eng, s
}

func TestDecisionBansOnThreat(t *testing.T) {
	eng, _ := newTestEngine(t)

	threat := models.Threat{
		Timestamp: time.Now(), SourceIP: net.ParseIP("10.0.0.1"),
		Detector: "brute_force", Severity: "high",
		Description: "test", EventCount: 5, Window: 60 * time.Second,
	}

	action := eng.Evaluate(threat)
	if action == nil {
		t.Fatal("expected ban action")
	}
	if action.IP.String() != "10.0.0.1" {
		t.Errorf("ban ip = %q, want 10.0.0.1", action.IP)
	}
	if action.Duration != 5*time.Minute {
		t.Errorf("duration = %v, want 5m", action.Duration)
	}
	if action.BanCount != 1 {
		t.Errorf("ban count = %d, want 1", action.BanCount)
	}
}

func TestDecisionWhitelistedIPNotBanned(t *testing.T) {
	eng, _ := newTestEngine(t)

	threat := models.Threat{
		Timestamp: time.Now(), SourceIP: net.ParseIP("192.168.1.50"),
		Detector: "brute_force", Severity: "high",
		Description: "test", EventCount: 5,
	}

	action := eng.Evaluate(threat)
	if action != nil {
		t.Error("whitelisted IP should not be banned")
	}
}

func TestDecisionAlreadyBannedSkips(t *testing.T) {
	eng, s := newTestEngine(t)

	s.CreateBan(models.BanEntry{
		IP: "10.0.0.1", Detector: "brute_force", Reason: "test",
		Severity: "high", BannedAt: time.Now(), Duration: 5 * time.Minute,
		BanCount: 1, Status: "active",
	})

	threat := models.Threat{
		Timestamp: time.Now(), SourceIP: net.ParseIP("10.0.0.1"),
		Detector: "brute_force", Severity: "high",
		Description: "test", EventCount: 5,
	}

	action := eng.Evaluate(threat)
	if action != nil {
		t.Error("already-banned IP should not get another ban action")
	}
}

func TestDecisionEscalatingDurations(t *testing.T) {
	eng, s := newTestEngine(t)

	for i := 0; i < 2; i++ {
		s.CreateBan(models.BanEntry{
			IP: "10.0.0.2", Detector: "brute_force", Reason: "test",
			Severity: "high", BannedAt: time.Now(), Duration: 5 * time.Minute,
			BanCount: i + 1, Status: "expired",
		})
	}

	threat := models.Threat{
		Timestamp: time.Now(), SourceIP: net.ParseIP("10.0.0.2"),
		Detector: "brute_force", Severity: "high",
		Description: "test", EventCount: 5,
	}

	action := eng.Evaluate(threat)
	if action == nil {
		t.Fatal("expected ban action")
	}
	if action.Duration != 2*time.Hour {
		t.Errorf("duration = %v, want 2h (3rd ban)", action.Duration)
	}
	if action.BanCount != 3 {
		t.Errorf("ban count = %d, want 3", action.BanCount)
	}
}
