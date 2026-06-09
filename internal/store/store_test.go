package store

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := New(path)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateAndGetBan(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)
	expires := now.Add(5 * time.Minute)

	entry := models.BanEntry{
		IP:        "192.168.1.100",
		Detector:  "brute_force",
		Reason:    "5 failed registrations in 60s",
		Severity:  "high",
		BannedAt:  now,
		Duration:  5 * time.Minute,
		ExpiresAt: &expires,
		BanCount:  1,
		Status:    "active",
	}

	id, err := s.CreateBan(entry)
	if err != nil {
		t.Fatalf("CreateBan() error: %v", err)
	}
	if id == 0 {
		t.Error("CreateBan() returned id 0")
	}

	bans, err := s.ListBans("active")
	if err != nil {
		t.Fatalf("ListBans() error: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("ListBans() len = %d, want 1", len(bans))
	}
	if bans[0].IP != "192.168.1.100" {
		t.Errorf("ban IP = %q, want 192.168.1.100", bans[0].IP)
	}
	if bans[0].BanCount != 1 {
		t.Errorf("ban count = %d, want 1", bans[0].BanCount)
	}
}

func TestUpdateBanStatus(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	entry := models.BanEntry{
		IP: "10.0.0.1", Detector: "scanner", Reason: "scan",
		Severity: "medium", BannedAt: now, Duration: 5 * time.Minute,
		BanCount: 1, Status: "active",
	}
	id, _ := s.CreateBan(entry)

	if err := s.UpdateBanStatus(id, "expired"); err != nil {
		t.Fatalf("UpdateBanStatus() error: %v", err)
	}

	bans, _ := s.ListBans("active")
	if len(bans) != 0 {
		t.Error("expected no active bans after expiry")
	}

	bans, _ = s.ListBans("")
	if len(bans) != 1 || bans[0].Status != "expired" {
		t.Error("expected one expired ban")
	}
}

func TestGetActiveBanByIP(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	entry := models.BanEntry{
		IP: "1.2.3.4", Detector: "brute_force", Reason: "test",
		Severity: "high", BannedAt: now, Duration: 5 * time.Minute,
		BanCount: 1, Status: "active",
	}
	s.CreateBan(entry)

	ban, err := s.GetActiveBanByIP("1.2.3.4")
	if err != nil {
		t.Fatalf("GetActiveBanByIP() error: %v", err)
	}
	if ban == nil {
		t.Fatal("expected non-nil ban")
	}
	if ban.IP != "1.2.3.4" {
		t.Errorf("ban IP = %q, want 1.2.3.4", ban.IP)
	}

	ban, err = s.GetActiveBanByIP("5.6.7.8")
	if err != nil {
		t.Fatalf("GetActiveBanByIP() error: %v", err)
	}
	if ban != nil {
		t.Error("expected nil ban for unknown IP")
	}
}

func TestManualBansAreCurrentAndExpire(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	expires := now.Add(time.Hour)

	_, err := s.CreateBan(models.BanEntry{
		IP: "203.0.113.10", Detector: "manual", Reason: "operator",
		Severity: "medium", BannedAt: now, Duration: time.Hour,
		ExpiresAt: &expires, BanCount: 1, Status: "manual",
	})
	if err != nil {
		t.Fatalf("CreateBan() error: %v", err)
	}

	current, err := s.ListEnforcedBans()
	if err != nil {
		t.Fatalf("ListEnforcedBans() error: %v", err)
	}
	if len(current) != 1 || current[0].Status != "manual" {
		t.Fatalf("current bans = %+v, want one manual ban", current)
	}

	expired, err := s.GetExpiredBans()
	if err != nil {
		t.Fatalf("GetExpiredBans() error: %v", err)
	}
	if len(expired) != 1 || expired[0].IP != "203.0.113.10" {
		t.Fatalf("expired bans = %+v, want manual ban", expired)
	}
}

func TestBanCountByIP(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)
	since := now.Add(-1 * time.Hour)

	for i := 0; i < 3; i++ {
		entry := models.BanEntry{
			IP: "1.2.3.4", Detector: "brute_force", Reason: "test",
			Severity: "high", BannedAt: now, Duration: 5 * time.Minute,
			BanCount: i + 1, Status: "expired",
		}
		s.CreateBan(entry)
	}

	count, err := s.BanCountByIP("1.2.3.4", since)
	if err != nil {
		t.Fatalf("BanCountByIP() error: %v", err)
	}
	if count != 3 {
		t.Errorf("ban count = %d, want 3", count)
	}
}

func TestRecordEvent(t *testing.T) {
	s := newTestStore(t)

	evt := models.SIPEvent{
		Timestamp: time.Now(), SourceIP: net.ParseIP("10.0.0.1"),
		Method: "REGISTER", Source: "log",
	}
	if err := s.RecordEvent(evt, "brute_force"); err != nil {
		t.Fatalf("RecordEvent() error: %v", err)
	}

	events, err := s.ListEvents("", "", 0, 100)
	if err != nil {
		t.Fatalf("ListEvents() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
}

func TestWhitelistCRUD(t *testing.T) {
	s := newTestStore(t)

	id, err := s.AddWhitelist("10.0.0.0/8", "internal", "dynamic")
	if err != nil {
		t.Fatalf("AddWhitelist() error: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero id")
	}

	entries, err := s.ListWhitelist()
	if err != nil {
		t.Fatalf("ListWhitelist() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("whitelist len = %d, want 1", len(entries))
	}
	if entries[0].IPCIDR != "10.0.0.0/8" {
		t.Errorf("ip_cidr = %q, want 10.0.0.0/8", entries[0].IPCIDR)
	}

	if err := s.RemoveWhitelist("10.0.0.0/8"); err != nil {
		t.Fatalf("RemoveWhitelist() error: %v", err)
	}

	entries, _ = s.ListWhitelist()
	if len(entries) != 0 {
		t.Error("expected empty whitelist after remove")
	}
}
