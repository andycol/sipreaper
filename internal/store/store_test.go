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

func TestListBansFilteredPageAndCount(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if _, err := s.CreateBan(models.BanEntry{
			IP: ip, Detector: "scanner", Reason: "scan",
			Severity: "medium", BannedAt: now.Add(time.Duration(i) * time.Minute),
			Duration: 5 * time.Minute, BanCount: 1, Status: "active",
		}); err != nil {
			t.Fatalf("CreateBan(%s) error: %v", ip, err)
		}
	}

	total, err := s.CountBansFiltered("current", "")
	if err != nil {
		t.Fatalf("CountBansFiltered() error: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}

	bans, err := s.ListBansFilteredPage("current", "", 2, 1)
	if err != nil {
		t.Fatalf("ListBansFilteredPage() error: %v", err)
	}
	if len(bans) != 2 {
		t.Fatalf("len(bans) = %d, want 2", len(bans))
	}
	if bans[0].IP != "10.0.0.2" || bans[1].IP != "10.0.0.1" {
		t.Fatalf("page IPs = %s,%s; want 10.0.0.2,10.0.0.1", bans[0].IP, bans[1].IP)
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
		Method: "REGISTER", Source: "log", UserAgent: "friendly-scanner",
		FromUser: "100", ToUser: "200", CallID: "abc-123",
		ResponseCode: 401, Rejected: true, RejectReason: "auth failed",
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
	if got := events[0].UserAgent; got != "friendly-scanner" {
		t.Errorf("user agent = %q, want friendly-scanner", got)
	}
	if got := events[0].FromUser; got != "100" {
		t.Errorf("from user = %q, want 100", got)
	}
	if got := events[0].ToUser; got != "200" {
		t.Errorf("to user = %q, want 200", got)
	}
	if got := events[0].CallID; got != "abc-123" {
		t.Errorf("call id = %q, want abc-123", got)
	}
	if got := events[0].ResponseCode; got != 401 {
		t.Errorf("response code = %d, want 401", got)
	}
	if got := events[0].Source; got != "log" {
		t.Errorf("source = %q, want log", got)
	}
	if !events[0].Rejected {
		t.Error("rejected = false, want true")
	}
	if got := events[0].RejectReason; got != "auth failed" {
		t.Errorf("reject reason = %q, want auth failed", got)
	}
}

func TestPruneEventsOlderThan(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	oldEvent := models.SIPEvent{
		Timestamp: now.Add(-48 * time.Hour), SourceIP: net.ParseIP("10.0.0.1"),
		Method: "REGISTER", Source: "log",
	}
	newEvent := models.SIPEvent{
		Timestamp: now, SourceIP: net.ParseIP("10.0.0.2"),
		Method: "INVITE", Source: "pcap",
	}

	if err := s.RecordEvent(oldEvent, "scanner"); err != nil {
		t.Fatalf("RecordEvent(old) error: %v", err)
	}
	if err := s.RecordEvent(newEvent, "scanner"); err != nil {
		t.Fatalf("RecordEvent(new) error: %v", err)
	}

	deleted, err := s.PruneEventsOlderThan(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("PruneEventsOlderThan() error: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}

	events, err := s.ListEvents("", "", 0, 10)
	if err != nil {
		t.Fatalf("ListEvents() error: %v", err)
	}
	if len(events) != 1 || !events[0].SourceIP.Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("remaining events = %+v, want only 10.0.0.2", events)
	}
}

func TestWhitelistCRUD(t *testing.T) {
	s := newTestStore(t)

	entry, err := s.AddWhitelist("10.0.0.0/8", "internal", "dynamic")
	if err != nil {
		t.Fatalf("AddWhitelist() error: %v", err)
	}
	if entry.ID == 0 {
		t.Error("expected non-zero id")
	}
	if entry.IPCIDR != "10.0.0.0/8" || entry.Comment != "internal" || entry.Source != "dynamic" {
		t.Fatalf("AddWhitelist() entry = %+v, want stored whitelist entry", entry)
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
