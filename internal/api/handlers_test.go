package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
	"github.com/andycol/sipreaper/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	srv := NewServer(s, "test-token", "127.0.0.1:0")
	return srv, s
}

func TestGetStatus(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "running" {
		t.Errorf("status = %q, want running", resp["status"])
	}
}

func TestAuthRequired(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status code = %d, want 401", w.Code)
	}
}

func TestListBans(t *testing.T) {
	srv, s := newTestServer(t)

	s.CreateBan(models.BanEntry{
		IP: "10.0.0.1", Detector: "brute_force", Reason: "test",
		Severity: "high", BannedAt: time.Now(), Duration: 5 * time.Minute,
		BanCount: 1, Status: "active",
	})

	req := httptest.NewRequest("GET", "/api/v1/bans", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d, want 200", w.Code)
	}

	var bans []models.BanEntry
	json.NewDecoder(w.Body).Decode(&bans)
	if len(bans) != 1 {
		t.Fatalf("bans len = %d, want 1", len(bans))
	}
	if bans[0].IP != "10.0.0.1" {
		t.Errorf("ban ip = %q, want 10.0.0.1", bans[0].IP)
	}
}

func TestManualBan(t *testing.T) {
	srv, s := newTestServer(t)

	body := `{"ip": "10.0.0.5", "duration": "1h"}`
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status code = %d, want 201", w.Code)
	}

	ban, _ := s.GetActiveBanByIP("10.0.0.5")
	if ban == nil {
		t.Fatal("expected ban to exist in store")
	}
	if ban.Status != "manual" {
		t.Errorf("status = %q, want manual", ban.Status)
	}
}

func TestManualBanRefusesWhitelistedIP(t *testing.T) {
	srv, _ := newTestServer(t)
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	srv.SetWhitelistGuard(func(ip net.IP) bool { return cidr.Contains(ip) })

	body := `{"ip": "10.5.5.5", "duration": "1h"}`
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status code = %d, want 409 for whitelisted IP", w.Code)
	}
}

func TestManualBanRejectsInvalidIP(t *testing.T) {
	srv, _ := newTestServer(t)

	body := `{"ip": "not-an-ip", "duration": "1h"}`
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want 400 for invalid IP", w.Code)
	}
}

func TestManualUnban(t *testing.T) {
	srv, s := newTestServer(t)

	s.CreateBan(models.BanEntry{
		IP: "10.0.0.1", Detector: "manual", Reason: "test",
		Severity: "medium", BannedAt: time.Now(), Duration: 0,
		BanCount: 1, Status: "manual",
	})

	req := httptest.NewRequest("DELETE", "/api/v1/bans/10.0.0.1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d, want 200", w.Code)
	}

	ban, _ := s.GetActiveBanByIP("10.0.0.1")
	if ban != nil {
		t.Error("ban should have been removed")
	}
}

func TestAddWhitelistRefusesBannedIP(t *testing.T) {
	srv, s := newTestServer(t)
	s.CreateBan(models.BanEntry{
		IP: "203.0.113.7", Detector: "brute_force", Reason: "test",
		Severity: "high", BannedAt: time.Now(), Duration: 1 * time.Hour,
		BanCount: 1, Status: "active",
	})

	body := `{"ip": "203.0.113.7", "comment": "oops"}`
	req := httptest.NewRequest("POST", "/api/v1/whitelist", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status code = %d, want 409 for banned IP", w.Code)
	}
}

func TestAddWhitelistWithClearBan(t *testing.T) {
	srv, s := newTestServer(t)
	s.CreateBan(models.BanEntry{
		IP: "203.0.113.8", Detector: "brute_force", Reason: "test",
		Severity: "high", BannedAt: time.Now(), Duration: 1 * time.Hour,
		BanCount: 1, Status: "active",
	})

	var unbanned net.IP
	srv.SetUnbanFunc(func(ip net.IP) error { unbanned = ip; return nil })

	body := `{"ip": "203.0.113.8", "comment": "trusted partner", "clear_ban": true}`
	req := httptest.NewRequest("POST", "/api/v1/whitelist", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want 201", w.Code)
	}
	if unbanned == nil || unbanned.String() != "203.0.113.8" {
		t.Errorf("unban callback got %v, want 203.0.113.8", unbanned)
	}
	ban, _ := s.GetActiveBanByIP("203.0.113.8")
	if ban != nil {
		t.Error("ban should have been expired by clear_ban=true")
	}
}

func TestAddWhitelistAcceptsCIDR(t *testing.T) {
	srv, _ := newTestServer(t)

	body := `{"ip": "10.0.0.0/8", "comment": "internal"}`
	req := httptest.NewRequest("POST", "/api/v1/whitelist", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status code = %d, want 201 (CIDR should be accepted)", w.Code)
	}
}

func TestListWhitelist(t *testing.T) {
	srv, s := newTestServer(t)

	s.AddWhitelist("10.0.0.0/8", "test", "dynamic")

	req := httptest.NewRequest("GET", "/api/v1/whitelist", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d, want 200", w.Code)
	}

	var entries []models.WhitelistEntry
	json.NewDecoder(w.Body).Decode(&entries)
	if len(entries) != 1 {
		t.Fatalf("whitelist len = %d, want 1", len(entries))
	}
}
