// JSON wire-format contract tests.
//
// These tests pin the *external* JSON shape returned by the HTTP API,
// not just round-tripping through Go's typed structs. The README and
// downstream admin UIs expect
// snake_case keys and integer-second durations. Without explicit JSON
// tags on the model structs Go's encoding/json silently emits
// PascalCase field names — see the Go type definitions in
// internal/models/models.go.
//
// Decoding into a typed struct will mask both bugs (Go matches both
// "ip" and "IP" against an exported field), so we deliberately decode
// into map[string]interface{} here and assert on raw key names.

package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

// requireKeys asserts every key in `want` is present in `got`. It does
// NOT assert absence of unexpected keys — adding new fields shouldn't
// fail this contract test.
func requireKeys(t *testing.T, label string, got map[string]interface{}, want []string) {
	t.Helper()
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%s: missing expected key %q. got keys = %v", label, k, keys(got))
		}
	}
}

func keys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------
// GET /api/v1/bans
// ---------------------------------------------------------------------

func TestListBansJSONContract(t *testing.T) {
	srv, s := newTestServer(t)

	expiresAt := time.Now().Add(1 * time.Hour)
	s.CreateBan(models.BanEntry{
		IP:        "10.0.0.99",
		Detector:  "brute_force",
		Reason:    "contract test",
		Severity:  "high",
		BannedAt:  time.Now(),
		Duration:  1 * time.Hour,
		ExpiresAt: &expiresAt,
		BanCount:  1,
		Status:    "active",
	})

	req := httptest.NewRequest("GET", "/api/v1/bans", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var bans []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&bans); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("len(bans) = %d, want 1", len(bans))
	}

	requireKeys(t, "bans[0]", bans[0], []string{
		"id", "ip", "detector", "reason", "severity",
		"banned_at", "duration", "expires_at", "ban_count", "status",
	})

	// Duration MUST be integer seconds, not Go's default nanoseconds.
	// 1 hour == 3600 seconds; nanoseconds would be 3.6e12.
	switch v := bans[0]["duration"].(type) {
	case float64:
		if v != 3600 {
			t.Errorf("duration = %v, want 3600 seconds", v)
		}
	default:
		t.Errorf("duration has wrong type %T (want number/seconds), value = %v", v, v)
	}

	// Sanity-check a couple of expected lowercase values.
	if got := bans[0]["status"]; got != "active" {
		t.Errorf("status = %v, want active", got)
	}
	if got := bans[0]["ip"]; got != "10.0.0.99" {
		t.Errorf("ip = %v, want 10.0.0.99", got)
	}
}

// ---------------------------------------------------------------------
// POST /api/v1/bans (manual)
// ---------------------------------------------------------------------

func TestCreateBanJSONContract(t *testing.T) {
	srv, _ := newTestServer(t)

	body := `{"ip": "10.0.0.7", "duration": "2h"}`
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}

	var ban map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&ban); err != nil {
		t.Fatalf("decode: %v", err)
	}

	requireKeys(t, "ban", ban, []string{
		"id", "ip", "detector", "reason", "severity",
		"banned_at", "duration", "expires_at", "ban_count", "status",
	})
	if got := ban["status"]; got != "manual" {
		t.Errorf("status = %v, want manual", got)
	}
	if v, ok := ban["duration"].(float64); !ok || v != 7200 {
		t.Errorf("duration = %v (%T), want 7200 seconds", ban["duration"], ban["duration"])
	}
}

// ---------------------------------------------------------------------
// GET /api/v1/whitelist
// ---------------------------------------------------------------------

func TestListWhitelistJSONContract(t *testing.T) {
	srv, s := newTestServer(t)

	if _, err := s.AddWhitelist("10.0.0.0/8", "contract test", "dynamic"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/v1/whitelist", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var entries []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}

	requireKeys(t, "whitelist[0]", entries[0], []string{
		"id", "ip_cidr", "comment", "source", "created_at",
	})
	if got := entries[0]["ip_cidr"]; got != "10.0.0.0/8" {
		t.Errorf("ip_cidr = %v, want 10.0.0.0/8", got)
	}
	if got := entries[0]["source"]; got != "dynamic" {
		t.Errorf("source = %v, want dynamic", got)
	}
}

// ---------------------------------------------------------------------
// POST /api/v1/whitelist
// ---------------------------------------------------------------------

func TestCreateWhitelistJSONContract(t *testing.T) {
	srv, _ := newTestServer(t)

	body := `{"ip": "10.0.0.0/8", "comment": "contract test"}`
	req := httptest.NewRequest("POST", "/api/v1/whitelist", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}

	var entry map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&entry); err != nil {
		t.Fatalf("decode: %v", err)
	}

	requireKeys(t, "whitelist create", entry, []string{
		"id", "ip_cidr", "comment", "source", "created_at",
	})
	if got := entry["ip_cidr"]; got != "10.0.0.0/8" {
		t.Errorf("ip_cidr = %v, want 10.0.0.0/8", got)
	}
	if got := entry["comment"]; got != "contract test" {
		t.Errorf("comment = %v, want contract test", got)
	}
	if got := entry["source"]; got != "dynamic" {
		t.Errorf("source = %v, want dynamic", got)
	}
}

// ---------------------------------------------------------------------
// GET /api/v1/events — SIP event JSON contract
// ---------------------------------------------------------------------

func TestListEventsJSONContract(t *testing.T) {
	srv, s := newTestServer(t)

	if err := s.RecordEvent(models.SIPEvent{
		Timestamp:    time.Now(),
		SourceIP:     net.ParseIP("10.0.0.42"),
		Method:       "REGISTER",
		UserAgent:    "friendly-scanner",
		FromUser:     "100",
		ToUser:       "200",
		CallID:       "abc-123",
		ResponseCode: 401,
		Source:       "log",
		Rejected:     true,
		RejectReason: "auth failed",
	}, "brute_force"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var events []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&events); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least 1 event")
	}

	// Only assert the externally-visible README-documented keys; the
	// store may add internal columns we don't care about pinning here.
	requireKeys(t, "events[0]", events[0], []string{
		"timestamp", "source_ip", "method", "user_agent",
		"from_user", "to_user", "call_id", "response_code",
		"source", "rejected", "reject_reason",
	})
	if got := events[0]["method"]; got != "REGISTER" {
		t.Errorf("method = %v, want REGISTER", got)
	}
	if got := events[0]["source_ip"]; got != "10.0.0.42" {
		t.Errorf("source_ip = %v, want 10.0.0.42", got)
	}
	if got := events[0]["user_agent"]; got != "friendly-scanner" {
		t.Errorf("user_agent = %v, want friendly-scanner", got)
	}
	if got := events[0]["from_user"]; got != "100" {
		t.Errorf("from_user = %v, want 100", got)
	}
	if got := events[0]["to_user"]; got != "200" {
		t.Errorf("to_user = %v, want 200", got)
	}
	if got := events[0]["call_id"]; got != "abc-123" {
		t.Errorf("call_id = %v, want abc-123", got)
	}
	if got := events[0]["response_code"]; got != float64(401) {
		t.Errorf("response_code = %v, want 401", got)
	}
	if got := events[0]["source"]; got != "log" {
		t.Errorf("source = %v, want log", got)
	}
	if got := events[0]["rejected"]; got != true {
		t.Errorf("rejected = %v, want true", got)
	}
	if got := events[0]["reject_reason"]; got != "auth failed" {
		t.Errorf("reject_reason = %v, want auth failed", got)
	}
}
