package ingest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestParseKamailioAuthFailure(t *testing.T) {
	line := `Mar 27 10:15:30 sip1 kamailio[1234]: ERROR: auth: authentication failed for alice@example.com from 203.0.113.50`

	evt, err := parseKamailioLine(line)
	if err != nil {
		t.Fatalf("parseKamailioLine() error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected non-nil event")
	}
	if evt.SourceIP.String() != "203.0.113.50" {
		t.Errorf("source ip = %q, want 203.0.113.50", evt.SourceIP)
	}
	if evt.Method != "REGISTER" {
		t.Errorf("method = %q, want REGISTER", evt.Method)
	}
	if evt.ResponseCode != 401 {
		t.Errorf("response code = %d, want 401", evt.ResponseCode)
	}
	if evt.FromUser != "alice" {
		t.Errorf("from user = %q, want alice", evt.FromUser)
	}
}

func TestParseKamailioReceived(t *testing.T) {
	line := `Mar 27 10:15:30 sip1 kamailio[1234]: received REGISTER from 198.51.100.20:5060`

	evt, err := parseKamailioLine(line)
	if err != nil {
		t.Fatalf("parseKamailioLine() error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected non-nil event")
	}
	if evt.SourceIP.String() != "198.51.100.20" {
		t.Errorf("source ip = %q, want 198.51.100.20", evt.SourceIP)
	}
	if evt.Method != "REGISTER" {
		t.Errorf("method = %q, want REGISTER", evt.Method)
	}
}

func TestParseKamailioUnmatchedLine(t *testing.T) {
	line := `Mar 27 10:15:30 sip1 kamailio[1234]: some other log line`

	evt, _ := parseKamailioLine(line)
	if evt != nil {
		t.Error("expected nil event for unmatched line")
	}
}

func TestParseOpenSIPSCarrierRejectionWithDID(t *testing.T) {
	line := `Apr 28 11:02:14 sip2 opensips[4321]: WARNING:Rejected inbound carrier INVITE from non-whitelisted source 77.68.33.97 for DID 64300441975359019`

	evt, err := parseOpenSIPSLine(line)
	if err != nil {
		t.Fatalf("parseOpenSIPSLine() error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected non-nil event for carrier rejection log line")
	}
	if got := evt.SourceIP.String(); got != "77.68.33.97" {
		t.Errorf("source ip = %q, want 77.68.33.97", got)
	}
	if evt.Method != "INVITE" {
		t.Errorf("method = %q, want INVITE", evt.Method)
	}
	if !evt.Rejected {
		t.Error("expected Rejected=true")
	}
	if evt.RejectReason == "" {
		t.Error("expected non-empty RejectReason")
	}
	if evt.ToUser != "64300441975359019" {
		t.Errorf("ToUser (DID) = %q, want 64300441975359019", evt.ToUser)
	}
	if evt.ResponseCode != 403 {
		t.Errorf("response code = %d, want 403", evt.ResponseCode)
	}
}

func TestLogTailerCascadesParsersWhenFormatIsKamailio(t *testing.T) {
	// User has format=kamailio configured but the underlying SIP server is
	// emitting opensips-style rejection lines. The tailer must still recognise
	// them — silently dropping was the bug that let 77.68.33.97 through.
	events := make(chan models.SIPEvent, 1)
	lt := &LogTailer{format: "kamailio", events: events, done: make(chan struct{})}

	line := `Apr 28 11:02:14 sip2 opensips[4321]: WARNING:Rejected inbound carrier INVITE from non-whitelisted source 77.68.33.97 for DID 64300441975359019`
	evt := lt.parseLine(line)
	if evt == nil {
		t.Fatal("expected the cascade to fall through to opensips parser")
	}
	if evt.SourceIP.String() != "77.68.33.97" || !evt.Rejected {
		t.Errorf("unexpected event: %+v", evt)
	}
}

func TestLogTailerReadsNewLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	events := make(chan models.SIPEvent, 10)
	tailer, err := NewLogTailer(logPath, "kamailio", nil, events)
	if err != nil {
		t.Fatalf("NewLogTailer() error: %v", err)
	}
	defer tailer.Stop()

	go tailer.Run()

	time.Sleep(100 * time.Millisecond)

	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString("Mar 27 10:15:30 sip1 kamailio[1234]: ERROR: auth: authentication failed for bob@example.com from 10.0.0.5\n")
	f.Close()

	select {
	case evt := <-events:
		if evt.SourceIP.String() != "10.0.0.5" {
			t.Errorf("source ip = %q, want 10.0.0.5", evt.SourceIP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}
