package ingest

import (
	"fmt"
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

// Real lines from a Phonovo OpenSIPS log.
func TestParseOpenSIPSRejectedLinesFromProduction(t *testing.T) {
	prefix := `2026-10-29T14:41:00.616046+00:00 ip-172-30-2-67 /usr/local/sbin/opensips[1325982]: WARNING:`
	tests := []struct {
		name     string
		line     string
		wantIP   string // "" = must produce no Rejected event
		wantDID  string
		wantMeth string
	}{
		{
			name:   "carrier acl",
			line:   prefix + `Rejected inbound carrier INVITE from non-whitelisted source 160.119.76.168 for DID 100`,
			wantIP: "160.119.76.168", wantDID: "100", wantMeth: "INVITE",
		},
		{
			// R-URI host (our own public IP) comes after the source; must not be picked.
			name:   "teams acl with ip in ruri",
			line:   prefix + `Rejected Teams ingress from non-whitelisted source 198.51.100.9 for INVITE sip:+441234@13.43.178.101:5061`,
			wantIP: "198.51.100.9", wantMeth: "INVITE",
		},
		{
			// Customer-side problem; the first IP is the phone's Call-ID host.
			name: "device without registration",
			line: prefix + `Rejected device INVITE without active registration callid=0_672753403@192.168.68.133 from=1006@ipcortex.phonovo.io source=195.180.36.101:45371`,
		},
		{
			name: "device auth mismatch",
			line: prefix + `Rejected device INVITE auth mismatch callid=abc@10.0.0.5 auth=1001 from=1006@13.43.178.101 source=195.180.36.101`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt, _ := parseOpenSIPSLine(tt.line)
			if tt.wantIP == "" {
				if evt != nil && evt.Rejected {
					t.Fatalf("expected no Rejected event, got %+v", evt)
				}
				return
			}
			if evt == nil || !evt.Rejected {
				t.Fatalf("expected Rejected event, got %+v", evt)
			}
			if evt.SourceIP.String() != tt.wantIP {
				t.Errorf("ip = %s, want %s", evt.SourceIP, tt.wantIP)
			}
			if evt.ToUser != tt.wantDID {
				t.Errorf("DID = %q, want %q", evt.ToUser, tt.wantDID)
			}
			if evt.Method != tt.wantMeth {
				t.Errorf("method = %q, want %q", evt.Method, tt.wantMeth)
			}
		})
	}
}

const authFailLine = "Mar 27 10:15:30 sip1 kamailio[1234]: ERROR: auth: authentication failed for bob@example.com from %s\n"

func startTailer(t *testing.T, logPath string) <-chan models.SIPEvent {
	t.Helper()
	events := make(chan models.SIPEvent, 10)
	tailer, err := NewLogTailer(logPath, "kamailio", nil, events)
	if err != nil {
		t.Fatal(err)
	}
	tailer.pollInterval = 10 * time.Millisecond
	tailer.rotateCheck = 20 * time.Millisecond
	t.Cleanup(tailer.Stop)
	go tailer.Run()
	time.Sleep(50 * time.Millisecond) // let it open and seek to the end
	return events
}

func appendLog(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func expectIP(t *testing.T, events <-chan models.SIPEvent, want string) {
	t.Helper()
	select {
	case evt := <-events:
		if evt.SourceIP.String() != want {
			t.Errorf("source ip = %s, want %s", evt.SourceIP, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event from %s", want)
	}
}

// logrotate's default: rename the file away and create a fresh one.
func TestLogTailerFollowsRenameRotation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "opensips.log")
	appendLog(t, logPath, "")
	events := startTailer(t, logPath)

	appendLog(t, logPath, fmt.Sprintf(authFailLine, "10.0.0.1"))
	expectIP(t, events, "10.0.0.1")

	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	// A late write to the old file still gets read before switching.
	appendLog(t, logPath+".1", fmt.Sprintf(authFailLine, "10.0.0.2"))
	expectIP(t, events, "10.0.0.2")

	appendLog(t, logPath, fmt.Sprintf(authFailLine, "10.0.0.3"))
	expectIP(t, events, "10.0.0.3")
}

// logrotate copytruncate: same file, cut back to zero length.
func TestLogTailerFollowsTruncation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "opensips.log")
	appendLog(t, logPath, "")
	events := startTailer(t, logPath)

	appendLog(t, logPath, fmt.Sprintf(authFailLine, "10.0.0.1"))
	expectIP(t, events, "10.0.0.1")

	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let it notice before new data lands
	appendLog(t, logPath, fmt.Sprintf(authFailLine, "10.0.0.4"))
	expectIP(t, events, "10.0.0.4")
}

// A writer flushing half a line must not lose it: the old loop dropped the
// partial read at EOF and then parsed only the tail.
func TestLogTailerJoinsLineSplitAcrossWrites(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "opensips.log")
	appendLog(t, logPath, "")
	events := startTailer(t, logPath)

	line := fmt.Sprintf(authFailLine, "10.0.0.5")
	cut := len(line) - 5 // mid-IP, so neither half parses on its own
	appendLog(t, logPath, line[:cut])
	time.Sleep(50 * time.Millisecond)
	appendLog(t, logPath, line[cut:])
	expectIP(t, events, "10.0.0.5")
}

func TestLogTailerWaitsForMissingFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "opensips.log")
	events := startTailer(t, logPath)

	// Created after startup, so it is read from the start.
	appendLog(t, logPath, fmt.Sprintf(authFailLine, "10.0.0.6"))
	expectIP(t, events, "10.0.0.6")
}
