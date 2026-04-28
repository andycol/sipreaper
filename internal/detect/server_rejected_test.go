package detect

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestServerRejectedIgnoresNonRejectedEvents(t *testing.T) {
	d := NewServerRejected(1, time.Minute)
	evt := models.SIPEvent{
		Timestamp: time.Now(),
		SourceIP:  net.ParseIP("198.51.100.10"),
		Method:    "INVITE",
		Rejected:  false,
	}
	if threat := d.Detect(evt); threat != nil {
		t.Fatalf("expected no threat for non-rejected event, got %+v", threat)
	}
}

func TestServerRejectedFiresImmediatelyAtDefault(t *testing.T) {
	d := NewServerRejected(1, time.Minute)
	evt := models.SIPEvent{
		Timestamp:    time.Now(),
		SourceIP:     net.ParseIP("77.68.33.97"),
		Method:       "INVITE",
		Rejected:     true,
		RejectReason: "non-whitelisted source",
	}

	threat := d.Detect(evt)
	if threat == nil {
		t.Fatal("expected immediate threat for first rejected event with max_hits=1")
	}
	if threat.Detector != "server_rejected" {
		t.Errorf("detector = %q, want server_rejected", threat.Detector)
	}
	if threat.Severity != "high" {
		t.Errorf("severity = %q, want high", threat.Severity)
	}
	if threat.SourceIP.String() != "77.68.33.97" {
		t.Errorf("source ip = %q, want 77.68.33.97", threat.SourceIP)
	}
}

func TestServerRejectedRespectsThreshold(t *testing.T) {
	d := NewServerRejected(3, time.Minute)
	ip := net.ParseIP("203.0.113.50")

	for i := 0; i < 2; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "INVITE", Rejected: true,
		}
		if threat := d.Detect(evt); threat != nil {
			t.Fatalf("unexpected threat at hit %d", i+1)
		}
	}

	threat := d.Detect(models.SIPEvent{
		Timestamp: time.Now(), SourceIP: ip, Method: "INVITE", Rejected: true,
	})
	if threat == nil {
		t.Fatal("expected threat at 3rd rejected hit")
	}
	if threat.EventCount != 3 {
		t.Errorf("event count = %d, want 3", threat.EventCount)
	}
}

func TestServerRejectedClampsBadConfig(t *testing.T) {
	d := NewServerRejected(0, 0)
	evt := models.SIPEvent{
		Timestamp: time.Now(),
		SourceIP:  net.ParseIP("198.51.100.99"),
		Method:    "INVITE",
		Rejected:  true,
	}
	if threat := d.Detect(evt); threat == nil {
		t.Fatal("expected threat with clamped defaults")
	}
}
