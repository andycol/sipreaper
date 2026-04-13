package detect

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestScannerKnownAgent(t *testing.T) {
	d := NewScanner(10, 30*time.Second, []string{"friendly-scanner", "sipvicious"})
	ip := net.ParseIP("10.0.0.1")

	evt := models.SIPEvent{
		Timestamp: time.Now(), SourceIP: ip,
		Method: "OPTIONS", UserAgent: "friendly-scanner",
	}
	threat := d.Detect(evt)
	if threat == nil {
		t.Fatal("known scanner agent should trigger immediate threat")
	}
	if threat.Severity != "high" {
		t.Errorf("severity = %q, want high", threat.Severity)
	}
}

func TestScannerProbeThreshold(t *testing.T) {
	d := NewScanner(5, 30*time.Second, []string{"friendly-scanner"})
	ip := net.ParseIP("10.0.0.1")

	var threat *models.Threat
	for i := 0; i < 5; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "OPTIONS", UserAgent: "some-unknown-agent",
		}
		threat = d.Detect(evt)
	}
	if threat == nil {
		t.Fatal("expected threat after probe threshold")
	}
	if threat.Detector != "scanner" {
		t.Errorf("detector = %q, want scanner", threat.Detector)
	}
}

func TestScannerIgnoresNonProbe(t *testing.T) {
	d := NewScanner(3, 30*time.Second, []string{})
	ip := net.ParseIP("10.0.0.1")

	for i := 0; i < 10; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "INVITE", UserAgent: "normal-phone",
		}
		if threat := d.Detect(evt); threat != nil {
			t.Error("INVITE should not trigger scanner detection")
		}
	}
}
