package detect

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestBruteForceNoThreatUnderThreshold(t *testing.T) {
	d := NewBruteForce(5, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	for i := 0; i < 4; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "REGISTER", ResponseCode: 401,
		}
		threat := d.Detect(evt)
		if threat != nil {
			t.Errorf("unexpected threat at attempt %d", i+1)
		}
	}
}

func TestBruteForceTriggersAtThreshold(t *testing.T) {
	d := NewBruteForce(5, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	var threat *models.Threat
	for i := 0; i < 5; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "REGISTER", ResponseCode: 401,
		}
		threat = d.Detect(evt)
	}
	if threat == nil {
		t.Fatal("expected threat at threshold")
	}
	if threat.Detector != "brute_force" {
		t.Errorf("detector = %q, want brute_force", threat.Detector)
	}
	if threat.Severity != "high" {
		t.Errorf("severity = %q, want high", threat.Severity)
	}
	if threat.SourceIP.String() != "10.0.0.1" {
		t.Errorf("source ip = %q, want 10.0.0.1", threat.SourceIP)
	}
}

func TestBruteForceIgnoresSuccess(t *testing.T) {
	d := NewBruteForce(3, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	for i := 0; i < 10; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "REGISTER", ResponseCode: 200,
		}
		if threat := d.Detect(evt); threat != nil {
			t.Error("successful registrations should not trigger threat")
		}
	}
}

func TestBruteForceIgnoresNonRegister(t *testing.T) {
	d := NewBruteForce(3, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	for i := 0; i < 10; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "INVITE", ResponseCode: 401,
		}
		if threat := d.Detect(evt); threat != nil {
			t.Error("non-REGISTER should not trigger brute force")
		}
	}
}
