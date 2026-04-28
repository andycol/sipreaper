package detect

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestHoneypotBansOnHit(t *testing.T) {
	d := NewHoneypot([]string{"1000", "admin", "0000"})
	evt := models.SIPEvent{
		Timestamp: time.Now(),
		SourceIP:  net.ParseIP("203.0.113.10"),
		Method:    "INVITE",
		ToUser:    "admin",
	}

	threat := d.Detect(evt)
	if threat == nil {
		t.Fatal("expected threat for honeypot extension")
	}
	if threat.Severity != "high" {
		t.Errorf("severity = %q, want high", threat.Severity)
	}
}

func TestHoneypotIgnoresNormalTraffic(t *testing.T) {
	d := NewHoneypot([]string{"1000"})
	evt := models.SIPEvent{
		Timestamp: time.Now(),
		SourceIP:  net.ParseIP("203.0.113.10"),
		Method:    "INVITE",
		ToUser:    "5005",
	}
	if threat := d.Detect(evt); threat != nil {
		t.Error("real-extension traffic should not trip the honeypot")
	}
}

func TestHoneypotEmptyConfigDoesNothing(t *testing.T) {
	d := NewHoneypot(nil)
	evt := models.SIPEvent{
		Timestamp: time.Now(),
		SourceIP:  net.ParseIP("203.0.113.10"),
		Method:    "INVITE",
		ToUser:    "1000",
	}
	if threat := d.Detect(evt); threat != nil {
		t.Error("empty honeypot config should never fire")
	}
}

func TestHoneypotIgnoresMissingToUser(t *testing.T) {
	d := NewHoneypot([]string{"1000"})
	evt := models.SIPEvent{
		Timestamp: time.Now(),
		SourceIP:  net.ParseIP("203.0.113.10"),
		Method:    "OPTIONS",
	}
	if threat := d.Detect(evt); threat != nil {
		t.Error("no ToUser should not fire honeypot")
	}
}
