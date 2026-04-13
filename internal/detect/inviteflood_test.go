package detect

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestInviteFloodNoThreatUnderThreshold(t *testing.T) {
	d := NewInviteFlood(10, 10*time.Second)
	ip := net.ParseIP("10.0.0.1")

	for i := 0; i < 9; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "INVITE",
		}
		if threat := d.Detect(evt); threat != nil {
			t.Errorf("unexpected threat at request %d", i+1)
		}
	}
}

func TestInviteFloodTriggersAtThreshold(t *testing.T) {
	d := NewInviteFlood(10, 10*time.Second)
	ip := net.ParseIP("10.0.0.1")

	var threat *models.Threat
	for i := 0; i < 10; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "INVITE",
		}
		threat = d.Detect(evt)
	}
	if threat == nil {
		t.Fatal("expected threat at threshold")
	}
	if threat.Detector != "invite_flood" {
		t.Errorf("detector = %q, want invite_flood", threat.Detector)
	}
}

func TestInviteFloodIgnoresNonInvite(t *testing.T) {
	d := NewInviteFlood(3, 10*time.Second)
	ip := net.ParseIP("10.0.0.1")

	for i := 0; i < 10; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "REGISTER",
		}
		if threat := d.Detect(evt); threat != nil {
			t.Error("non-INVITE should not trigger invite flood")
		}
	}
}
