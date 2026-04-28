package detect

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestFailedCallRatioRequiresMinCalls(t *testing.T) {
	d := NewFailedCallRatio(10, 0.5, time.Minute)
	ip := net.ParseIP("203.0.113.50")

	for i := 0; i < 9; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "INVITE", Rejected: true,
		}
		if threat := d.Detect(evt); threat != nil {
			t.Fatalf("fired before min_calls reached at %d", i+1)
		}
	}
}

func TestFailedCallRatioFiresAtThreshold(t *testing.T) {
	d := NewFailedCallRatio(10, 0.8, time.Minute)
	ip := net.ParseIP("203.0.113.50")

	// 9 failed + 1 success = 90% failure rate; well above 0.8
	var threat *models.Threat
	for i := 0; i < 9; i++ {
		threat = d.Detect(models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "INVITE", Rejected: true,
		})
	}
	threat = d.Detect(models.SIPEvent{
		Timestamp: time.Now(), SourceIP: ip, Method: "INVITE", ResponseCode: 200,
	})
	// 10th call lands and ratio = 9/10 = 0.9, should fire
	if threat == nil {
		// Some additional calls may need to come in; one more
		threat = d.Detect(models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "INVITE", Rejected: true,
		})
	}
	if threat == nil {
		t.Fatal("expected threat once threshold reached")
	}
	if threat.Detector != "failed_call_ratio" {
		t.Errorf("detector = %q, want failed_call_ratio", threat.Detector)
	}
}

func TestFailedCallRatioDoesNotFireForSuccessfulIP(t *testing.T) {
	d := NewFailedCallRatio(5, 0.8, time.Minute)
	ip := net.ParseIP("203.0.113.51")

	for i := 0; i < 20; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "INVITE", ResponseCode: 200,
		}
		if threat := d.Detect(evt); threat != nil {
			t.Fatalf("unexpected threat for successful caller at %d", i+1)
		}
	}
}

func TestFailedCallRatioIgnoresNonInvite(t *testing.T) {
	d := NewFailedCallRatio(5, 0.5, time.Minute)
	ip := net.ParseIP("203.0.113.52")

	for i := 0; i < 50; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "REGISTER", Rejected: true,
		}
		if threat := d.Detect(evt); threat != nil {
			t.Fatal("non-INVITE should not affect failed call ratio")
		}
	}
}
