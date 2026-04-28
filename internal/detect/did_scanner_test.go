package detect

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestDIDScannerFiresOnManyDistinctDIDs(t *testing.T) {
	d := NewDIDScanner(5, time.Minute)
	ip := net.ParseIP("203.0.113.99")

	var threat *models.Threat
	for i := 0; i < 5; i++ {
		threat = d.Detect(models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "INVITE",
			ToUser: fmt.Sprintf("4400000000%d", i),
		})
	}
	if threat == nil {
		t.Fatal("expected threat after 5 distinct DIDs")
	}
	if threat.Detector != "did_scanner" {
		t.Errorf("detector = %q, want did_scanner", threat.Detector)
	}
}

func TestDIDScannerIgnoresRepeatsToSameDID(t *testing.T) {
	d := NewDIDScanner(3, time.Minute)
	ip := net.ParseIP("203.0.113.98")

	for i := 0; i < 50; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "INVITE", ToUser: "4401234",
		}
		if threat := d.Detect(evt); threat != nil {
			t.Fatalf("unexpected threat after %d INVITEs to one DID", i+1)
		}
	}
}

func TestDIDScannerIgnoresNonInvite(t *testing.T) {
	d := NewDIDScanner(3, time.Minute)
	ip := net.ParseIP("203.0.113.97")

	for i := 0; i < 50; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: "OPTIONS",
			ToUser: fmt.Sprintf("DID-%d", i),
		}
		if threat := d.Detect(evt); threat != nil {
			t.Fatal("OPTIONS probe should not feed did_scanner")
		}
	}
}
