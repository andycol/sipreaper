package detect

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

// Request-counting detectors must ignore pcap response events, otherwise a
// single call (INVITE → 100 → 180 → 200) counts four times.
func TestRequestCountingDetectorsIgnoreResponses(t *testing.T) {
	ip := net.ParseIP("198.51.100.7")
	resolver := &mockGeoResolver{countries: map[string]string{"198.51.100.7": "CN"}}
	detectors := []Detector{
		NewInviteFlood(1, time.Minute),
		NewUserEnum(1, time.Minute),
		NewDIDScanner(1, time.Minute),
		NewScanner(1, time.Minute, []string{"friendly-scanner"}),
		NewInvalidRequest(1, time.Minute),
		NewHoneypot([]string{"1000"}),
		NewGeoAnomaly([]string{"GB"}, resolver),
	}
	for _, method := range []string{"INVITE", "REGISTER", "OPTIONS", ""} {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: method, ToUser: "1000",
			UserAgent: "friendly-scanner", ResponseCode: 200, IsResponse: true,
		}
		for _, d := range detectors {
			if threat := d.Detect(evt); threat != nil {
				t.Errorf("%s fired on %s response event: %+v", d.Name(), method, threat)
			}
		}
	}
}
