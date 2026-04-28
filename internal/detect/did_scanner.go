package detect

import (
	"fmt"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

// DIDScanner detects an IP that is reaching for many distinct DIDs (called
// numbers) inside the window — the classic shape of carrier-side toll-fraud
// dial-plan probing. Distinct from user_enum, which targets internal user
// accounts. Reuses the SlidingWindow's distinct-key support.
type DIDScanner struct {
	maxDIDs int
	window  time.Duration
	sw      *SlidingWindow
}

func NewDIDScanner(maxDIDs int, window time.Duration) *DIDScanner {
	if maxDIDs < 1 {
		maxDIDs = 20
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &DIDScanner{
		maxDIDs: maxDIDs,
		window:  window,
		sw:      NewSlidingWindow(window),
	}
}

func (d *DIDScanner) Name() string { return "did_scanner" }

func (d *DIDScanner) Detect(event models.SIPEvent) *models.Threat {
	// Only INVITEs attempt to reach a DID; REGISTER/OPTIONS noise would
	// inflate the count and turn this into a worse copy of user_enum.
	if event.Method != "INVITE" || event.SourceIP == nil || event.ToUser == "" {
		return nil
	}

	ip := event.SourceIP.String()
	d.sw.AddKeyed(ip, event.ToUser)

	count := d.sw.DistinctCount(ip)
	if count < d.maxDIDs {
		return nil
	}

	return &models.Threat{
		Timestamp:   time.Now(),
		SourceIP:    event.SourceIP,
		Detector:    "did_scanner",
		Severity:    "high",
		Description: fmt.Sprintf("%d distinct DIDs targeted in %s", count, d.window),
		EventCount:  count,
		Window:      d.window,
	}
}
