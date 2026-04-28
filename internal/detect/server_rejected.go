package detect

import (
	"fmt"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

// ServerRejected fires on events the SIP server itself has already rejected
// (e.g. "Rejected inbound carrier INVITE from non-whitelisted source ..."). The
// SIP server has authoritative knowledge of who is allowed to send what — if it
// said no, that's a high-confidence threat signal and the threshold should be
// low. Default ships at 1 hit / 5 minutes.
type ServerRejected struct {
	maxHits int
	window  time.Duration
	sw      *SlidingWindow
}

func NewServerRejected(maxHits int, window time.Duration) *ServerRejected {
	if maxHits < 1 {
		maxHits = 1
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &ServerRejected{
		maxHits: maxHits,
		window:  window,
		sw:      NewSlidingWindow(window),
	}
}

func (d *ServerRejected) Name() string { return "server_rejected" }

func (d *ServerRejected) Detect(event models.SIPEvent) *models.Threat {
	if !event.Rejected || event.SourceIP == nil {
		return nil
	}

	ip := event.SourceIP.String()
	d.sw.Add(ip)

	count := d.sw.Count(ip)
	if count < d.maxHits {
		return nil
	}

	reason := event.RejectReason
	if reason == "" {
		reason = "rejected by sip server"
	}
	desc := fmt.Sprintf("%d %s rejection(s) in %s", count, event.Method, d.window)
	if reason != "" {
		desc = fmt.Sprintf("%s: %s", desc, reason)
	}

	return &models.Threat{
		Timestamp:   time.Now(),
		SourceIP:    event.SourceIP,
		Detector:    "server_rejected",
		Severity:    "high",
		Description: desc,
		EventCount:  count,
		Window:      d.window,
	}
}
