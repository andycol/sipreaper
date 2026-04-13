package detect

import (
	"fmt"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

type InviteFlood struct {
	maxRequests int
	window      time.Duration
	sw          *SlidingWindow
}

func NewInviteFlood(maxRequests int, window time.Duration) *InviteFlood {
	return &InviteFlood{
		maxRequests: maxRequests,
		window:      window,
		sw:          NewSlidingWindow(window),
	}
}

func (d *InviteFlood) Name() string { return "invite_flood" }

func (d *InviteFlood) Detect(event models.SIPEvent) *models.Threat {
	if event.Method != "INVITE" {
		return nil
	}

	ip := event.SourceIP.String()
	d.sw.Add(ip)

	count := d.sw.Count(ip)
	if count >= d.maxRequests {
		return &models.Threat{
			Timestamp:   time.Now(),
			SourceIP:    event.SourceIP,
			Detector:    "invite_flood",
			Severity:    "high",
			Description: fmt.Sprintf("%d INVITEs in %s", count, d.window),
			EventCount:  count,
			Window:      d.window,
		}
	}
	return nil
}
