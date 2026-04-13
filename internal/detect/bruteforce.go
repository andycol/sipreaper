package detect

import (
	"fmt"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

type BruteForce struct {
	maxAttempts int
	window      time.Duration
	sw          *SlidingWindow
}

func NewBruteForce(maxAttempts int, window time.Duration) *BruteForce {
	return &BruteForce{
		maxAttempts: maxAttempts,
		window:      window,
		sw:          NewSlidingWindow(window),
	}
}

func (d *BruteForce) Name() string { return "brute_force" }

func (d *BruteForce) Detect(event models.SIPEvent) *models.Threat {
	if event.Method != "REGISTER" {
		return nil
	}
	if event.ResponseCode != 401 && event.ResponseCode != 403 {
		return nil
	}

	ip := event.SourceIP.String()
	d.sw.Add(ip)

	count := d.sw.Count(ip)
	if count >= d.maxAttempts {
		return &models.Threat{
			Timestamp:   time.Now(),
			SourceIP:    event.SourceIP,
			Detector:    "brute_force",
			Severity:    "high",
			Description: fmt.Sprintf("%d failed REGISTER attempts in %s", count, d.window),
			EventCount:  count,
			Window:      d.window,
		}
	}
	return nil
}
