package detect

import (
	"fmt"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

var validSIPMethods = map[string]bool{
	"REGISTER":  true,
	"INVITE":    true,
	"ACK":       true,
	"BYE":       true,
	"CANCEL":    true,
	"OPTIONS":   true,
	"PRACK":     true,
	"SUBSCRIBE": true,
	"NOTIFY":    true,
	"PUBLISH":   true,
	"INFO":      true,
	"REFER":     true,
	"MESSAGE":   true,
	"UPDATE":    true,
}

type InvalidRequest struct {
	maxInvalid int
	window     time.Duration
	sw         *SlidingWindow
}

func NewInvalidRequest(maxInvalid int, window time.Duration) *InvalidRequest {
	return &InvalidRequest{
		maxInvalid: maxInvalid,
		window:     window,
		sw:         NewSlidingWindow(window),
	}
}

func (d *InvalidRequest) Name() string { return "invalid_request" }

func (d *InvalidRequest) Detect(event models.SIPEvent) *models.Threat {
	if event.Method != "" && validSIPMethods[event.Method] {
		return nil
	}

	ip := event.SourceIP.String()
	d.sw.Add(ip)

	count := d.sw.Count(ip)
	if count >= d.maxInvalid {
		return &models.Threat{
			Timestamp:   time.Now(),
			SourceIP:    event.SourceIP,
			Detector:    "invalid_request",
			Severity:    "medium",
			Description: fmt.Sprintf("%d invalid requests in %s", count, d.window),
			EventCount:  count,
			Window:      d.window,
		}
	}
	return nil
}
