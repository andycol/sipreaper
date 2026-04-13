package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

type Scanner struct {
	maxProbes   int
	window      time.Duration
	knownAgents []string
	sw          *SlidingWindow
}

func NewScanner(maxProbes int, window time.Duration, knownAgents []string) *Scanner {
	lower := make([]string, len(knownAgents))
	for i, a := range knownAgents {
		lower[i] = strings.ToLower(a)
	}
	return &Scanner{
		maxProbes:   maxProbes,
		window:      window,
		knownAgents: lower,
		sw:          NewSlidingWindow(window),
	}
}

func (d *Scanner) Name() string { return "scanner" }

func (d *Scanner) Detect(event models.SIPEvent) *models.Threat {
	// Known scanner user-agent = immediate threat
	if event.UserAgent != "" {
		ua := strings.ToLower(event.UserAgent)
		for _, known := range d.knownAgents {
			if strings.Contains(ua, known) {
				return &models.Threat{
					Timestamp:   time.Now(),
					SourceIP:    event.SourceIP,
					Detector:    "scanner",
					Severity:    "high",
					Description: fmt.Sprintf("known scanner user-agent: %s", event.UserAgent),
					EventCount:  1,
					Window:      d.window,
				}
			}
		}
	}

	// OPTIONS probes count toward threshold
	if event.Method != "OPTIONS" {
		return nil
	}

	ip := event.SourceIP.String()
	d.sw.Add(ip)

	count := d.sw.Count(ip)
	if count >= d.maxProbes {
		return &models.Threat{
			Timestamp:   time.Now(),
			SourceIP:    event.SourceIP,
			Detector:    "scanner",
			Severity:    "medium",
			Description: fmt.Sprintf("%d OPTIONS probes in %s", count, d.window),
			EventCount:  count,
			Window:      d.window,
		}
	}
	return nil
}
