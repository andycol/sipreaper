package detect

import (
	"fmt"
	"sync"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

// FailedCallRatio fires when a single source IP racks up a high ratio of
// rejected/failed calls over a meaningful sample. Toll-fraud reconnaissance
// tools dial through long DID lists and most calls fail; legit endpoints don't
// look like that. We require minCalls samples before evaluating, so quiet IPs
// don't get banned for a single fluke.
type FailedCallRatio struct {
	minCalls int
	minRatio float64
	window   time.Duration

	mu        sync.Mutex
	data      map[string]*ratioBucket
	lastSweep time.Time
	now       func() time.Time // replaced in tests
}

type ratioBucket struct {
	events []ratioEvent
}

type ratioEvent struct {
	t      time.Time
	failed bool
}

func NewFailedCallRatio(minCalls int, minRatio float64, window time.Duration) *FailedCallRatio {
	if minCalls < 1 {
		minCalls = 20
	}
	if minRatio <= 0 || minRatio > 1 {
		minRatio = 0.8
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &FailedCallRatio{
		minCalls:  minCalls,
		minRatio:  minRatio,
		window:    window,
		data:      make(map[string]*ratioBucket),
		lastSweep: time.Now(),
		now:       time.Now,
	}
}

func (d *FailedCallRatio) Name() string { return "failed_call_ratio" }

func (d *FailedCallRatio) Detect(event models.SIPEvent) *models.Threat {
	if event.Method != "INVITE" || event.SourceIP == nil {
		return nil
	}

	failed := event.Rejected || (event.ResponseCode >= 400 && event.ResponseCode < 600)

	ip := event.SourceIP.String()

	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	cutoff := now.Add(-d.window)

	// Forget IPs that have gone quiet, at most once per window.
	if now.Sub(d.lastSweep) >= d.window {
		for k, b := range d.data {
			if n := len(b.events); n == 0 || !b.events[n-1].t.After(cutoff) {
				delete(d.data, k)
			}
		}
		d.lastSweep = now
	}

	b, ok := d.data[ip]
	if !ok {
		b = &ratioBucket{}
		d.data[ip] = b
	}
	b.events = append(b.events, ratioEvent{t: now, failed: failed})

	// Drop old events
	kept := b.events[:0]
	for _, e := range b.events {
		if e.t.After(cutoff) {
			kept = append(kept, e)
		}
	}
	if over := len(kept) - maxEntriesPerIP; over > 0 {
		kept = kept[:copy(kept, kept[over:])]
	}
	b.events = kept

	if len(b.events) < d.minCalls {
		return nil
	}

	failedCount := 0
	for _, e := range b.events {
		if e.failed {
			failedCount++
		}
	}
	ratio := float64(failedCount) / float64(len(b.events))
	if ratio < d.minRatio {
		return nil
	}

	return &models.Threat{
		Timestamp:   now,
		SourceIP:    event.SourceIP,
		Detector:    "failed_call_ratio",
		Severity:    "high",
		Description: fmt.Sprintf("%d/%d INVITEs failed (%.0f%%) over %s", failedCount, len(b.events), ratio*100, d.window),
		EventCount:  len(b.events),
		Window:      d.window,
	}
}
