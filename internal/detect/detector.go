package detect

import (
	"sync"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

// Detector detects threats from SIP events.
type Detector interface {
	Name() string
	Detect(event models.SIPEvent) *models.Threat
}

// timestampedEntry stores a timestamp and an optional sub-key for distinct counting.
type timestampedEntry struct {
	time time.Time
	key  string
}

// SlidingWindow tracks events per IP within a time window.
type SlidingWindow struct {
	mu     sync.Mutex
	window time.Duration
	data   map[string][]timestampedEntry
}

func NewSlidingWindow(window time.Duration) *SlidingWindow {
	return &SlidingWindow{
		window: window,
		data:   make(map[string][]timestampedEntry),
	}
}

func (sw *SlidingWindow) Add(ip string) {
	sw.AddKeyed(ip, "")
}

func (sw *SlidingWindow) AddKeyed(ip, key string) {
	now := time.Now()
	sw.mu.Lock()
	defer sw.mu.Unlock()

	sw.data[ip] = append(sw.data[ip], timestampedEntry{time: now, key: key})
}

func (sw *SlidingWindow) Count(ip string) int {
	cutoff := time.Now().Add(-sw.window)
	sw.mu.Lock()
	defer sw.mu.Unlock()

	entries := sw.data[ip]
	count := 0
	for _, e := range entries {
		if e.time.After(cutoff) {
			count++
		}
	}
	return count
}

func (sw *SlidingWindow) DistinctCount(ip string) int {
	cutoff := time.Now().Add(-sw.window)
	sw.mu.Lock()
	defer sw.mu.Unlock()

	seen := make(map[string]struct{})
	for _, e := range sw.data[ip] {
		if e.time.After(cutoff) && e.key != "" {
			seen[e.key] = struct{}{}
		}
	}
	return len(seen)
}

func (sw *SlidingWindow) Prune() {
	cutoff := time.Now().Add(-sw.window)
	sw.mu.Lock()
	defer sw.mu.Unlock()

	for ip, entries := range sw.data {
		var kept []timestampedEntry
		for _, e := range entries {
			if e.time.After(cutoff) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(sw.data, ip)
		} else {
			sw.data[ip] = kept
		}
	}
}
