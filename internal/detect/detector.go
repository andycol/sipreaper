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

// maxEntriesPerIP caps one IP's entries in a window. pcap sees packets before
// netfilter drops them, so a banned flooder keeps feeding the detectors; the
// cap bounds memory and makes Count O(cap) per event. Thresholds are far
// below it, so a saturated count still trips them.
const maxEntriesPerIP = 10_000

// timestampedEntry stores a timestamp and an optional sub-key for distinct counting.
type timestampedEntry struct {
	time time.Time
	key  string
}

// SlidingWindow tracks events per IP within a time window. Memory is bounded:
// each Add trims that IP's expired entries, and IPs that have gone quiet are
// swept out at most once per window.
type SlidingWindow struct {
	mu        sync.Mutex
	window    time.Duration
	data      map[string][]timestampedEntry
	lastSweep time.Time
	now       func() time.Time // replaced in tests
}

func NewSlidingWindow(window time.Duration) *SlidingWindow {
	return &SlidingWindow{
		window:    window,
		data:      make(map[string][]timestampedEntry),
		lastSweep: time.Now(),
		now:       time.Now,
	}
}

func (sw *SlidingWindow) Add(ip string) {
	sw.AddKeyed(ip, "")
}

func (sw *SlidingWindow) AddKeyed(ip, key string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := sw.now()
	cutoff := now.Add(-sw.window)

	entries := append(sw.data[ip], timestampedEntry{time: now, key: key})
	// Entries are appended in time order, so expired ones are a prefix.
	drop := 0
	for drop < len(entries) && !entries[drop].time.After(cutoff) {
		drop++
	}
	if over := len(entries) - drop - maxEntriesPerIP; over > 0 {
		drop += over
	}
	if drop > 0 {
		// Copy down rather than re-slice so the backing array is reused
		// instead of creeping forward and reallocating forever.
		n := copy(entries, entries[drop:])
		entries = entries[:n]
	}
	sw.data[ip] = entries

	if now.Sub(sw.lastSweep) >= sw.window {
		sw.pruneLocked(cutoff)
		sw.lastSweep = now
	}
}

func (sw *SlidingWindow) Count(ip string) int {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	cutoff := sw.now().Add(-sw.window)

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
	sw.mu.Lock()
	defer sw.mu.Unlock()
	cutoff := sw.now().Add(-sw.window)

	seen := make(map[string]struct{})
	for _, e := range sw.data[ip] {
		if e.time.After(cutoff) && e.key != "" {
			seen[e.key] = struct{}{}
		}
	}
	return len(seen)
}

// Prune drops expired entries and forgets IPs with none left. AddKeyed runs
// it automatically once per window; exported for tests and callers that
// want to reclaim memory eagerly.
func (sw *SlidingWindow) Prune() {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.pruneLocked(sw.now().Add(-sw.window))
}

func (sw *SlidingWindow) pruneLocked(cutoff time.Time) {
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

// size reports how many IPs and entries are held, for tests.
func (sw *SlidingWindow) size() (ips, entries int) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	for _, e := range sw.data {
		entries += len(e)
	}
	return len(sw.data), entries
}
