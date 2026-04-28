package ingest

import (
	"strconv"
	"sync"
	"time"
)

type Dedup struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	window time.Duration
	done   chan struct{}
}

func NewDedup(window time.Duration) *Dedup {
	d := &Dedup{
		seen:   make(map[string]time.Time),
		window: window,
		done:   make(chan struct{}),
	}
	go d.pruneLoop()
	return d
}

func (d *Dedup) IsDuplicate(callID, method string) bool {
	return d.isDup(callID + "|" + method)
}

// IsDuplicateEvent considers Call-ID + Method + ResponseCode so that the
// request "INVITE" and the synthesized "INVITE/403" derived from a response
// are not collapsed into one.
func (d *Dedup) IsDuplicateEvent(callID, method string, responseCode int) bool {
	return d.isDup(callID + "|" + method + "|" + strconv.Itoa(responseCode))
}

func (d *Dedup) isDup(key string) bool {
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	if ts, ok := d.seen[key]; ok && now.Sub(ts) < d.window {
		return true
	}
	d.seen[key] = now
	return false
}

func (d *Dedup) Stop() {
	close(d.done)
}

func (d *Dedup) pruneLoop() {
	ticker := time.NewTicker(d.window)
	defer ticker.Stop()

	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
			d.prune()
		}
	}
}

func (d *Dedup) prune() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()

	for key, ts := range d.seen {
		if now.Sub(ts) >= d.window {
			delete(d.seen, key)
		}
	}
}
