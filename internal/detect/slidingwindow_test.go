package detect

import (
	"fmt"
	"testing"
	"time"
)

func TestSlidingWindowAdd(t *testing.T) {
	sw := NewSlidingWindow(60 * time.Second)

	sw.Add("10.0.0.1")
	sw.Add("10.0.0.1")
	sw.Add("10.0.0.2")

	if got := sw.Count("10.0.0.1"); got != 2 {
		t.Errorf("count for 10.0.0.1 = %d, want 2", got)
	}
	if got := sw.Count("10.0.0.2"); got != 1 {
		t.Errorf("count for 10.0.0.2 = %d, want 1", got)
	}
	if got := sw.Count("10.0.0.3"); got != 0 {
		t.Errorf("count for 10.0.0.3 = %d, want 0", got)
	}
}

func TestSlidingWindowExpiry(t *testing.T) {
	sw := NewSlidingWindow(50 * time.Millisecond)

	sw.Add("10.0.0.1")
	if got := sw.Count("10.0.0.1"); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}

	time.Sleep(100 * time.Millisecond)

	if got := sw.Count("10.0.0.1"); got != 0 {
		t.Errorf("count after expiry = %d, want 0", got)
	}
}

func TestSlidingWindowDistinctKeys(t *testing.T) {
	sw := NewSlidingWindow(60 * time.Second)

	sw.AddKeyed("10.0.0.1", "ext-100")
	sw.AddKeyed("10.0.0.1", "ext-101")
	sw.AddKeyed("10.0.0.1", "ext-100") // duplicate

	if got := sw.DistinctCount("10.0.0.1"); got != 2 {
		t.Errorf("distinct count = %d, want 2", got)
	}
}

func TestSlidingWindowPrune(t *testing.T) {
	sw := NewSlidingWindow(50 * time.Millisecond)

	sw.Add("10.0.0.1")
	sw.Add("10.0.0.2")
	time.Sleep(100 * time.Millisecond)

	sw.Prune()

	if got := sw.Count("10.0.0.1"); got != 0 {
		t.Errorf("count after prune = %d, want 0", got)
	}
}

// fakeClock lets tests move time without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// The production leak: a busy IP's entries were never trimmed, so the slice
// (and Count's scan) grew with every event for the life of the process.
func TestSlidingWindowTrimsBusyIPOnAdd(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	sw := NewSlidingWindow(10 * time.Second)
	sw.now = clock.now

	for i := 0; i < 1000; i++ {
		sw.Add("10.0.0.1")
		clock.advance(time.Second)
	}
	_, entries := sw.size()
	if entries > 11 {
		t.Errorf("entries held = %d, want <= 11 (one window's worth)", entries)
	}
	// The clock has moved 1s past the last Add, so the oldest of the last
	// ten entries sits exactly on the cutoff and no longer counts.
	if got := sw.Count("10.0.0.1"); got != 9 {
		t.Errorf("count = %d, want 9", got)
	}
}

func TestSlidingWindowSweepsQuietIPs(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	sw := NewSlidingWindow(time.Minute)
	sw.now = clock.now

	for i := 0; i < 500; i++ {
		sw.Add(fmt.Sprintf("ip-%d", i))
	}
	clock.advance(2 * time.Minute)
	sw.Add("10.0.0.1") // triggers the once-per-window sweep

	if ips, _ := sw.size(); ips != 1 {
		t.Errorf("ips held = %d, want 1 after quiet IPs swept", ips)
	}
}

func TestSlidingWindowCapsEntriesPerIP(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	sw := NewSlidingWindow(time.Hour)
	sw.now = clock.now

	for i := 0; i < maxEntriesPerIP+500; i++ {
		sw.AddKeyed("10.0.0.1", fmt.Sprint(i))
		clock.advance(time.Millisecond)
	}
	if got := sw.Count("10.0.0.1"); got != maxEntriesPerIP {
		t.Errorf("count = %d, want cap %d", got, maxEntriesPerIP)
	}
	if got := sw.DistinctCount("10.0.0.1"); got != maxEntriesPerIP {
		t.Errorf("distinct = %d, want cap %d", got, maxEntriesPerIP)
	}
}
