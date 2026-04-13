package detect

import (
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
