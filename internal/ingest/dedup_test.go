package ingest

import (
	"testing"
	"time"
)

func TestDedupFirstSeen(t *testing.T) {
	d := NewDedup(5 * time.Second)
	defer d.Stop()

	if d.IsDuplicate("call-1", "REGISTER") {
		t.Error("first occurrence should not be duplicate")
	}
}

func TestDedupSecondSeen(t *testing.T) {
	d := NewDedup(5 * time.Second)
	defer d.Stop()

	d.IsDuplicate("call-1", "REGISTER")
	if !d.IsDuplicate("call-1", "REGISTER") {
		t.Error("second occurrence should be duplicate")
	}
}

func TestDedupDifferentMethod(t *testing.T) {
	d := NewDedup(5 * time.Second)
	defer d.Stop()

	d.IsDuplicate("call-1", "REGISTER")
	if d.IsDuplicate("call-1", "INVITE") {
		t.Error("different method should not be duplicate")
	}
}

func TestDedupExpiry(t *testing.T) {
	d := NewDedup(50 * time.Millisecond)
	defer d.Stop()

	d.IsDuplicate("call-1", "REGISTER")
	time.Sleep(100 * time.Millisecond)
	if d.IsDuplicate("call-1", "REGISTER") {
		t.Error("entry should have expired")
	}
}
