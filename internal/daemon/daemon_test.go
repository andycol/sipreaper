package daemon

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/detect"
	"github.com/andycol/sipreaper/internal/ingest"
	"github.com/andycol/sipreaper/internal/models"
	"github.com/andycol/sipreaper/internal/store"
)

type noThreatDetector struct{}

func (noThreatDetector) Name() string { return "noop" }

func (noThreatDetector) Detect(models.SIPEvent) *models.Threat { return nil }

var _ detect.Detector = noThreatDetector{}

func TestDetectionPipelineRecordsEventEvidence(t *testing.T) {
	s, err := store.New(filepath.Join(t.TempDir(), "sipreaper.db"))
	if err != nil {
		t.Fatalf("store.New() error: %v", err)
	}
	defer s.Close()

	d := &Daemon{
		store:     s,
		events:    make(chan models.SIPEvent, 1),
		detectors: []detect.Detector{noThreatDetector{}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dedup := ingest.NewDedup(time.Second)
	defer dedup.Stop()

	go d.runDetectionPipeline(ctx, dedup)

	d.events <- models.SIPEvent{
		Timestamp:    time.Now(),
		SourceIP:     net.ParseIP("203.0.113.9"),
		Method:       "INVITE",
		UserAgent:    "friendly-scanner",
		FromUser:     "100",
		ToUser:       "200",
		CallID:       "call-123",
		ResponseCode: 403,
		Source:       "pcap",
		Rejected:     true,
		RejectReason: "forbidden",
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events, err := s.ListEvents("203.0.113.9", "", time.Hour, 10)
		if err != nil {
			t.Fatalf("ListEvents() error: %v", err)
		}
		if len(events) == 1 {
			if got := events[0].UserAgent; got != "friendly-scanner" {
				t.Fatalf("user agent = %q, want friendly-scanner", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("event was not recorded by detection pipeline")
}
