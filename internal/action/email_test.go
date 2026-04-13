package action

import (
	"strings"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestEmailFormatMessage(t *testing.T) {
	e := &EmailNotifier{from: "sipreaper@example.com"}

	evt := models.NotifyEvent{
		Type: "ban", IP: "10.0.0.1", Detector: "brute_force",
		Severity: "high", Duration: 5 * time.Minute,
		Reason: "5 failed REGISTER attempts in 60s", Timestamp: time.Now(),
	}

	subject, body := e.formatMessage(evt)
	if !strings.Contains(subject, "10.0.0.1") {
		t.Errorf("subject should contain IP: %q", subject)
	}
	if !strings.Contains(subject, "ban") {
		t.Errorf("subject should contain event type: %q", subject)
	}
	if !strings.Contains(body, "brute_force") {
		t.Errorf("body should contain detector: %q", body)
	}
	if !strings.Contains(body, "5m0s") {
		t.Errorf("body should contain duration: %q", body)
	}
}

func TestEmailSeverityFilter(t *testing.T) {
	e := &EmailNotifier{minSeverity: "medium"}

	if e.shouldNotify("low") {
		t.Error("low severity should be filtered when min is medium")
	}
	if !e.shouldNotify("medium") {
		t.Error("medium severity should pass when min is medium")
	}
	if !e.shouldNotify("high") {
		t.Error("high severity should pass when min is medium")
	}
}
