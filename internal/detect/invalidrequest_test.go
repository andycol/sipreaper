package detect

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestInvalidRequestTriggersAtThreshold(t *testing.T) {
	d := NewInvalidRequest(3, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	var threat *models.Threat
	for i := 0; i < 3; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "XYZGARBAGE",
		}
		threat = d.Detect(evt)
	}
	if threat == nil {
		t.Fatal("expected threat for invalid methods")
	}
	if threat.Detector != "invalid_request" {
		t.Errorf("detector = %q, want invalid_request", threat.Detector)
	}
}

func TestInvalidRequestIgnoresValidMethods(t *testing.T) {
	d := NewInvalidRequest(3, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	validMethods := []string{"REGISTER", "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE"}
	for _, method := range validMethods {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip, Method: method,
		}
		if threat := d.Detect(evt); threat != nil {
			t.Errorf("valid method %s should not trigger threat", method)
		}
	}
}

func TestInvalidRequestEmptyMethod(t *testing.T) {
	d := NewInvalidRequest(1, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	evt := models.SIPEvent{
		Timestamp: time.Now(), SourceIP: ip, Method: "",
	}
	threat := d.Detect(evt)
	if threat == nil {
		t.Fatal("empty method should trigger threat")
	}
}
