package detect

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestUserEnumTriggersAtThreshold(t *testing.T) {
	d := NewUserEnum(5, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	var threat *models.Threat
	for i := 0; i < 5; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "REGISTER", ToUser: fmt.Sprintf("ext-%d", 100+i),
		}
		threat = d.Detect(evt)
	}
	if threat == nil {
		t.Fatal("expected threat for user enumeration")
	}
	if threat.Detector != "user_enum" {
		t.Errorf("detector = %q, want user_enum", threat.Detector)
	}
}

func TestUserEnumSameExtensionNoThreat(t *testing.T) {
	d := NewUserEnum(5, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	for i := 0; i < 10; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "REGISTER", ToUser: "ext-100",
		}
		if threat := d.Detect(evt); threat != nil {
			t.Error("same extension repeated should not trigger user enum")
		}
	}
}

func TestUserEnumIgnoresNonRegisterInvite(t *testing.T) {
	d := NewUserEnum(3, 60*time.Second)
	ip := net.ParseIP("10.0.0.1")

	for i := 0; i < 10; i++ {
		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: ip,
			Method: "OPTIONS", ToUser: fmt.Sprintf("ext-%d", i),
		}
		if threat := d.Detect(evt); threat != nil {
			t.Error("OPTIONS should not trigger user enum")
		}
	}
}
