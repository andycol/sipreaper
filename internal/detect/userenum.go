package detect

import (
	"fmt"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

type UserEnum struct {
	maxExtensions int
	window        time.Duration
	sw            *SlidingWindow
}

func NewUserEnum(maxExtensions int, window time.Duration) *UserEnum {
	return &UserEnum{
		maxExtensions: maxExtensions,
		window:        window,
		sw:            NewSlidingWindow(window),
	}
}

func (d *UserEnum) Name() string { return "user_enum" }

func (d *UserEnum) Detect(event models.SIPEvent) *models.Threat {
	if event.Method != "REGISTER" && event.Method != "INVITE" {
		return nil
	}
	if event.ToUser == "" {
		return nil
	}

	ip := event.SourceIP.String()
	d.sw.AddKeyed(ip, event.ToUser)

	distinct := d.sw.DistinctCount(ip)
	if distinct >= d.maxExtensions {
		return &models.Threat{
			Timestamp:   time.Now(),
			SourceIP:    event.SourceIP,
			Detector:    "user_enum",
			Severity:    "high",
			Description: fmt.Sprintf("%d distinct extensions targeted in %s", distinct, d.window),
			EventCount:  distinct,
			Window:      d.window,
		}
	}
	return nil
}
