package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

// Honeypot bans IPs that touch a configured set of decoy extensions/DIDs.
// Real users never dial these — anyone who does is fishing the dial plan and
// should be ejected on the first hit.
type Honeypot struct {
	extensions map[string]struct{}
}

func NewHoneypot(extensions []string) *Honeypot {
	set := make(map[string]struct{}, len(extensions))
	for _, e := range extensions {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		set[strings.ToLower(e)] = struct{}{}
	}
	return &Honeypot{extensions: set}
}

func (d *Honeypot) Name() string { return "honeypot" }

func (d *Honeypot) Detect(event models.SIPEvent) *models.Threat {
	if len(d.extensions) == 0 || event.SourceIP == nil {
		return nil
	}

	target := strings.ToLower(event.ToUser)
	if target == "" {
		return nil
	}
	if _, hit := d.extensions[target]; !hit {
		return nil
	}

	return &models.Threat{
		Timestamp:   time.Now(),
		SourceIP:    event.SourceIP,
		Detector:    "honeypot",
		Severity:    "high",
		Description: fmt.Sprintf("traffic to honeypot extension %q (method=%s)", event.ToUser, event.Method),
		EventCount:  1,
		Window:      time.Hour, // descriptive only — honeypot fires immediately
	}
}
