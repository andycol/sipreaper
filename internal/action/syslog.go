package action

import (
	"log"

	"github.com/andycol/sipreaper/internal/models"
)

type SyslogNotifier struct{}

func NewSyslogNotifier() *SyslogNotifier {
	return &SyslogNotifier{}
}

func (n *SyslogNotifier) Name() string { return "syslog" }

func (n *SyslogNotifier) Notify(event models.NotifyEvent) error {
	log.Printf("sipreaper %s: ip=%s detector=%s severity=%s duration=%s reason=%q",
		event.Type, event.IP, event.Detector, event.Severity, event.Duration, event.Reason)
	return nil
}
