package action

import (
	"github.com/andycol/sipreaper/internal/models"
)

// Notifier sends notifications about ban/unban events.
type Notifier interface {
	Name() string
	Notify(event models.NotifyEvent) error
}
