package action

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"github.com/andycol/sipreaper/internal/models"
)

var severityLevels = map[string]int{
	"low":    1,
	"medium": 2,
	"high":   3,
}

type EmailNotifier struct {
	host        string
	port        int
	useTLS      bool
	from        string
	to          []string
	username    string
	passwordEnv string
	minSeverity string
}

func NewEmailNotifier(host string, port int, useTLS bool, from string, to []string, username, passwordEnv, minSeverity string) *EmailNotifier {
	return &EmailNotifier{
		host:        host,
		port:        port,
		useTLS:      useTLS,
		from:        from,
		to:          to,
		username:    username,
		passwordEnv: passwordEnv,
		minSeverity: minSeverity,
	}
}

func (n *EmailNotifier) Name() string { return "email" }

func (n *EmailNotifier) Notify(event models.NotifyEvent) error {
	if !n.shouldNotify(event.Severity) {
		return nil
	}

	subject, body := n.formatMessage(event)
	return n.send(subject, body)
}

func (n *EmailNotifier) shouldNotify(severity string) bool {
	if n.minSeverity == "" {
		return true
	}
	return severityLevels[severity] >= severityLevels[n.minSeverity]
}

func (n *EmailNotifier) formatMessage(event models.NotifyEvent) (string, string) {
	subject := fmt.Sprintf("[SIPReaper] %s: %s", event.Type, event.IP)
	body := fmt.Sprintf(
		"SIPReaper %s notification\n\n"+
			"IP:       %s\n"+
			"Detector: %s\n"+
			"Severity: %s\n"+
			"Duration: %s\n"+
			"Reason:   %s\n"+
			"Time:     %s\n",
		event.Type, event.IP, event.Detector,
		event.Severity, event.Duration, event.Reason,
		event.Timestamp.Format("2006-01-02 15:04:05 UTC"),
	)
	return subject, body
}

func (n *EmailNotifier) send(subject, body string) error {
	password := os.Getenv(n.passwordEnv)
	addr := fmt.Sprintf("%s:%d", n.host, n.port)
	auth := smtp.PlainAuth("", n.username, password, n.host)

	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n",
		n.from, strings.Join(n.to, ","), subject)
	msg := []byte(headers + body)

	if n.useTLS {
		return n.sendTLS(addr, auth, msg)
	}
	return smtp.SendMail(addr, auth, n.from, n.to, msg)
}

func (n *EmailNotifier) sendTLS(addr string, auth smtp.Auth, msg []byte) error {
	tlsConfig := &tls.Config{ServerName: n.host}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}

	client, err := smtp.NewClient(conn, n.host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := client.Mail(n.from); err != nil {
		return err
	}
	for _, addr := range n.to {
		if err := client.Rcpt(addr); err != nil {
			return err
		}
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}
