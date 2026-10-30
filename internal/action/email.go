package action

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

const (
	// emailQueueSize bounds mail waiting to go out. A ban storm beyond this
	// drops mail rather than memory or ban latency.
	emailQueueSize = 100
	// emailTimeout covers one whole delivery: dial, TLS, auth and DATA.
	emailTimeout = 30 * time.Second
	// emailDrainTimeout is how long Close waits for queued mail on shutdown.
	emailDrainTimeout = 5 * time.Second
)

type emailMessage struct {
	subject, body string
}

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

	// Delivery happens on a background worker so a slow or dead SMTP server
	// never stalls the ban pipeline that calls Notify.
	timeout   time.Duration
	queue     chan emailMessage
	done      chan struct{}
	closeOnce sync.Once
}

func NewEmailNotifier(host string, port int, useTLS bool, from string, to []string, username, passwordEnv, minSeverity string) *EmailNotifier {
	n := &EmailNotifier{
		host:        host,
		port:        port,
		useTLS:      useTLS,
		from:        from,
		to:          to,
		username:    username,
		passwordEnv: passwordEnv,
		minSeverity: minSeverity,
		timeout:     emailTimeout,
		queue:       make(chan emailMessage, emailQueueSize),
		done:        make(chan struct{}),
	}
	go n.worker()
	return n
}

func (n *EmailNotifier) Name() string { return "email" }

// Notify queues the message and returns immediately. It only errors when the
// queue is full, in which case the message is dropped.
func (n *EmailNotifier) Notify(event models.NotifyEvent) error {
	if !n.shouldNotify(event.Severity) {
		return nil
	}

	subject, body := n.formatMessage(event)
	select {
	case n.queue <- emailMessage{subject: subject, body: body}:
		return nil
	default:
		return fmt.Errorf("email queue full, dropped %s notification for %s", event.Type, event.IP)
	}
}

// Close stops accepting mail and waits briefly for the queue to drain.
func (n *EmailNotifier) Close() error {
	n.closeOnce.Do(func() { close(n.queue) })
	select {
	case <-n.done:
		return nil
	case <-time.After(emailDrainTimeout):
		return fmt.Errorf("email: %d messages still queued at shutdown", len(n.queue))
	}
}

func (n *EmailNotifier) worker() {
	defer close(n.done)
	for m := range n.queue {
		if err := n.send(m.subject, m.body); err != nil {
			log.Printf("notifier email error: %v", err)
		}
	}
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

	return n.deliver(addr, auth, msg)
}

// deliver does what smtp.SendMail does, but with a deadline on the whole
// conversation: SendMail has none, so a server that accepts the TCP
// connection and then goes quiet would hang the worker forever.
func (n *EmailNotifier) deliver(addr string, auth smtp.Auth, msg []byte) error {
	deadline := time.Now().Add(n.timeout)
	dialer := &net.Dialer{Deadline: deadline}

	var conn net.Conn
	var err error
	if n.useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: n.host})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return err
	}

	client, err := smtp.NewClient(conn, n.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	if !n.useTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: n.host}); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}
	if ok, _ := client.Extension("AUTH"); ok && n.username != "" {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
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
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
