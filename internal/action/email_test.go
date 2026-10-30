package action

import (
	"bufio"
	"fmt"
	"io"
	"net"
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

// fakeSMTP is a minimal plaintext SMTP server. With hang set it accepts the
// connection and never speaks, like a wedged relay.
func fakeSMTP(t *testing.T, hang bool) (host string, port int, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 10)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if hang {
					io.Copy(io.Discard, c)
					return
				}
				r := bufio.NewReader(c)
				fmt.Fprint(c, "220 fake ESMTP\r\n")
				var data strings.Builder
				inData := false
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if inData {
						if line == ".\r\n" {
							inData = false
							got <- data.String()
							fmt.Fprint(c, "250 queued\r\n")
							continue
						}
						data.WriteString(line)
						continue
					}
					switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
					case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
						fmt.Fprint(c, "250 fake\r\n")
					case cmd == "DATA":
						inData = true
						fmt.Fprint(c, "354 go ahead\r\n")
					case cmd == "QUIT":
						fmt.Fprint(c, "221 bye\r\n")
						return
					default:
						fmt.Fprint(c, "250 ok\r\n")
					}
				}
			}(c)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, got
}

func banEvent(ip string) models.NotifyEvent {
	return models.NotifyEvent{Type: "ban", IP: ip, Detector: "scanner", Severity: "high", Timestamp: time.Now()}
}

func TestEmailDeliversQueuedMail(t *testing.T) {
	host, port, got := fakeSMTP(t, false)
	n := NewEmailNotifier(host, port, false, "sipreaper@example.com", []string{"ops@example.com"}, "", "", "")
	defer n.Close()

	if err := n.Notify(banEvent("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-got:
		if !strings.Contains(msg, "Subject: [SIPReaper] ban: 10.0.0.1") {
			t.Errorf("unexpected message:\n%s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mail never arrived")
	}
}

// A wedged SMTP server must not block the caller (the ban pipeline), and the
// worker must give up on it rather than hang forever.
func TestEmailHungServerDoesNotBlockNotify(t *testing.T) {
	host, port, _ := fakeSMTP(t, true)
	n := NewEmailNotifier(host, port, false, "sipreaper@example.com", []string{"ops@example.com"}, "", "", "")
	n.timeout = 200 * time.Millisecond

	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := n.Notify(banEvent(fmt.Sprintf("10.0.0.%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("Notify blocked for %s", elapsed)
	}

	// 5 messages × 200ms timeout each — the worker must finish well inside
	// the drain window instead of hanging on the first one.
	if err := n.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestEmailFullQueueDropsInsteadOfBlocking(t *testing.T) {
	// Not started via the constructor, so nothing drains the queue.
	n := &EmailNotifier{queue: make(chan emailMessage, 1), done: make(chan struct{})}
	if err := n.Notify(banEvent("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(banEvent("10.0.0.2")); err == nil {
		t.Error("expected an error when the queue is full")
	}
}
