package ingest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

var (
	kamailioAuthFailRe = regexp.MustCompile(
		`auth.*authentication failed for (\w+)@\S+ from (\d+\.\d+\.\d+\.\d+)`,
	)
	kamailioReceivedRe = regexp.MustCompile(
		`received (\w+) from (\d+\.\d+\.\d+\.\d+):\d+`,
	)
)

type LogTailer struct {
	path     string
	format   string
	patterns []*regexp.Regexp
	events   chan<- models.SIPEvent
	done     chan struct{}
}

func NewLogTailer(path, format string, customPatterns []string, events chan<- models.SIPEvent) (*LogTailer, error) {
	lt := &LogTailer{
		path:   path,
		format: format,
		events: events,
		done:   make(chan struct{}),
	}

	for _, p := range customPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("compiling custom pattern %q: %w", p, err)
		}
		lt.patterns = append(lt.patterns, re)
	}

	return lt, nil
}

func (lt *LogTailer) Run() {
	f, err := os.Open(lt.path)
	if err != nil {
		return
	}
	defer f.Close()

	// Seek to end -- we only want new lines
	f.Seek(0, io.SeekEnd)

	reader := bufio.NewReader(f)
	for {
		select {
		case <-lt.done:
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		line = strings.TrimRight(line, "\n\r")
		if line == "" {
			continue
		}

		var evt *models.SIPEvent
		switch lt.format {
		case "kamailio":
			evt, _ = parseKamailioLine(line)
		case "opensips":
			evt, _ = parseKamailioLine(line) // similar format
		}

		if evt != nil {
			evt.Source = "log"
			select {
			case lt.events <- *evt:
			case <-lt.done:
				return
			}
		}
	}
}

func (lt *LogTailer) Stop() {
	close(lt.done)
}

func parseKamailioLine(line string) (*models.SIPEvent, error) {
	// Auth failure: "authentication failed for user@domain from IP"
	if m := kamailioAuthFailRe.FindStringSubmatch(line); m != nil {
		return &models.SIPEvent{
			Timestamp:    time.Now(),
			SourceIP:     net.ParseIP(m[2]),
			Method:       "REGISTER",
			FromUser:     m[1],
			ResponseCode: 401,
		}, nil
	}

	// Received message: "received METHOD from IP:port"
	if m := kamailioReceivedRe.FindStringSubmatch(line); m != nil {
		return &models.SIPEvent{
			Timestamp: time.Now(),
			SourceIP:  net.ParseIP(m[2]),
			Method:    strings.ToUpper(m[1]),
		}, nil
	}

	return nil, nil
}
