package ingest

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/andycol/sipreaper/internal/metrics"
	"github.com/andycol/sipreaper/internal/models"
)

var (
	// Kamailio patterns
	kamailioAuthFailRe = regexp.MustCompile(
		`auth.*authentication failed for (\w+)@\S+ from (\d+\.\d+\.\d+\.\d+)`,
	)
	kamailioReceivedRe = regexp.MustCompile(
		`received (\w+) from (\d+\.\d+\.\d+\.\d+):\d+`,
	)

	// OpenSIPS patterns
	// Specific pattern for the carrier-rejection message that also exposes the DID:
	// "Rejected inbound carrier INVITE from non-whitelisted source 172.110.223.33 for DID 64300441975359019"
	opensipsRejectedDIDRe = regexp.MustCompile(
		`(?i)rejected\b[^\n]*\b(INVITE|REGISTER|OPTIONS|SUBSCRIBE|MESSAGE|NOTIFY|ACK|BYE|CANCEL|UPDATE|REFER|INFO|PRACK)\b[^\n]*?(\d+\.\d+\.\d+\.\d+)[^\n]*?\bDID\s+(\S+)`,
	)
	// Generic rejection: "Rejected ... INVITE ... 1.2.3.4 ..."
	opensipsRejectedRe = regexp.MustCompile(
		`(?i)rejected\b.*\b(INVITE|REGISTER|OPTIONS|SUBSCRIBE|MESSAGE|NOTIFY|ACK|BYE|CANCEL|UPDATE|REFER|INFO|PRACK)\b.*?(\d+\.\d+\.\d+\.\d+)`,
	)
	// "authentication failed for user@domain from 1.2.3.4"
	opensipsAuthFailRe = regexp.MustCompile(
		`(?i)authentication failed for (\w[\w.]*)@\S+ from (\d+\.\d+\.\d+\.\d+)`,
	)
	// "failed to authenticate user from 1.2.3.4"
	opensipsFailedAuthRe = regexp.MustCompile(
		`(?i)failed to authenticate (\w+) from (\d+\.\d+\.\d+\.\d+)`,
	)
	// "received (METHOD) from 1.2.3.4:port"
	opensipsReceivedRe = regexp.MustCompile(
		`(?i)received\s+(INVITE|REGISTER|OPTIONS|SUBSCRIBE|MESSAGE|NOTIFY)\s+from\s+(\d+\.\d+\.\d+\.\d+)`,
	)
	// "request (METHOD) from 1.2.3.4 rejected/blocked/denied/forbidden"
	opensipsDeniedRe = regexp.MustCompile(
		`(?i)(INVITE|REGISTER|OPTIONS|SUBSCRIBE|MESSAGE|NOTIFY)\s+from\s+(\d+\.\d+\.\d+\.\d+).*(?:rejected|blocked|denied|forbidden)`,
	)
)

type LogTailer struct {
	path     string
	format   string
	patterns []*regexp.Regexp
	events   chan<- models.SIPEvent
	done     chan struct{}

	// Stats — accessed atomically.
	matchedCount   atomic.Uint64
	unmatchedCount atomic.Uint64

	// Periodically log a sample of unmatched lines so operators can spot
	// patterns the parser is missing. Rate-limited inside Run().
	debugUnmatched bool
}

func NewLogTailer(path, format string, customPatterns []string, events chan<- models.SIPEvent) (*LogTailer, error) {
	lt := &LogTailer{
		path:           path,
		format:         format,
		events:         events,
		done:           make(chan struct{}),
		debugUnmatched: true,
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
		log.Printf("log tailer: failed to open %s: %v", lt.path, err)
		return
	}
	log.Printf("log tailer: tailing %s (format=%s)", lt.path, lt.format)
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

		evt := lt.parseLine(line)

		if evt != nil {
			lt.matchedCount.Add(1)
			metrics.LogTailerMatched.Inc()
			evt.Source = "log"
			select {
			case lt.events <- *evt:
			case <-lt.done:
				return
			}
		} else {
			lt.unmatchedCount.Add(1)
			metrics.LogTailerUnmatched.Inc()
			if lt.debugUnmatched {
				// Sample roughly one unmatched line per 100 to avoid spam.
				if lt.unmatchedCount.Load()%100 == 1 {
					log.Printf("log tailer: unmatched line (sample): %s", line)
				}
			}
		}
	}
}

func (lt *LogTailer) Stop() {
	close(lt.done)
}

// Stats returns the running totals of parsed vs unparsed lines.
func (lt *LogTailer) Stats() (matched, unmatched uint64) {
	return lt.matchedCount.Load(), lt.unmatchedCount.Load()
}

// ParseLine runs a line through every built-in parser (kamailio + opensips)
// and returns which parser matched + the resulting event. Used by the CLI
// "test-line" command for diagnosing custom log formats.
func ParseLine(line string) (parser string, evt *models.SIPEvent) {
	if e, _ := parseKamailioLine(line); e != nil {
		return "kamailio", e
	}
	if e, _ := parseOpenSIPSLine(line); e != nil {
		return "opensips", e
	}
	return "", nil
}

// parseLine runs every available parser against the line and returns the first
// match. We cascade kamailio/opensips/custom regardless of configured format
// — the configured format is just a hint about which to try first. This makes
// the daemon robust to format misconfiguration and to mixed-vendor log files
// (e.g. a kamailio-fronted opensips dispatcher).
func (lt *LogTailer) parseLine(line string) *models.SIPEvent {
	primary, secondary := parseKamailioLine, parseOpenSIPSLine
	if lt.format == "opensips" {
		primary, secondary = parseOpenSIPSLine, parseKamailioLine
	}

	if evt, _ := primary(line); evt != nil {
		return evt
	}
	if evt, _ := secondary(line); evt != nil {
		return evt
	}
	if len(lt.patterns) > 0 {
		if evt := lt.matchCustomPatterns(line); evt != nil {
			return evt
		}
	}
	return nil
}

func parseOpenSIPSLine(line string) (*models.SIPEvent, error) {
	// Carrier rejection with DID context — most informative variant.
	// "Rejected inbound carrier INVITE from non-whitelisted source 172.110.223.33 for DID 64300441975359019"
	if m := opensipsRejectedDIDRe.FindStringSubmatch(line); m != nil {
		return &models.SIPEvent{
			Timestamp:    time.Now(),
			SourceIP:     net.ParseIP(m[2]),
			Method:       strings.ToUpper(m[1]),
			ToUser:       m[3],
			ResponseCode: 403,
			Rejected:     true,
			RejectReason: "non-whitelisted source",
		}, nil
	}

	// Generic "Rejected ... METHOD ... IP" without a DID.
	if m := opensipsRejectedRe.FindStringSubmatch(line); m != nil {
		return &models.SIPEvent{
			Timestamp:    time.Now(),
			SourceIP:     net.ParseIP(m[2]),
			Method:       strings.ToUpper(m[1]),
			ResponseCode: 403,
			Rejected:     true,
			RejectReason: "rejected by sip server",
		}, nil
	}

	// "authentication failed for user@domain from 1.2.3.4"
	if m := opensipsAuthFailRe.FindStringSubmatch(line); m != nil {
		return &models.SIPEvent{
			Timestamp:    time.Now(),
			SourceIP:     net.ParseIP(m[2]),
			Method:       "REGISTER",
			FromUser:     m[1],
			ResponseCode: 401,
		}, nil
	}

	// "failed to authenticate user from 1.2.3.4"
	if m := opensipsFailedAuthRe.FindStringSubmatch(line); m != nil {
		return &models.SIPEvent{
			Timestamp:    time.Now(),
			SourceIP:     net.ParseIP(m[2]),
			Method:       "REGISTER",
			FromUser:     m[1],
			ResponseCode: 401,
		}, nil
	}

	// "received METHOD from 1.2.3.4"
	if m := opensipsReceivedRe.FindStringSubmatch(line); m != nil {
		return &models.SIPEvent{
			Timestamp: time.Now(),
			SourceIP:  net.ParseIP(m[2]),
			Method:    strings.ToUpper(m[1]),
		}, nil
	}

	// "INVITE from 1.2.3.4 rejected/blocked/denied/forbidden"
	if m := opensipsDeniedRe.FindStringSubmatch(line); m != nil {
		return &models.SIPEvent{
			Timestamp:    time.Now(),
			SourceIP:     net.ParseIP(m[2]),
			Method:       strings.ToUpper(m[1]),
			ResponseCode: 403,
			Rejected:     true,
			RejectReason: "denied by sip server",
		}, nil
	}

	return nil, nil
}

// matchCustomPatterns tries user-defined regex patterns.
// Patterns should have named or positional groups: group 1 = IP (required), group 2 = method (optional).
func (lt *LogTailer) matchCustomPatterns(line string) *models.SIPEvent {
	ipRe := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
	for _, re := range lt.patterns {
		if m := re.FindStringSubmatch(line); m != nil {
			var ip net.IP
			var method string

			// Try to extract IP from named group or find first IP in match
			if len(m) > 1 {
				ip = net.ParseIP(m[1])
			}
			if ip == nil {
				// Fallback: find any IP in the full match
				if found := ipRe.FindString(m[0]); found != "" {
					ip = net.ParseIP(found)
				}
			}
			if ip == nil {
				continue
			}
			if len(m) > 2 {
				method = strings.ToUpper(m[2])
			}

			return &models.SIPEvent{
				Timestamp: time.Now(),
				SourceIP:  ip,
				Method:    method,
			}
		}
	}
	return nil
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
