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
	// Access-control rejection, e.g.
	//   "Rejected inbound carrier INVITE from non-whitelisted source 172.110.223.33 for DID 6430044…"
	//   "Rejected Teams ingress from non-whitelisted source 1.2.3.4 for INVITE sip:…"
	// Only lines that say WHY in ACL terms count: scripts also log customer-side
	// problems as "Rejected …" ("Rejected device INVITE without active
	// registration"), and those must not ban a customer's site.
	opensipsRejectedRe = regexp.MustCompile(
		`(?i)\brejected\b.*\b(non-whitelisted|not whitelisted|not allowed|blacklisted|blocked source|denied|forbidden)\b`,
	)
	sipMethodRe = regexp.MustCompile(
		`\b(INVITE|REGISTER|OPTIONS|SUBSCRIBE|MESSAGE|NOTIFY|ACK|BYE|CANCEL|UPDATE|REFER|INFO|PRACK)\b`,
	)
	// The offending address is the one labelled source/from — not whatever
	// IP happens to appear first (a Call-ID host, an R-URI host…).
	labelledIPRe = regexp.MustCompile(`(?i)\b(?:source|from|src)[=:\s]+(\d+\.\d+\.\d+\.\d+)`)
	anyIPRe      = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
	didRe        = regexp.MustCompile(`\bDID\s+(\S+)`)
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

	// pollInterval is the sleep at EOF; rotateCheck is how often, while
	// idle at EOF, the path is checked for rotation or truncation.
	pollInterval time.Duration
	rotateCheck  time.Duration
}

// maxLogLineLen caps a line held across reads; a "line" that never ends is
// dropped rather than buffered without limit.
const maxLogLineLen = 64 * 1024

func NewLogTailer(path, format string, customPatterns []string, events chan<- models.SIPEvent) (*LogTailer, error) {
	lt := &LogTailer{
		path:           path,
		format:         format,
		events:         events,
		done:           make(chan struct{}),
		debugUnmatched: true,
		pollInterval:   100 * time.Millisecond,
		rotateCheck:    time.Second,
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

// Run tails the log until Stop. It follows the file across rotation: when
// the path is replaced (logrotate create, or rename and recreate) it finishes
// the old file and continues from the start of the new one, and when the file
// is truncated in place (copytruncate) it starts again from the top. A file
// that doesn't exist yet is waited for.
func (lt *LogTailer) Run() {
	f, ok := lt.open(true)
	if !ok {
		return
	}
	log.Printf("log tailer: tailing %s (format=%s)", lt.path, lt.format)
	defer func() { f.Close() }()

	reader := bufio.NewReader(f)
	var partial strings.Builder
	lastCheck := time.Now()

	for {
		select {
		case <-lt.done:
			return
		default:
		}

		chunk, err := reader.ReadString('\n')
		if err != nil {
			// At EOF the writer may be mid-line: keep what we have and finish
			// the line on a later read instead of throwing it away.
			if partial.Len()+len(chunk) <= maxLogLineLen {
				partial.WriteString(chunk)
			} else {
				partial.Reset()
			}
			if err != io.EOF {
				log.Printf("log tailer: read %s: %v", lt.path, err)
			}

			if time.Since(lastCheck) >= lt.rotateCheck {
				lastCheck = time.Now()
				if nf, why := lt.checkRotation(f); nf != nil {
					log.Printf("log tailer: %s %s, reopening", lt.path, why)
					if nf != f {
						f.Close()
						f = nf
					}
					reader.Reset(f)
					partial.Reset()
					continue
				}
			}

			select {
			case <-lt.done:
				return
			case <-time.After(lt.pollInterval):
			}
			continue
		}

		line := chunk
		if partial.Len() > 0 {
			partial.WriteString(chunk)
			line = partial.String()
			partial.Reset()
		}
		lt.handleLine(strings.TrimRight(line, "\n\r"))
	}
}

// open opens the log, retrying until it exists or Stop is called. Only a
// file present at startup is read from the end: one that appears later is new,
// so all of it is unread.
func (lt *LogTailer) open(atStartup bool) (*os.File, bool) {
	warned := false
	for {
		f, err := os.Open(lt.path)
		if err == nil {
			if atStartup && !warned {
				f.Seek(0, io.SeekEnd)
			}
			return f, true
		}
		if !warned {
			log.Printf("log tailer: waiting for %s: %v", lt.path, err)
			warned = true
		}
		select {
		case <-lt.done:
			return nil, false
		case <-time.After(lt.rotateCheck):
		}
	}
}

// checkRotation is called at EOF, so everything in f has been read. It
// returns a file to switch to (and why), or nil to keep reading f.
func (lt *LogTailer) checkRotation(f *os.File) (*os.File, string) {
	cur, err := f.Stat()
	if err != nil {
		return nil, ""
	}
	onDisk, err := os.Stat(lt.path)
	if err != nil {
		// Renamed away and not yet recreated: keep the old file and look
		// again next time.
		return nil, ""
	}

	if !os.SameFile(cur, onDisk) {
		nf, err := os.Open(lt.path)
		if err != nil {
			return nil, ""
		}
		return nf, "was rotated"
	}

	pos, err := f.Seek(0, io.SeekCurrent)
	if err == nil && onDisk.Size() < pos {
		if _, err := f.Seek(0, io.SeekStart); err == nil {
			// Same descriptor, rewound — hand it back so the reader resets.
			return f, "was truncated"
		}
	}
	return nil, ""
}

func (lt *LogTailer) handleLine(line string) {
	if line == "" {
		return
	}

	evt := lt.parseLine(line)
	if evt == nil {
		lt.unmatchedCount.Add(1)
		metrics.LogTailerUnmatched.Inc()
		if lt.debugUnmatched {
			// Sample roughly one unmatched line per 100 to avoid spam.
			if lt.unmatchedCount.Load()%100 == 1 {
				log.Printf("log tailer: unmatched line (sample): %s", line)
			}
		}
		return
	}

	lt.matchedCount.Add(1)
	metrics.LogTailerMatched.Inc()
	evt.Source = "log"
	select {
	case lt.events <- *evt:
	case <-lt.done:
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
	if evt := parseOpenSIPSRejected(line); evt != nil {
		return evt, nil
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

// parseOpenSIPSRejected handles access-control rejection lines (see
// opensipsRejectedRe). Returns nil unless the line names a method and an IP.
func parseOpenSIPSRejected(line string) *models.SIPEvent {
	m := opensipsRejectedRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	method := sipMethodRe.FindString(line)
	if method == "" {
		return nil
	}
	var ip net.IP
	if lm := labelledIPRe.FindStringSubmatch(line); lm != nil {
		ip = net.ParseIP(lm[1])
	} else {
		ip = net.ParseIP(anyIPRe.FindString(line))
	}
	if ip == nil {
		return nil
	}

	evt := &models.SIPEvent{
		Timestamp:    time.Now(),
		SourceIP:     ip,
		Method:       method,
		ResponseCode: 403,
		Rejected:     true,
		RejectReason: "rejected by sip server",
	}
	if strings.EqualFold(m[1], "non-whitelisted") {
		evt.RejectReason = "non-whitelisted source"
	}
	if dm := didRe.FindStringSubmatch(line); dm != nil {
		evt.ToUser = dm[1]
	}
	return evt
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
