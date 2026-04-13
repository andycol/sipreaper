package ingest

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SIPMessage represents a parsed SIP message (request or response).
type SIPMessage struct {
	IsResponse   bool
	Method       string
	ResponseCode int
	CallID       string
	UserAgent    string
	FromUser     string
	ToUser       string
}

var (
	requestLineRe  = regexp.MustCompile(`^(\w+)\s+sip:`)
	responseLineRe = regexp.MustCompile(`^SIP/2\.0\s+(\d+)`)
	cseqMethodRe   = regexp.MustCompile(`(?i)^CSeq:\s*\d+\s+(\w+)`)
	userRe         = regexp.MustCompile(`sip:([^@]+)@`)
)

func ParseSIPMessage(data []byte) (*SIPMessage, error) {
	text := string(data)
	lines := strings.Split(text, "\r\n")
	if len(lines) < 2 {
		lines = strings.Split(text, "\n")
	}
	if len(lines) < 2 {
		return nil, fmt.Errorf("too few lines in SIP message")
	}

	msg := &SIPMessage{}

	// Parse first line: request or response
	firstLine := lines[0]
	if m := responseLineRe.FindStringSubmatch(firstLine); m != nil {
		msg.IsResponse = true
		code, _ := strconv.Atoi(m[1])
		msg.ResponseCode = code
	} else if m := requestLineRe.FindStringSubmatch(firstLine); m != nil {
		msg.Method = m[1]
	} else {
		return nil, fmt.Errorf("unrecognized SIP first line: %q", firstLine)
	}

	// Parse headers
	for _, line := range lines[1:] {
		if line == "" {
			break
		}

		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "call-id:") || strings.HasPrefix(lower, "i:") {
			msg.CallID = strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
		} else if strings.HasPrefix(lower, "user-agent:") {
			msg.UserAgent = strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
		} else if strings.HasPrefix(lower, "from:") || strings.HasPrefix(lower, "f:") {
			msg.FromUser = extractUser(line[strings.IndexByte(line, ':')+1:])
		} else if strings.HasPrefix(lower, "to:") || strings.HasPrefix(lower, "t:") {
			prefix := line[:strings.IndexByte(line, ':')]
			if strings.EqualFold(strings.TrimSpace(prefix), "to") || strings.TrimSpace(prefix) == "t" {
				msg.ToUser = extractUser(line[strings.IndexByte(line, ':')+1:])
			}
		} else if m := cseqMethodRe.FindStringSubmatch(line); m != nil {
			if msg.IsResponse {
				msg.Method = strings.ToUpper(m[1])
			}
		}
	}

	return msg, nil
}

func extractUser(headerValue string) string {
	m := userRe.FindStringSubmatch(headerValue)
	if m != nil {
		return m[1]
	}
	return ""
}
