package ingest

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestBuildBPFFilter(t *testing.T) {
	tests := []struct {
		ports  []int
		custom string
		want   string
	}{
		{[]int{5060}, "", "udp port 5060"},
		{[]int{5060, 5061}, "", "udp port 5060 or udp port 5061"},
		{[]int{5060}, "host 10.0.0.1", "host 10.0.0.1"},
	}

	for _, tt := range tests {
		got := buildBPFFilter(tt.ports, tt.custom)
		if got != tt.want {
			t.Errorf("buildBPFFilter(%v, %q) = %q, want %q", tt.ports, tt.custom, got, tt.want)
		}
	}
}

func TestPcapResponsePairingAttributesRejectionToOriginalSender(t *testing.T) {
	events := make(chan models.SIPEvent, 4)
	pc := &PcapCapture{events: events, done: make(chan struct{}), inflight: make(map[string]requestRecord),
		rejects: newRejectMatcher([]string{"403 Forbidden"})}

	attacker := net.ParseIP("203.0.113.50")
	server := net.ParseIP("10.0.0.1")

	// Step 1: attacker INVITEs us
	pc.handleSIP(attacker, server, &SIPMessage{
		Method: "INVITE", CallID: "abc-123",
		FromUser: "evil", ToUser: "10000",
	})

	// Drain the request event
	<-events

	// Step 2: our SIP server responds 403 — the response packet's source IP is
	// the SIP server, but the threat originates from `attacker`.
	pc.handleSIP(server, attacker, &SIPMessage{
		IsResponse: true, ResponseCode: 403, Reason: "Forbidden", Method: "INVITE", CallID: "abc-123",
	})

	select {
	case evt := <-events:
		if !evt.SourceIP.Equal(attacker) {
			t.Errorf("source ip = %s, want attacker %s", evt.SourceIP, attacker)
		}
		if !evt.Rejected {
			t.Error("expected Rejected=true on synthesized response event")
		}
		if evt.ResponseCode != 403 {
			t.Errorf("response code = %d, want 403", evt.ResponseCode)
		}
		if evt.Method != "INVITE" {
			t.Errorf("method = %q, want INVITE", evt.Method)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for synthesized response event")
	}
}

func TestPcapInflightMapIsBounded(t *testing.T) {
	// Drain channel keeps the goroutine that emits events from blocking.
	events := make(chan models.SIPEvent, 1024)
	go func() {
		for range events {
		}
	}()

	pc := &PcapCapture{events: events, done: make(chan struct{}), inflight: make(map[string]requestRecord)}

	src := net.ParseIP("203.0.113.1")
	dst := net.ParseIP("10.0.0.1")

	// Push a couple thousand more requests than the cap; each with a unique
	// Call-ID so nothing collapses.
	overflow := 200
	for i := 0; i < inflightMaxEntries+overflow; i++ {
		pc.handleSIP(src, dst, &SIPMessage{
			Method: "INVITE",
			CallID: fmt.Sprintf("call-%d", i),
		})
	}

	pc.inflightMu.Lock()
	got := len(pc.inflight)
	pc.inflightMu.Unlock()

	if got > inflightMaxEntries {
		t.Errorf("inflight grew to %d, cap is %d", got, inflightMaxEntries)
	}
}

func TestPcapResponseWithoutMatchingRequestUsesPacketDest(t *testing.T) {
	events := make(chan models.SIPEvent, 1)
	pc := &PcapCapture{events: events, done: make(chan struct{}), inflight: make(map[string]requestRecord)}

	// We didn't see the request (SIP server sends a stray 4xx). The destination
	// of the response is the only attribution we have.
	server := net.ParseIP("10.0.0.1")
	target := net.ParseIP("203.0.113.99")

	pc.handleSIP(server, target, &SIPMessage{
		IsResponse: true, ResponseCode: 404, Method: "INVITE", CallID: "no-match",
	})

	select {
	case evt := <-events:
		if !evt.SourceIP.Equal(target) {
			t.Errorf("source ip = %s, want %s", evt.SourceIP, target)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out")
	}
}

// drain returns every event currently buffered on ch.
func drain(ch chan models.SIPEvent) []models.SIPEvent {
	var out []models.SIPEvent
	for {
		select {
		case e := <-ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

func newTestPcap(local ...string) (*PcapCapture, chan models.SIPEvent) {
	events := make(chan models.SIPEvent, 64)
	locals := map[string]bool{}
	for _, l := range local {
		locals[net.ParseIP(l).String()] = true
	}
	return &PcapCapture{
		events: events, done: make(chan struct{}), inflight: make(map[string]requestRecord),
		isLocal: func(ip net.IP) bool { return locals[ip.String()] },
		rejects: newRejectMatcher([]string{"403 Forbidden"}),
	}, events
}

func TestPcapDigestChallengeIsNotAnEvent(t *testing.T) {
	server, phone := "203.0.113.1", "198.51.100.7"
	pc, events := newTestPcap(server)

	for _, tc := range []struct {
		method string
		code   int
	}{{"REGISTER", 401}, {"INVITE", 407}} {
		pc.handleSIP(net.ParseIP(phone), net.ParseIP(server), &SIPMessage{Method: tc.method, CallID: "c-" + tc.method})
		pc.handleSIP(net.ParseIP(server), net.ParseIP(phone), &SIPMessage{
			IsResponse: true, ResponseCode: tc.code, Method: tc.method, CallID: "c-" + tc.method,
		})
	}

	for _, e := range drain(events) {
		if e.IsResponse {
			t.Errorf("challenge produced a response event: %+v", e)
		}
	}
}

func TestPcapChallengeForUnseenRequestIsIgnored(t *testing.T) {
	pc, events := newTestPcap("203.0.113.1")
	pc.handleSIP(net.ParseIP("203.0.113.1"), net.ParseIP("198.51.100.7"), &SIPMessage{
		IsResponse: true, ResponseCode: 401, Method: "REGISTER", CallID: "never-seen",
	})
	if got := drain(events); len(got) != 0 {
		t.Errorf("expected no events, got %+v", got)
	}
}

func TestPcapFailedAuthWithCredentialsIsEmittedButNotRejected(t *testing.T) {
	server, phone := "203.0.113.1", "198.51.100.7"
	pc, events := newTestPcap(server)

	pc.handleSIP(net.ParseIP(phone), net.ParseIP(server), &SIPMessage{Method: "REGISTER", CallID: "c1", HasAuth: true})
	pc.handleSIP(net.ParseIP(server), net.ParseIP(phone), &SIPMessage{
		IsResponse: true, ResponseCode: 401, Method: "REGISTER", CallID: "c1",
	})

	got := drain(events)
	if len(got) != 2 {
		t.Fatalf("expected request + response events, got %d: %+v", len(got), got)
	}
	resp := got[1]
	if !resp.IsResponse || resp.ResponseCode != 401 || !resp.SourceIP.Equal(net.ParseIP(phone)) {
		t.Errorf("unexpected failed-auth event: %+v", resp)
	}
	if resp.Rejected {
		t.Error("failed auth must not be Rejected (server_rejected would ban on one stale nonce)")
	}
}

func TestPcapOrdinaryCallOutcomesAreNotRejected(t *testing.T) {
	server, phone := "203.0.113.1", "198.51.100.7"
	pc, events := newTestPcap(server)

	for _, code := range []int{404, 480, 486, 487, 488, 503, 603} {
		pc.handleSIP(net.ParseIP(server), net.ParseIP(phone), &SIPMessage{
			IsResponse: true, ResponseCode: code, Method: "INVITE", CallID: fmt.Sprintf("c-%d", code),
		})
	}
	for _, e := range drain(events) {
		if e.Rejected {
			t.Errorf("code %d marked Rejected", e.ResponseCode)
		}
		if !e.IsResponse {
			t.Errorf("code %d event missing IsResponse", e.ResponseCode)
		}
	}
}

// A proxied call: phone → server → carrier, same Call-ID on both legs. The
// carrier answers 486, the server relays 486 to the phone. Nothing may be
// attributed to the server itself or to the carrier.
func TestPcapProxiedCallNeverAttributesServerOrCarrier(t *testing.T) {
	server, phone, carrier := "203.0.113.1", "198.51.100.7", "192.0.2.50"
	pc, events := newTestPcap(server)
	S, P, C := net.ParseIP(server), net.ParseIP(phone), net.ParseIP(carrier)

	pc.handleSIP(P, S, &SIPMessage{Method: "INVITE", CallID: "x", ToUser: "441234", HasAuth: true})
	pc.handleSIP(S, C, &SIPMessage{Method: "INVITE", CallID: "x", ToUser: "441234"})
	pc.handleSIP(C, S, &SIPMessage{IsResponse: true, ResponseCode: 486, Method: "INVITE", CallID: "x"})
	pc.handleSIP(S, P, &SIPMessage{IsResponse: true, ResponseCode: 486, Method: "INVITE", CallID: "x"})
	// Server-originated OPTIONS keepalive to the phone, and the phone's 200.
	pc.handleSIP(S, P, &SIPMessage{Method: "OPTIONS", CallID: "ka"})
	pc.handleSIP(P, S, &SIPMessage{IsResponse: true, ResponseCode: 200, Method: "OPTIONS", CallID: "ka"})

	got := drain(events)
	if len(got) != 2 {
		t.Fatalf("expected exactly phone's INVITE + relayed 486, got %d: %+v", len(got), got)
	}
	for _, e := range got {
		if !e.SourceIP.Equal(P) {
			t.Errorf("event attributed to %s, want phone %s: %+v", e.SourceIP, P, e)
		}
	}
	if got[1].ToUser != "441234" {
		t.Errorf("response not enriched from phone's request: %+v", got[1])
	}
}

// Phonovo's script answers ACL failures with "403 Forbidden" but reuses 403
// for customer-side problems. Only the configured phrase may count.
func TestPcapRejectionMatchesReasonPhrase(t *testing.T) {
	server, phone := "203.0.113.1", "198.51.100.7"
	pc, events := newTestPcap(server)

	cases := map[string]bool{
		"Forbidden":               true,
		"forbidden":               true,
		"Registration Required":   false,
		"Call blocked":            false,
		"Auth ID mismatch":        false,
		"To/From mismatch":        false,
		"Internal Test Line Only": false,
	}
	for reason, want := range cases {
		pc.handleSIP(net.ParseIP(server), net.ParseIP(phone), &SIPMessage{
			IsResponse: true, ResponseCode: 403, Reason: reason, Method: "INVITE", CallID: "c-" + reason,
		})
		got := drain(events)
		if len(got) != 1 {
			t.Fatalf("%q: expected 1 event, got %d", reason, len(got))
		}
		if got[0].Rejected != want {
			t.Errorf("403 %q: Rejected = %v, want %v", reason, got[0].Rejected, want)
		}
	}
}

func TestRejectMatcherCodeOnlyMatchesAnyPhrase(t *testing.T) {
	m := newRejectMatcher([]string{"403", "603 Declined By Policy"})
	if !m.match(403, "Registration Required") {
		t.Error(`"403" should match any 403`)
	}
	if !m.match(603, "declined by policy") {
		t.Error("phrase match should be case-insensitive")
	}
	if m.match(603, "Decline") {
		t.Error("different phrase must not match")
	}
	if m.match(404, "Not Found") {
		t.Error("unlisted code must not match")
	}
}
