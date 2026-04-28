package ingest

import (
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
	pc := &PcapCapture{events: events, done: make(chan struct{}), inflight: make(map[string]requestRecord)}

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
		IsResponse: true, ResponseCode: 403, Method: "INVITE", CallID: "abc-123",
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
