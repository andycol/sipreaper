package ingest

import (
	"testing"
)

func TestParseSIPRequest(t *testing.T) {
	raw := "REGISTER sip:example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.100:5060\r\n" +
		"From: <sip:alice@example.com>;tag=abc123\r\n" +
		"To: <sip:alice@example.com>\r\n" +
		"Call-ID: call-123@192.168.1.100\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"User-Agent: friendly-scanner\r\n" +
		"Content-Length: 0\r\n\r\n"

	msg, err := ParseSIPMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseSIPMessage() error: %v", err)
	}

	if msg.Method != "REGISTER" {
		t.Errorf("method = %q, want REGISTER", msg.Method)
	}
	if msg.CallID != "call-123@192.168.1.100" {
		t.Errorf("call-id = %q, want call-123@192.168.1.100", msg.CallID)
	}
	if msg.UserAgent != "friendly-scanner" {
		t.Errorf("user-agent = %q, want friendly-scanner", msg.UserAgent)
	}
	if msg.FromUser != "alice" {
		t.Errorf("from user = %q, want alice", msg.FromUser)
	}
	if msg.ToUser != "alice" {
		t.Errorf("to user = %q, want alice", msg.ToUser)
	}
	if msg.ResponseCode != 0 {
		t.Errorf("response code = %d, want 0 for request", msg.ResponseCode)
	}
	if msg.IsResponse {
		t.Error("should not be a response")
	}
}

func TestParseSIPResponse(t *testing.T) {
	raw := "SIP/2.0 401 Unauthorized\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.100:5060\r\n" +
		"From: <sip:alice@example.com>;tag=abc123\r\n" +
		"To: <sip:alice@example.com>;tag=def456\r\n" +
		"Call-ID: call-456@192.168.1.100\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Content-Length: 0\r\n\r\n"

	msg, err := ParseSIPMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseSIPMessage() error: %v", err)
	}

	if !msg.IsResponse {
		t.Error("should be a response")
	}
	if msg.ResponseCode != 401 {
		t.Errorf("response code = %d, want 401", msg.ResponseCode)
	}
	if msg.Method != "REGISTER" {
		t.Errorf("method = %q, want REGISTER (from CSeq)", msg.Method)
	}
}

func TestParseSIPInvalidMessage(t *testing.T) {
	_, err := ParseSIPMessage([]byte("garbage data"))
	if err == nil {
		t.Error("expected error for garbage input")
	}
}

func TestParseSIPFromUser(t *testing.T) {
	tests := []struct {
		from string
		want string
	}{
		{`<sip:100@example.com>`, "100"},
		{`"Alice" <sip:alice@example.com>;tag=abc`, "alice"},
		{`sip:bob@example.com`, "bob"},
	}

	for _, tt := range tests {
		got := extractUser(tt.from)
		if got != tt.want {
			t.Errorf("extractUser(%q) = %q, want %q", tt.from, got, tt.want)
		}
	}
}
