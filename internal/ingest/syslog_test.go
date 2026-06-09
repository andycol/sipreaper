package ingest

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func TestSyslogIngestParsesUDPLine(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("udp bind unavailable in this environment: %v", err)
	}
	probe.Close()

	events := make(chan models.SIPEvent, 1)
	ing := NewSyslogIngest("127.0.0.1:0", events)

	ready := make(chan string, 1)
	go func() {
		for {
			ing.mu.Lock()
			conn := ing.conn
			ing.mu.Unlock()
			if conn != nil {
				ready <- conn.LocalAddr().String()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	go ing.Run()
	defer ing.Stop()

	var addr string
	select {
	case addr = <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for syslog listener")
	}

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()

	line := `Apr 28 11:02:14 sip2 opensips[4321]: WARNING:Rejected inbound carrier INVITE from non-whitelisted source 77.68.33.97 for DID 64300441975359019`
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatalf("write udp: %v", err)
	}

	select {
	case evt := <-events:
		if evt.Source != "syslog" {
			t.Fatalf("source = %q, want syslog", evt.Source)
		}
		if evt.SourceIP.String() != "77.68.33.97" || !evt.Rejected {
			t.Fatalf("unexpected event: %+v", evt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for syslog event")
	}
}
