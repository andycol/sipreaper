package ingest

import (
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

type SyslogIngest struct {
	listen string
	events chan<- models.SIPEvent
	done   chan struct{}

	mu   sync.Mutex
	conn net.PacketConn
	once sync.Once

	matchedCount   atomic.Uint64
	unmatchedCount atomic.Uint64
}

func NewSyslogIngest(listen string, events chan<- models.SIPEvent) *SyslogIngest {
	return &SyslogIngest{
		listen: listen,
		events: events,
		done:   make(chan struct{}),
	}
}

func (s *SyslogIngest) Run() {
	conn, err := net.ListenPacket("udp", s.listen)
	if err != nil {
		log.Printf("syslog ingest: failed to listen on %s/udp: %v", s.listen, err)
		return
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	defer conn.Close()

	log.Printf("syslog ingest: listening on %s/udp", s.listen)
	buf := make([]byte, 64*1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("syslog ingest: read error: %v", err)
			continue
		}

		line := strings.TrimRight(string(buf[:n]), "\n\r")
		if line == "" {
			continue
		}
		_, evt := ParseLine(line)
		if evt == nil {
			s.unmatchedCount.Add(1)
			continue
		}
		s.matchedCount.Add(1)
		evt.Source = "syslog"
		select {
		case s.events <- *evt:
		case <-s.done:
			return
		}
	}
}

func (s *SyslogIngest) Stop() {
	s.once.Do(func() {
		close(s.done)
		s.mu.Lock()
		if s.conn != nil {
			_ = s.conn.Close()
		}
		s.mu.Unlock()
	})
}

func (s *SyslogIngest) Stats() (matched, unmatched uint64) {
	return s.matchedCount.Load(), s.unmatchedCount.Load()
}
