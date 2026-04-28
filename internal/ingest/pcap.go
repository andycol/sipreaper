package ingest

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andycol/sipreaper/internal/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// inflightMaxEntries caps the Call-ID → request map. A scanner that uses a
// fresh Call-ID per probe could otherwise grow this without bound until the
// 5-minute prune runs. ~200 bytes/entry × 100k = ~20MB worst case before
// overflow eviction kicks in.
const inflightMaxEntries = 100_000

type PcapCapture struct {
	iface  string
	ports  []int
	filter string
	events chan<- models.SIPEvent
	done   chan struct{}

	// inflight maps Call-ID → original request metadata so when we observe
	// the SIP server's 4xx response we can attribute the rejection back to
	// the original sender (the response packet's destination, not source).
	inflight   map[string]requestRecord
	inflightMu sync.Mutex
}

type requestRecord struct {
	srcIP     net.IP
	method    string
	userAgent string
	fromUser  string
	toUser    string
	seen      time.Time
}

func NewPcapCapture(iface string, ports []int, customFilter string, events chan<- models.SIPEvent) *PcapCapture {
	pc := &PcapCapture{
		iface:    iface,
		ports:    ports,
		filter:   buildBPFFilter(ports, customFilter),
		events:   events,
		done:     make(chan struct{}),
		inflight: make(map[string]requestRecord),
	}
	go pc.pruneInflight()
	return pc
}

// evictOldestInflightLocked removes up to n oldest entries. Must be called
// with inflightMu held. We don't keep an LRU list; under overflow we sort
// once and drop the oldest n. O(map log map) but only runs at overflow.
func (pc *PcapCapture) evictOldestInflightLocked(n int) {
	if n <= 0 || len(pc.inflight) == 0 {
		return
	}
	type aged struct {
		k string
		t time.Time
	}
	all := make([]aged, 0, len(pc.inflight))
	for k, v := range pc.inflight {
		all = append(all, aged{k, v.seen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	if n > len(all) {
		n = len(all)
	}
	for i := 0; i < n; i++ {
		delete(pc.inflight, all[i].k)
	}
}

// pruneInflight expires Call-ID records we never matched a response to. SIP
// transactions usually finish in under a minute; 5 minutes is generous and
// prevents unbounded growth on busy hosts.
func (pc *PcapCapture) pruneInflight() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-pc.done:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-5 * time.Minute)
			pc.inflightMu.Lock()
			for k, v := range pc.inflight {
				if v.seen.Before(cutoff) {
					delete(pc.inflight, k)
				}
			}
			pc.inflightMu.Unlock()
		}
	}
}

func (pc *PcapCapture) Run() error {
	handle, err := pcap.OpenLive(pc.iface, 65535, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("opening pcap on %s: %w", pc.iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(pc.filter); err != nil {
		return fmt.Errorf("setting BPF filter: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-pc.done:
			return nil
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}
			pc.processPacket(packet)
		}
	}
}

func (pc *PcapCapture) Stop() {
	close(pc.done)
}

func (pc *PcapCapture) processPacket(packet gopacket.Packet) {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}

	msg, err := ParseSIPMessage(appLayer.Payload())
	if err != nil {
		return
	}

	var srcIP, dstIP net.IP
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		l := ipLayer.(*layers.IPv4)
		srcIP, dstIP = l.SrcIP, l.DstIP
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		l := ipLayer.(*layers.IPv6)
		srcIP, dstIP = l.SrcIP, l.DstIP
	}
	if srcIP == nil {
		return
	}

	pc.handleSIP(srcIP, dstIP, msg)
}

// handleSIP performs the request/response pairing and event emission. Split
// out from processPacket so it can be unit-tested without constructing
// gopacket layers.
func (pc *PcapCapture) handleSIP(srcIP, dstIP net.IP, msg *SIPMessage) {
	// Requests: emit normally and stash the request keyed by Call-ID so we
	// can attribute future responses.
	if !msg.IsResponse {
		if msg.CallID != "" {
			pc.inflightMu.Lock()
			if len(pc.inflight) >= inflightMaxEntries {
				pc.evictOldestInflightLocked(inflightMaxEntries / 10)
			}
			pc.inflight[msg.CallID] = requestRecord{
				srcIP: srcIP, method: msg.Method, userAgent: msg.UserAgent,
				fromUser: msg.FromUser, toUser: msg.ToUser, seen: time.Now(),
			}
			pc.inflightMu.Unlock()
		}

		evt := models.SIPEvent{
			Timestamp: time.Now(), SourceIP: srcIP, Method: msg.Method,
			UserAgent: msg.UserAgent, FromUser: msg.FromUser, ToUser: msg.ToUser,
			CallID: msg.CallID, ResponseCode: msg.ResponseCode, Source: "pcap",
		}
		pc.send(evt)
		return
	}

	// Responses: look up the original request and emit a synthesized event
	// attributed to the *original* sender (not the response's source, which
	// is our own SIP server).
	originIP := dstIP
	method := msg.Method
	userAgent := ""
	fromUser, toUser := "", ""
	if msg.CallID != "" {
		pc.inflightMu.Lock()
		if rec, ok := pc.inflight[msg.CallID]; ok {
			originIP = rec.srcIP
			if method == "" {
				method = rec.method
			}
			userAgent = rec.userAgent
			fromUser = rec.fromUser
			toUser = rec.toUser
			// Keep the record around briefly — final responses can be retransmitted.
		}
		pc.inflightMu.Unlock()
	}
	if originIP == nil {
		return
	}

	rejected := msg.ResponseCode >= 400 && msg.ResponseCode < 600
	reason := ""
	if rejected {
		reason = fmt.Sprintf("sip server returned %d", msg.ResponseCode)
	}

	evt := models.SIPEvent{
		Timestamp: time.Now(), SourceIP: originIP, Method: method,
		UserAgent: userAgent, FromUser: fromUser, ToUser: toUser,
		CallID: msg.CallID, ResponseCode: msg.ResponseCode, Source: "pcap",
		Rejected: rejected, RejectReason: reason,
	}
	pc.send(evt)
}

func (pc *PcapCapture) send(evt models.SIPEvent) {
	select {
	case pc.events <- evt:
	default:
		log.Println("pcap: event channel full, dropping packet")
	}
}

func buildBPFFilter(ports []int, custom string) string {
	if custom != "" {
		return custom
	}

	var parts []string
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("udp port %d", p))
	}
	return strings.Join(parts, " or ")
}
