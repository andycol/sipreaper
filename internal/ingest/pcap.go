package ingest

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// rejectMatcher decides which responses mean "the SIP server refused this
// source" (→ SIPEvent.Rejected, which server_rejected bans on). Ordinary call
// outcomes — 404, 480, 486, 487, 503, 603… — and digest challenges (401/407)
// happen on every healthy system and must never be listed.
type rejectMatcher struct {
	codes   map[int]bool            // code alone matches any phrase
	phrases map[int]map[string]bool // code → lower-cased reason phrases
}

// newRejectMatcher parses entries of the form "403" or "403 Forbidden".
// Entries are validated by config; anything unparsable is skipped.
func newRejectMatcher(entries []string) rejectMatcher {
	m := rejectMatcher{codes: map[int]bool{}, phrases: map[int]map[string]bool{}}
	for _, e := range entries {
		fields := strings.SplitN(strings.TrimSpace(e), " ", 2)
		code, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		if len(fields) == 1 || strings.TrimSpace(fields[1]) == "" {
			m.codes[code] = true
			continue
		}
		if m.phrases[code] == nil {
			m.phrases[code] = map[string]bool{}
		}
		m.phrases[code][strings.ToLower(strings.TrimSpace(fields[1]))] = true
	}
	return m
}

func (m rejectMatcher) match(code int, reason string) bool {
	return m.codes[code] || m.phrases[code][strings.ToLower(reason)]
}

type PcapCapture struct {
	iface  string
	ports  []int
	filter string
	events chan<- models.SIPEvent
	done   chan struct{}

	// isLocal reports whether an IP belongs to this host. Packets the SIP
	// server itself sends (requests it forwards to carriers, OPTIONS pings to
	// phones) and responses it receives to those requests are not evidence
	// about any remote sender, so they are ignored. nil = nothing is local.
	isLocal func(net.IP) bool

	rejects rejectMatcher

	// inflight maps Call-ID+sender → original request metadata so when we
	// observe the SIP server's response we can enrich it (UA, users, whether
	// credentials were sent). Keyed by sender too because a proxy reuses the
	// same Call-ID on both legs of a call.
	inflight   map[string]requestRecord
	inflightMu sync.Mutex

	// Diagnostic counters — atomic so we can read without locking.
	pktsReceived  uint64
	pktsNoAppLyr  uint64
	pktsParseFail uint64
}

type requestRecord struct {
	srcIP     net.IP
	method    string
	userAgent string
	fromUser  string
	toUser    string
	hasAuth   bool
	seen      time.Time
}

func inflightKey(callID string, sender net.IP) string {
	return callID + "|" + sender.String()
}

func NewPcapCapture(iface string, ports []int, customFilter string, rejectResponses []string, isLocal func(net.IP) bool, events chan<- models.SIPEvent) *PcapCapture {
	pc := &PcapCapture{
		iface:    iface,
		ports:    ports,
		filter:   buildBPFFilter(ports, customFilter),
		events:   events,
		isLocal:  isLocal,
		rejects:  newRejectMatcher(rejectResponses),
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

func (pc *PcapCapture) Run() (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("pcap: PANIC in Run: %v (recovered)", r)
			retErr = fmt.Errorf("pcap panic: %v", r)
		}
	}()

	handle, err := pcap.OpenLive(pc.iface, 65535, false, pcap.BlockForever)
	if err != nil {
		log.Printf("pcap: OpenLive failed on %s: %v", pc.iface, err)
		return fmt.Errorf("opening pcap on %s: %w", pc.iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(pc.filter); err != nil {
		log.Printf("pcap: SetBPFFilter failed (filter=%q): %v", pc.filter, err)
		return fmt.Errorf("setting BPF filter: %w", err)
	}

	log.Printf("pcap: capture loop entered iface=%s linktype=%s filter=%q", pc.iface, handle.LinkType(), pc.filter)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Heartbeat so we can tell if packets are arriving at all.
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-pc.done:
			log.Printf("pcap: Run exiting on done signal (recv=%d noapp=%d parsefail=%d)",
				atomic.LoadUint64(&pc.pktsReceived),
				atomic.LoadUint64(&pc.pktsNoAppLyr),
				atomic.LoadUint64(&pc.pktsParseFail))
			return nil
		case <-heartbeat.C:
			log.Printf("pcap: heartbeat recv=%d noapp=%d parsefail=%d",
				atomic.LoadUint64(&pc.pktsReceived),
				atomic.LoadUint64(&pc.pktsNoAppLyr),
				atomic.LoadUint64(&pc.pktsParseFail))
		case packet, ok := <-packetSource.Packets():
			if !ok {
				log.Printf("pcap: Run exiting — packet source channel CLOSED (recv=%d). This usually means libpcap returned an error mid-read.",
					atomic.LoadUint64(&pc.pktsReceived))
				return nil
			}
			atomic.AddUint64(&pc.pktsReceived, 1)
			pc.processPacket(packet)
		}
	}
}

func (pc *PcapCapture) Stop() {
	close(pc.done)
}

func (pc *PcapCapture) processPacket(packet gopacket.Packet) {
	// Use the transport-layer payload (everything after the UDP header) rather
	// than ApplicationLayer().Payload(). gopacket's built-in layers.SIP decoder
	// auto-fires on UDP/5060 and UDP/5061 and consumes the headers into struct
	// fields, leaving Payload() pointing at only the message body. For
	// header-only SIP messages (REGISTER, 401, OPTIONS) the body is empty, so
	// ParseSIPMessage would reject every packet.
	transport := packet.TransportLayer()
	if transport == nil {
		atomic.AddUint64(&pc.pktsNoAppLyr, 1)
		return
	}
	payload := transport.LayerPayload()
	if len(payload) == 0 {
		atomic.AddUint64(&pc.pktsNoAppLyr, 1)
		return
	}

	msg, err := ParseSIPMessage(payload)
	if err != nil {
		n := atomic.AddUint64(&pc.pktsParseFail, 1)
		if n <= 5 {
			pc.dumpPayload(payload, err)
		}
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
	if !msg.IsResponse {
		// A request from this host is the SIP server's own outbound leg.
		if pc.local(srcIP) {
			return
		}
		// Stash the request so the server's response can be enriched.
		if msg.CallID != "" {
			pc.inflightMu.Lock()
			if len(pc.inflight) >= inflightMaxEntries {
				pc.evictOldestInflightLocked(inflightMaxEntries / 10)
			}
			pc.inflight[inflightKey(msg.CallID, srcIP)] = requestRecord{
				srcIP: srcIP, method: msg.Method, userAgent: msg.UserAgent,
				fromUser: msg.FromUser, toUser: msg.ToUser, hasAuth: msg.HasAuth,
				seen: time.Now(),
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

	// Responses go back to the request's sender (Via/rport), so the packet's
	// destination IS the sender we attribute the outcome to. A response
	// addressed to this host answers a request the server sent itself (e.g. a
	// carrier's 486) and says nothing about a remote attacker.
	originIP := dstIP
	if originIP == nil || pc.local(originIP) {
		return
	}

	method := msg.Method
	userAgent := ""
	fromUser, toUser := "", ""
	var rec requestRecord
	found := false
	if msg.CallID != "" {
		pc.inflightMu.Lock()
		rec, found = pc.inflight[inflightKey(msg.CallID, originIP)]
		// Keep the record around briefly — final responses can be retransmitted.
		pc.inflightMu.Unlock()
	}
	if found {
		if method == "" {
			method = rec.method
		}
		userAgent = rec.userAgent
		fromUser = rec.fromUser
		toUser = rec.toUser
	}

	// 401/407 to a request without credentials is the normal digest
	// challenge every phone gets on every REGISTER/INVITE. Only a challenge
	// to a request that already carried credentials is a failed login. If we
	// never saw the request we can't tell, so assume challenge (don't ban).
	if (msg.ResponseCode == 401 || msg.ResponseCode == 407) && !(found && rec.hasAuth) {
		return
	}

	rejected := pc.rejects.match(msg.ResponseCode, msg.Reason)
	reason := ""
	if rejected {
		reason = strings.TrimSpace(fmt.Sprintf("sip server returned %d %s", msg.ResponseCode, msg.Reason))
	}

	evt := models.SIPEvent{
		Timestamp: time.Now(), SourceIP: originIP, Method: method,
		UserAgent: userAgent, FromUser: fromUser, ToUser: toUser,
		CallID: msg.CallID, ResponseCode: msg.ResponseCode, Source: "pcap",
		IsResponse: true, Rejected: rejected, RejectReason: reason,
	}
	pc.send(evt)
}

func (pc *PcapCapture) local(ip net.IP) bool {
	return pc.isLocal != nil && pc.isLocal(ip)
}

func (pc *PcapCapture) send(evt models.SIPEvent) {
	select {
	case pc.events <- evt:
	default:
		log.Println("pcap: event channel full, dropping packet")
	}
}

// dumpPayload prints a hex+ascii preview of a payload that ParseSIPMessage
// rejected. Used only for diagnostics — capped to the first 5 failures.
func (pc *PcapCapture) dumpPayload(p []byte, parseErr error) {
	const max = 200
	n := len(p)
	if n > max {
		n = max
	}
	prev := p[:n]

	var hex strings.Builder
	var ascii strings.Builder
	for _, b := range prev {
		fmt.Fprintf(&hex, "%02x ", b)
		if b >= 0x20 && b <= 0x7e {
			ascii.WriteByte(b)
		} else {
			ascii.WriteByte('.')
		}
	}
	log.Printf("pcap: PARSE FAIL (#%d) len=%d err=%q ascii=%q hex=%s",
		atomic.LoadUint64(&pc.pktsParseFail), len(p), parseErr.Error(), ascii.String(), hex.String())
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
