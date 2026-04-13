package ingest

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/andycol/sipreaper/internal/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PcapCapture struct {
	iface  string
	ports  []int
	filter string
	events chan<- models.SIPEvent
	done   chan struct{}
}

func NewPcapCapture(iface string, ports []int, customFilter string, events chan<- models.SIPEvent) *PcapCapture {
	return &PcapCapture{
		iface:  iface,
		ports:  ports,
		filter: buildBPFFilter(ports, customFilter),
		events: events,
		done:   make(chan struct{}),
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

	var srcIP net.IP
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		srcIP = ipLayer.(*layers.IPv4).SrcIP
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		srcIP = ipLayer.(*layers.IPv6).SrcIP
	}
	if srcIP == nil {
		return
	}

	evt := models.SIPEvent{
		Timestamp:    time.Now(),
		SourceIP:     srcIP,
		Method:       msg.Method,
		UserAgent:    msg.UserAgent,
		FromUser:     msg.FromUser,
		ToUser:       msg.ToUser,
		CallID:       msg.CallID,
		ResponseCode: msg.ResponseCode,
		Source:       "pcap",
	}

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
