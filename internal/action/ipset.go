package action

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// IPSetEnforcer pushes bans into an ipset hash:net set, then ensures a single
// iptables rule jumps to that set. This is O(1) lookup at the network layer
// regardless of how many IPs are banned — the iptables/chain enforcer adds one
// rule per ban and walks them linearly, which becomes a real cost above a few
// thousand bans.
type IPSetEnforcer struct {
	setName string
	chain   string // iptables chain that the set is wired into
}

func NewIPSetEnforcer(setName, chain string) *IPSetEnforcer {
	if setName == "" {
		setName = "sipreaper"
	}
	if chain == "" {
		chain = "SIPREAPER"
	}
	return &IPSetEnforcer{setName: setName, chain: chain}
}

func (e *IPSetEnforcer) Name() string { return "ipset" }

func (e *IPSetEnforcer) Init() error {
	// Create the set if it doesn't exist. hash:net handles single IPs and
	// CIDRs; timeout=0 means we manage expiry ourselves (the ban-expiry
	// goroutine), keeping a single source of truth.
	if err := exec.Command("ipset", "create", e.setName, "hash:net", "family", "inet", "-exist").Run(); err != nil {
		return fmt.Errorf("ipset create %s: %w", e.setName, err)
	}

	// Make sure the chain exists & is linked from INPUT — same shape as the
	// iptables enforcer for a smooth swap-over.
	exec.Command("iptables", "-N", e.chain).Run()
	if err := exec.Command("iptables", "-C", "INPUT", "-j", e.chain).Run(); err != nil {
		if err := exec.Command("iptables", "-I", "INPUT", "-j", e.chain).Run(); err != nil {
			return fmt.Errorf("linking chain %s to INPUT: %w", e.chain, err)
		}
	}

	// Single match rule: -m set --match-set <name> src -j DROP. Idempotent
	// thanks to -C / -A pattern.
	check := exec.Command("iptables", "-C", e.chain, "-m", "set", "--match-set", e.setName, "src", "-j", "DROP")
	if err := check.Run(); err != nil {
		if err := exec.Command("iptables", "-A", e.chain, "-m", "set", "--match-set", e.setName, "src", "-j", "DROP").Run(); err != nil {
			return fmt.Errorf("adding ipset match rule: %w", err)
		}
	}
	return nil
}

func (e *IPSetEnforcer) Ban(ip net.IP, duration time.Duration, reason string) error {
	if err := exec.Command("ipset", "add", e.setName, ip.String(), "-exist").Run(); err != nil {
		return fmt.Errorf("ipset add %s: %w", ip, err)
	}
	return nil
}

func (e *IPSetEnforcer) Unban(ip net.IP) error {
	if err := exec.Command("ipset", "del", e.setName, ip.String(), "-exist").Run(); err != nil {
		return fmt.Errorf("ipset del %s: %w", ip, err)
	}
	return nil
}

func (e *IPSetEnforcer) List() ([]BanEntry, error) {
	out, err := exec.Command("ipset", "list", e.setName).Output()
	if err != nil {
		return nil, fmt.Errorf("ipset list %s: %w", e.setName, err)
	}

	var entries []BanEntry
	scanner := bufio.NewScanner(bytes.NewReader(out))
	inMembers := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "Members:" {
			inMembers = true
			continue
		}
		if !inMembers || line == "" {
			continue
		}
		entries = append(entries, BanEntry{IP: strings.Fields(line)[0]})
	}
	return entries, scanner.Err()
}
