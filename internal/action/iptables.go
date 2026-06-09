package action

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

type IPTablesEnforcer struct {
	chain string
}

func NewIPTablesEnforcer(chain string) *IPTablesEnforcer {
	return &IPTablesEnforcer{chain: chain}
}

func (e *IPTablesEnforcer) Name() string { return "iptables" }

func (e *IPTablesEnforcer) Init() error {
	// Create chain if it doesn't exist
	exec.Command("iptables", "-N", e.chain).Run()

	// Ensure chain is linked from INPUT
	if err := exec.Command("iptables", "-C", "INPUT", "-j", e.chain).Run(); err != nil {
		if err := exec.Command("iptables", "-I", "INPUT", "-j", e.chain).Run(); err != nil {
			return fmt.Errorf("linking chain %s to INPUT: %w", e.chain, err)
		}
	}
	return nil
}

func (e *IPTablesEnforcer) Ban(ip net.IP, duration time.Duration, reason string) error {
	checkArgs := e.checkArgs(ip)
	if err := exec.Command("iptables", checkArgs...).Run(); err == nil {
		return nil
	}

	args := e.banArgs(ip)
	if err := exec.Command("iptables", args...).Run(); err != nil {
		return fmt.Errorf("iptables ban %s: %w", ip, err)
	}
	return nil
}

func (e *IPTablesEnforcer) Unban(ip net.IP) error {
	checkArgs := e.checkArgs(ip)
	for removed := 0; removed < 10000; removed++ {
		if err := exec.Command("iptables", checkArgs...).Run(); err != nil {
			return nil
		}

		args := e.unbanArgs(ip)
		if err := exec.Command("iptables", args...).Run(); err != nil {
			if checkErr := exec.Command("iptables", checkArgs...).Run(); checkErr != nil {
				return nil
			}
			return fmt.Errorf("iptables unban %s: %w", ip, err)
		}
	}
	return fmt.Errorf("iptables unban %s: exceeded duplicate removal limit", ip)
}

func (e *IPTablesEnforcer) List() ([]BanEntry, error) {
	out, err := exec.Command("iptables", "-L", e.chain, "-n", "--line-numbers").Output()
	if err != nil {
		return nil, fmt.Errorf("listing chain %s: %w", e.chain, err)
	}

	var entries []BanEntry
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[1] == "DROP" {
			entries = append(entries, BanEntry{IP: fields[4]})
		}
	}
	return entries, nil
}

func (e *IPTablesEnforcer) banArgs(ip net.IP) []string {
	return []string{"-A", e.chain, "-s", ip.String(), "-j", "DROP"}
}

func (e *IPTablesEnforcer) checkArgs(ip net.IP) []string {
	return []string{"-C", e.chain, "-s", ip.String(), "-j", "DROP"}
}

func (e *IPTablesEnforcer) unbanArgs(ip net.IP) []string {
	return []string{"-D", e.chain, "-s", ip.String(), "-j", "DROP"}
}
