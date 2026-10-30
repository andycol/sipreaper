package action

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// iptablesCmd runs iptables with -w so a concurrent caller holding the xtables
// lock (fail2ban, firewalld, an admin) makes us wait rather than fail outright
// and silently leave a ban unapplied or a rule un-removed.
func iptablesCmd(args ...string) *exec.Cmd {
	return exec.Command("iptables", append([]string{"-w", "10"}, args...)...)
}

type IPTablesEnforcer struct {
	chain string
}

func NewIPTablesEnforcer(chain string) *IPTablesEnforcer {
	return &IPTablesEnforcer{chain: chain}
}

func (e *IPTablesEnforcer) Name() string { return "iptables" }

func (e *IPTablesEnforcer) Init() error {
	// Create chain if it doesn't exist
	iptablesCmd("-N", e.chain).Run()

	// Ensure chain is linked from INPUT
	if err := iptablesCmd("-C", "INPUT", "-j", e.chain).Run(); err != nil {
		if err := iptablesCmd("-I", "INPUT", "-j", e.chain).Run(); err != nil {
			return fmt.Errorf("linking chain %s to INPUT: %w", e.chain, err)
		}
	}
	return nil
}

func (e *IPTablesEnforcer) Ban(ip net.IP, duration time.Duration, reason string) error {
	checkArgs := e.checkArgs(ip)
	if err := iptablesCmd(checkArgs...).Run(); err == nil {
		return nil
	}

	args := e.banArgs(ip)
	if err := iptablesCmd(args...).Run(); err != nil {
		return fmt.Errorf("iptables ban %s: %w", ip, err)
	}
	return nil
}

func (e *IPTablesEnforcer) Unban(ip net.IP) error {
	checkArgs := e.checkArgs(ip)
	for removed := 0; removed < 10000; removed++ {
		if err := iptablesCmd(checkArgs...).Run(); err != nil {
			return nil
		}

		args := e.unbanArgs(ip)
		if err := iptablesCmd(args...).Run(); err != nil {
			if checkErr := iptablesCmd(checkArgs...).Run(); checkErr != nil {
				return nil
			}
			return fmt.Errorf("iptables unban %s: %w", ip, err)
		}
	}
	return fmt.Errorf("iptables unban %s: exceeded duplicate removal limit", ip)
}

func (e *IPTablesEnforcer) List() ([]BanEntry, error) {
	out, err := iptablesCmd("-L", e.chain, "-n", "--line-numbers").Output()
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
