package action

import (
	"fmt"
	"os/exec"
	"strconv"
)

// PreFilter installs a hashlimit-based per-source-IP rate limit on INVITE
// traffic before it reaches OpenSIPS / Kamailio. Anything above the rate is
// dropped at the kernel firewall — the userspace pipeline never sees it. This
// is the cheapest possible stop-gap against volumetric INVITE floods. It does
// NOT replace the userspace detector (which can ban repeat offenders); it just
// keeps the box upright while the detector decides.
type PreFilter struct {
	chain   string
	rate    int
	burst   int
	ports   []int
	tableID string
}

func NewPreFilter(chain string, rate, burst int, ports []int) *PreFilter {
	return &PreFilter{
		chain:   chain,
		rate:    rate,
		burst:   burst,
		ports:   ports,
		tableID: "sipreaper-invite",
	}
}

// Apply installs the hashlimit rules. Idempotent: if rules with matching
// parameters already exist, it leaves them alone.
func (p *PreFilter) Apply() error {
	if p.rate < 1 || p.burst < 1 {
		return fmt.Errorf("invalid prefilter rate=%d burst=%d", p.rate, p.burst)
	}
	if len(p.ports) == 0 {
		return fmt.Errorf("prefilter: no ports configured")
	}

	for _, port := range p.ports {
		// "INVITE sip:" is the most reliable string — it appears at the start
		// of every INVITE request line. We use --algo bm with --to 100 so the
		// kernel only inspects the first 100 bytes (the request line).
		args := []string{
			"-I", p.chain, "1",
			"-p", "udp", "--dport", strconv.Itoa(port),
			"-m", "string", "--algo", "bm", "--string", "INVITE sip:", "--to", "100",
			"-m", "hashlimit",
			"--hashlimit-mode", "srcip",
			"--hashlimit-name", p.tableID + "-" + strconv.Itoa(port),
			"--hashlimit-above", fmt.Sprintf("%d/sec", p.rate),
			"--hashlimit-burst", strconv.Itoa(p.burst),
			"-j", "DROP",
		}

		// Idempotent install: -C with the same args, skip if it exists.
		check := append([]string{"-C", p.chain}, args[2:]...)
		if err := exec.Command("iptables", check...).Run(); err == nil {
			continue
		}
		if err := exec.Command("iptables", args...).Run(); err != nil {
			return fmt.Errorf("installing prefilter rule on port %d: %w", port, err)
		}
	}
	return nil
}
