//go:build linux && xdp

package banner

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// minKernelMajor / minKernelMinor is the floor for bpf_link-based XDP
// attachment (5.7). CAP_BPF arrives at 5.8, but that is a deployment concern
// (capabilities), not a load gate.
const (
	minKernelMajor = 5
	minKernelMinor = 7
)

// Preflight runs the cheap, non-mutating host checks the daemon does at startup
// before it even constructs the enforcer. It returns "" when XDP looks usable,
// or a short human-readable reason when it does not — the daemon logs the
// reason and stays on its base (iptables/ipset) enforcer. It never panics and
// never mutates host state.
func Preflight(iface string) string {
	if ok, rel := kernelAtLeast(minKernelMajor, minKernelMinor); !ok {
		return fmt.Sprintf("kernel %s < %d.%d (need bpf_link XDP)", rel, minKernelMajor, minKernelMinor)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return "kernel BTF (/sys/kernel/btf/vmlinux) absent"
	}
	if !bpffsMounted() {
		return "bpffs not mounted at /sys/fs/bpf"
	}
	if iface == "" {
		return "no interface configured (set enforcer.xdp.interface or ingest.pcap.interface)"
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Sprintf("interface %q not found: %v", iface, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return fmt.Sprintf("interface %q is down", iface)
	}
	return ""
}

// kernelAtLeast parses uname release ("5.15.0-89-generic") and compares against
// the floor. Returns the raw release string for logging.
func kernelAtLeast(major, minor int) (bool, string) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return false, "unknown"
	}
	rel := unix.ByteSliceToString(u.Release[:])
	maj, min := parseKernelVersion(rel)
	if maj > major {
		return true, rel
	}
	if maj == major && min >= minor {
		return true, rel
	}
	return false, rel
}

func parseKernelVersion(rel string) (major, minor int) {
	// Take the leading "X.Y" before any "-" / extra dots.
	rel = strings.SplitN(rel, "-", 2)[0]
	parts := strings.Split(rel, ".")
	if len(parts) >= 1 {
		major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	return
}

// bpffsMounted reports whether /sys/fs/bpf is a bpf filesystem. We statfs it
// and check the magic rather than parsing /proc/mounts.
func bpffsMounted() bool {
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err != nil {
		return false
	}
	return st.Type == unix.BPF_FS_MAGIC
}
