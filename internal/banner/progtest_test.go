//go:build linux

package banner

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad test IP %q", s)
	}
	return ip
}

// XDP return codes (see uapi/linux/bpf.h).
const (
	xdpAborted = 0
	xdpDrop    = 1
	xdpPass    = 2
)

// loadForTest loads the committed objects with NO pinning (so tests never
// touch /sys/fs/bpf), skipping the whole test when we lack the privileges or
// kernel support to load eBPF.
func loadForTest(t *testing.T) *bpfObjects {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock (need privileges): %v", err)
	}
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("eBPF not supported here: %v", err)
		}
		t.Skipf("cannot load objects (need root/BTF): %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

func runXDP(t *testing.T, objs *bpfObjects, frame []byte) uint32 {
	t.Helper()
	ret, err := objs.XdpBanFunc.Run(ebpf.RunOptions{Data: frame})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	return ret
}

// --- frame builders -------------------------------------------------------

func ethIPv4(src [4]byte) []byte {
	f := make([]byte, 14+20)
	// eth: dst, src, ethertype
	binary.BigEndian.PutUint16(f[12:14], 0x0800) // ETH_P_IP
	// minimal IPv4 header; version/IHL then saddr at offset 12 of the L3 header
	f[14] = 0x45 // version 4, IHL 5
	f[14+9] = 17 // proto UDP (not dereferenced by the program)
	copy(f[14+12:14+16], src[:])
	return f
}

func ethVLANIPv4(src [4]byte, depth int) []byte {
	hdr := 14 + depth*4 + 20
	f := make([]byte, hdr)
	binary.BigEndian.PutUint16(f[12:14], 0x8100) // first tag
	off := 14
	for i := 0; i < depth; i++ {
		// TCI (2 bytes) then inner ethertype (2 bytes)
		next := uint16(0x8100)
		if i == depth-1 {
			next = 0x0800 // last tag -> IPv4
		}
		binary.BigEndian.PutUint16(f[off+2:off+4], next)
		off += 4
	}
	f[off] = 0x45
	copy(f[off+12:off+16], src[:])
	return f
}

func ethIPv6(src [16]byte) []byte {
	f := make([]byte, 14+40)
	binary.BigEndian.PutUint16(f[12:14], 0x86DD) // ETH_P_IPV6
	f[14] = 0x60                                 // version 6
	copy(f[14+8:14+24], src[:])                  // src addr at offset 8 of v6 header
	return f
}

// --- tests ----------------------------------------------------------------

// TestClassification is the primary correctness gate for the verifier-sensitive
// VLAN/bounds parsing: it exercises every PASS/DROP branch.
func TestClassification(t *testing.T) {
	objs := loadForTest(t)
	banned := [4]byte{198, 18, 0, 5}
	if err := objs.BannedV4.Put(banned, uint8(1)); err != nil {
		t.Fatalf("seed banned_v4: %v", err)
	}

	cases := []struct {
		name  string
		frame []byte
		want  uint32
	}{
		{"banned v4 -> DROP", ethIPv4(banned), xdpDrop},
		{"non-banned v4 -> PASS", ethIPv4([4]byte{8, 8, 8, 8}), xdpPass},
		{"VLAN(1) banned -> DROP", ethVLANIPv4(banned, 1), xdpDrop},
		{"QinQ(2) banned -> DROP", ethVLANIPv4(banned, 2), xdpDrop},
		{"QinQ(3) banned -> PASS (documented gap)", ethVLANIPv4(banned, 3), xdpPass},
		{"non-IP EtherType -> PASS", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x06 /*ARP*/}, xdpPass},
		{"truncated frame -> PASS", []byte{0, 1, 2, 3}, xdpPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runXDP(t, objs, tc.frame)
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestClassificationV6(t *testing.T) {
	objs := loadForTest(t)
	banned := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66}
	if err := objs.BannedV6.Put(bpfIn6Key{Addr: banned}, uint8(1)); err != nil {
		t.Fatalf("seed banned_v6: %v", err)
	}
	if got := runXDP(t, objs, ethIPv6(banned)); got != xdpDrop {
		t.Fatalf("banned v6 got %d, want DROP", got)
	}
	other := banned
	other[15] = 0x67
	if got := runXDP(t, objs, ethIPv6(other)); got != xdpPass {
		t.Fatalf("non-banned v6 got %d, want PASS", got)
	}
}

// TestBanRoundTrip proves the userspace key bytes ACTUALLY match what the
// program looks up: ban via the public API, then test-run a frame from that
// source and require XDP_DROP. A self-consistent byte helper would pass while
// being wrong; this catches it (M1 acceptance).
func TestBanRoundTrip(t *testing.T) {
	objs := loadForTest(t)
	e := &XdpEnforcer{objs: *objs}
	ip := mustIP(t, "203.0.113.9")
	if err := e.Ban(ip, 0, "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	src := [4]byte{203, 0, 113, 9}
	if got := runXDP(t, objs, ethIPv4(src)); got != xdpDrop {
		t.Fatalf("after Ban, frame got %d, want DROP", got)
	}
	if err := e.Unban(ip); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if got := runXDP(t, objs, ethIPv4(src)); got != xdpPass {
		t.Fatalf("after Unban, frame got %d, want PASS", got)
	}
}

func TestListReflectsMap(t *testing.T) {
	objs := loadForTest(t)
	e := &XdpEnforcer{objs: *objs}
	if err := e.Ban(mustIP(t, "192.0.2.1"), 0, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.Ban(mustIP(t, "192.0.2.2"), 0, ""); err != nil {
		t.Fatal(err)
	}
	entries, err := e.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(entries))
	}
}
