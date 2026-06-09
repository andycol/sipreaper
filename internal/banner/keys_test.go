package banner

import (
	"net"
	"testing"
)

// TestV4KeyByteLayout pins the contract that the userspace key is the four raw
// wire bytes in network order with NO swap — the same bytes the XDP program
// reads from iphdr.saddr. A self-consistent helper could be wrong in both
// directions; here we assert the literal bytes.
func TestV4KeyByteLayout(t *testing.T) {
	k, ok := v4Key(net.ParseIP("1.2.3.4"))
	if !ok {
		t.Fatal("v4Key returned ok=false for 1.2.3.4")
	}
	want := [4]byte{1, 2, 3, 4}
	if k != want {
		t.Fatalf("v4Key(1.2.3.4) = %v, want %v", k, want)
	}
}

func TestV4KeyRejectsV6(t *testing.T) {
	if _, ok := v4Key(net.ParseIP("2001:db8::1")); ok {
		t.Fatal("v4Key accepted an IPv6 address")
	}
}

func TestV6KeyByteLayout(t *testing.T) {
	k, ok := v6Key(net.ParseIP("2001:db8::1"))
	if !ok {
		t.Fatal("v6Key returned ok=false for 2001:db8::1")
	}
	want := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if k != want {
		t.Fatalf("v6Key(2001:db8::1) = %v, want %v", k, want)
	}
}

// TestV6KeyRejectsV4 ensures IPv4 addresses (whose To16 yields a v4-mapped
// form) are not routed to the v6 map.
func TestV6KeyRejectsV4(t *testing.T) {
	if _, ok := v6Key(net.ParseIP("1.2.3.4")); ok {
		t.Fatal("v6Key accepted an IPv4 address")
	}
}

// TestRoundTrip confirms String() of the bytes we store reproduces the input —
// the same round-trip List() relies on for reconcile.
func TestV4KeyRoundTrip(t *testing.T) {
	in := net.ParseIP("203.0.113.7")
	k, _ := v4Key(in)
	got := net.IP(k[:]).String()
	if got != "203.0.113.7" {
		t.Fatalf("round-trip = %s, want 203.0.113.7", got)
	}
}
