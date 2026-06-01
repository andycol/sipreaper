// Package banner — key conversion helpers shared by the Linux enforcer and its
// tests. These have NO build tag on purpose: the byte-layout contract (the Go
// userspace must produce exactly the bytes the kernel program keys on) is
// verifiable on every platform, including darwin dev machines, even though the
// enforcer itself only builds on Linux.
package banner

import "net"

// v4Key returns the four raw wire bytes of an IPv4 address — precisely the key
// the XDP program looks up in banned_v4. There is deliberately no byte-order
// conversion: storing ip.To4() and looking up &iphdr.saddr compare identical
// bytes. ok is false for anything that is not an IPv4 address.
func v4Key(ip net.IP) (k [4]byte, ok bool) {
	v4 := ip.To4()
	if v4 == nil {
		return k, false
	}
	copy(k[:], v4)
	return k, true
}

// v6Key returns the sixteen bytes of an IPv6 address for banned_v6. It reports
// ok=false for IPv4 addresses (which To16 would otherwise return a v4-mapped
// form for) so callers route v4 and v6 to the right map.
func v6Key(ip net.IP) (k [16]byte, ok bool) {
	if ip.To4() != nil {
		return k, false
	}
	v6 := ip.To16()
	if v6 == nil {
		return k, false
	}
	copy(k[:], v6)
	return k, true
}
