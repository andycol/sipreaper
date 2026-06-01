// SPDX-License-Identifier: GPL-2.0
//
// xdp_ban.c — sipreaper's kernel-fastpath source-IP drop program.
//
// Contract (see docs/plans/xdp-enforcer.md, "Safety Invariants"):
//   * The program ONLY ever returns XDP_PASS or XDP_DROP. No redirect, no
//     packet mutation, no tail calls, no L4 dereference.
//   * It FAILS OPEN: any source IP not present in a ban map, any non-IP
//     EtherType, any VLAN nesting deeper than VLAN_MAX_DEPTH, and any
//     bounds-check failure all return XDP_PASS. A map miss must never drop
//     legitimate traffic.
//   * The v4 ban map is keyed by the four raw wire bytes of iphdr.saddr, and
//     the Go side stores ip.To4() — the same four bytes. There is therefore
//     ZERO byte-order conversion on either side (eliminates the classic XDP
//     endianness bug).
//
// We touch only ABI-stable packet-header fields (ethhdr.h_proto,
// iphdr.saddr, ipv6hdr.saddr), so plain kernel UAPI headers are used rather
// than a vmlinux.h/CO-RE setup. The source IP lives in the fixed L3 header of
// every IPv4 fragment and in the base header of every IPv6 packet, so no
// reassembly is required — SEC("xdp.frags") only lets the program load on
// multi-buffer drivers; we read the linear head exclusively.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#define VLAN_MAX_DEPTH 2
#define MAX_BANS (1 << 20) /* 1,048,576 entries per family */

/* stats array indices — kept in sync with the Go side (statsPassed/Dropped). */
#define STAT_PASSED 0
#define STAT_DROPPED 1

/* 16-byte key for the IPv6 ban map. -type in6_key makes bpf2go emit a Go
 * struct (bpfIn6Key) with a matching [16]byte field. */
struct in6_key {
	__u8 addr[16];
};

/* 802.1Q / 802.1ad tag — only the EtherType after the tag matters to us. */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* banned_v4: exact-match on the 4 raw wire bytes of the source address.
 * Keyed by __u8[4] precisely so there is no htonl()/NativeEndian anywhere. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u8[4]);
	__type(value, __u8);
	__uint(max_entries, MAX_BANS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} banned_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct in6_key);
	__type(value, __u8);
	__uint(max_entries, MAX_BANS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} banned_v6 SEC(".maps");

/* stats: per-CPU array so the per-packet increment is lock-free. The Go side
 * sums across CPUs on scrape. PERCPU is correct HERE (a counter); it would be
 * wrong for the ban maps (which must be visible from any CPU). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
} stats SEC(".maps");

/* schema_version: a single __u32 layout stamp written at load. On a startup
 * mismatch the daemon unlinks the pins and recreates them rather than failing
 * into an unenforced state. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} schema_version SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&stats, &idx);
	if (c)
		(*c)++;
}

SEC("xdp.frags")
int xdp_ban_func(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS; /* runt frame — fail open */

	__u16 proto = eth->h_proto;
	void *cur = (void *)(eth + 1);

	/* Walk up to VLAN_MAX_DEPTH stacked VLAN tags, RE-READING the inner
	 * EtherType each hop. A banned host on a trunk port would otherwise
	 * bypass the filter because the outer EtherType is 802.1Q, not IP.
	 * QinQ deeper than VLAN_MAX_DEPTH -> fall through to XDP_PASS (a
	 * documented fail-open gap). The bounded loop keeps the verifier happy. */
#pragma unroll
	for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) &&
		    proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_hdr *vh = cur;
		if ((void *)(vh + 1) > data_end)
			return XDP_PASS;
		proto = vh->h_vlan_encapsulated_proto;
		cur = (void *)(vh + 1);
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = cur;
		if ((void *)(ip + 1) > data_end)
			return XDP_PASS;
		/* &ip->saddr is 4 wire bytes; the Go side keys by ip.To4(). */
		__u8 *hit = bpf_map_lookup_elem(&banned_v4, &ip->saddr);
		if (hit) {
			stat_inc(STAT_DROPPED);
			return XDP_DROP;
		}
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = cur;
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;
		struct in6_key k6;
		__builtin_memcpy(k6.addr, &ip6->saddr, sizeof(k6.addr));
		__u8 *hit = bpf_map_lookup_elem(&banned_v6, &k6);
		if (hit) {
			stat_inc(STAT_DROPPED);
			return XDP_DROP;
		}
	}

	stat_inc(STAT_PASSED);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
