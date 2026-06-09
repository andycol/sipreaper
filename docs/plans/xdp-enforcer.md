# Implementation Plan: XDP Source-IP Drop Enforcer for `sipreaper`

## Goal & Core Design Decision

Add a kernel-fastpath XDP source-IP drop enforcer so that banned IPs are dropped at the NIC/driver layer (`XDP_DROP`) instead of (or in addition to) the existing netfilter `INPUT` path, eliminating the `%soft` (NET_RX softirq) cost a flood pays today under iptables/ipset. The **core design decision is a composite enforcer**: we keep the existing `IPTablesEnforcer`/`IPSetEnforcer` and add `XdpEnforcer`, both satisfying the unchanged `action.Enforcer` interface (`internal/action/enforcer.go:15-20`). A new `CompositeEnforcer` fans `Ban`/`Unban`/`List` out to both, so rollout is purely **additive** (XDP on top of the proven iptables path). Only after the benchmark proves parity-or-better do we *optionally* let the XDP backend stand alone and retire the redundant per-IP iptables/ipset drop rules.

**Why this is safe by construction:** the XDP program does PASS/DROP only (no modify/redirect/tx), it fails open (any source not in the map → `XDP_PASS`), and it reuses the daemon's existing whitelist↔ban guard so whitelisted IPs can never reach the drop map. The enforcer is driven from the SQLite source-of-truth (`internal/store/store.go`), exactly like the existing backends. **The pinned kernel map is a *second* source of truth, and is reconciled against the DB and whitelist at every startup** (see Phase 3) — the DB always wins.

> **Two known behavioral changes from iptables, called out up front (not bugs — design facts to accept and document):**
> 1. **Detection blindness (M4):** `internal/ingest/pcap.go:121` captures via `pcap.OpenLive` (AF_PACKET/tpacket), which on virtually every driver receives packets *after* the XDP hook. So once an IP is dropped at XDP, sipreaper's own detectors stop seeing it. This means **ban-duration escalation / recidivism counting on an already-banned IP stops** (the engine's `BanCountByIP` escalation can't re-trigger while XDP is dropping). This is acceptable — the IP is already banned — but it is a semantic change vs. some iptables `INPUT` placements, and is why we keep iptables in the composite during rollout (the AF_PACKET tap still observes pre-DROP packets only if the iptables DROP is in `INPUT`, which is after the tap — so detection blindness applies to *both* backends equally once dropping; documented in Phase 7).
> 2. **Mid-stream TCP/TLS teardown (S7):** XDP_DROP on a banned source kills in-flight TCP/TLS (SIP-over-TLS, port 5061) calls abruptly, identical to an iptables DROP. Documented, and 5061/TCP is added to the benchmark.

---

## Prerequisites & host checks

These must hold (or be explicitly handled) before XDP can be enabled. The daemon performs a **programmatic preflight** at startup (Phase 3) and degrades to the base enforcer with an actionable log line if any fail — it never crashes.

| Check | How verified (manual / P0) | Daemon preflight (Phase 3) | If absent |
|---|---|---|---|
| Kernel ≥ 5.7 (`bpf_link` for XDP); ≥ 5.8 for `CAP_BPF` | `uname -r` | Parse `uname` release; log if `< 5.7` | Degrade to base enforcer (warn) |
| BTF present | `ls /sys/kernel/btf/vmlinux` | `os.Stat("/sys/kernel/btf/vmlinux")` | Degrade to base enforcer (warn) |
| bpffs mounted at `/sys/fs/bpf` | `mount \| grep bpf` | Check mount + **write-probe** a temp pin under `pinDir` | Degrade to base enforcer (warn); see M6 |
| SIP-facing NIC identified, up | `ethtool -i <iface>`, `ip -d link show` | `net.InterfaceByName` + flag `FlagUp` check; log chosen iface loudly | Degrade to base enforcer (warn) |
| No conflicting XDP prog already attached | `ip -d link show <iface>` | Distinguish `EBUSY`/`EEXIST` at attach (M7) | Degrade to base enforcer (warn) |
| clang/LLVM ≥ 11 + bpftool **(generate time only)** | `clang --version`, `bpftool version` | n/a (committed `.o` used at runtime) | `make build` still works (object committed) |

**Capabilities (runtime):** `CAP_BPF` + `CAP_NET_ADMIN` (kernel ≥ 5.8); on `< 5.8` add `CAP_SYS_ADMIN` and `CAP_SYS_RESOURCE` (for `RLIMIT_MEMLOCK`/pin). `CAP_NET_RAW` already required for pcap.

---

## Safety Invariants (apply to every phase — non-negotiable)

1. **Fail-open default.** The XDP program returns `XDP_PASS` for any source IP not present in a ban map, any non-IP EtherType, any QinQ depth > 2, and any bounds-check failure. A map miss, load failure, attach failure, **failed preflight, stale/incompatible pin, full map, or panic** must NEVER drop legitimate traffic. If XDP fails for any reason, the daemon logs a warning and continues with the iptables/ipset enforcer (mirrors the existing `Init()` "log warning, don't be fatal" pattern at `daemon.go:310-312,316-318`).
2. **Whitelist IPs never enter the drop map — enforced at *three* producers, not "by construction".** Bans reach the enforcer from (a) `decision.Engine.Evaluate` (returns `nil` for whitelisted IPs, `internal/decision/engine.go:41-45`), (b) the manual ban API (refuses whitelisted IPs, `internal/api/handlers.go:57-60`), and (c) **`restoreBans` at startup, which today has NO whitelist check** (`daemon.go:508-525`). Phase 3 adds an explicit `whitelist.Contains` skip to `restoreBans` (M3) and a **startup reconcile** that deletes from the XDP map any entry that is whitelisted or not in `ListBans("active")` (M2). The atomic unban-on-whitelist path (`handlers.go:160-182`, wired via `srv.SetUnbanFunc(...)` at `daemon.go:172-174`) calls the composite `Unban`, evicting the IP from the map too.
3. **PASS/DROP only.** No `bpf_redirect`, `bpf_xdp_adjust_*`, tail calls, or any mutating helper. No L4 deref. Verifier-visible read-only header parsing only.
4. **Explicit native→generic mode selection with conflict-aware fallback.** Attach in driver mode first; on `EOPNOTSUPP`/`ENOTSUP` fall back to generic; on `EBUSY`/`EEXIST` (another prog attached) do **not** retry — fail open with a specific log. On any final failure, keep iptables. Mode is overridable from config.
5. **Dry-run is honored.** The composite is only invoked when `!d.engine.DryRun()` (`daemon.go:430`); `Status="dry_run"` rows never reach the map, and expiry skips them (`daemon.go:485`).
6. **DB is authoritative; the map is reconciled to it.** On every startup, before re-applying bans, the daemon reconciles the pinned map against `ListBans("active")` ∖ whitelist. On spec-mismatch of a pinned map (schema bump), the daemon **unlinks and recreates** the pin rather than failing into an unenforced state (M5).

---

## PHASE 0 — Spike / feasibility on the target host

**Objective:** Before writing product code, empirically determine on the *actual* SUT NIC whether native (driver) XDP works or we are limited to generic (SKB) mode — this changes benchmark expectations (generic XDP runs after the same RX softirq alloc + after GRO, so the `%soft` win is smaller) and the default config value we ship.

**Tasks**
- Identify the SIP-facing NIC and driver: `ethtool -i <iface>`, `ip -d link show <iface>`. Record driver name + version.
- Confirm kernel ≥ 5.7 (≥ 5.8 for `CAP_BPF`): `uname -r`.
- Confirm bpffs at `/sys/fs/bpf`: `mount | grep bpf` (mount if absent: `mount -t bpf bpf /sys/fs/bpf`).
- Attach a throwaway "drop nothing / count packets" XDP program (upstream `cilium/ebpf` `examples/xdp` or a 10-line scratch program) in driver mode; if it errors with native-unsupported, retry generic. Record which succeeded.
- **Explicitly test the "XDP program already attached" path:** attach twice / attach with another prog present, confirm we get `EBUSY`/`EEXIST` and record the errno (drives M7 logic).
- Record multi-buffer/jumbo status (`ip link show` MTU), **GRO/LRO and RSS/queue count** (`ethtool -k`, `ethtool -l`, `ethtool -x`) — these are pinned identically across all benchmark cells (S3) and inform the `SEC("xdp.frags")` decision (Phase 1).
- Verify LLVM/clang toolchain on the build host: `clang --version` (LLVM ≥ 11), `bpftool version`.

**Files:** none committed (throwaway). Record findings in the PR description.

**Acceptance criteria**
- Documented: driver name, native-vs-generic verdict, kernel version, bpffs mount status, GRO/RSS/queue state, the already-attached errno, clang/bpftool versions.
- A scratch XDP program loads + attaches + detaches cleanly on the SUT NIC in at least one mode.

**Risks / prereqs:** Some cloud/virtio NICs only support generic XDP; bonded/VLAN/bridge setups need attaching to the lower device. If only generic mode is available, the `%soft` delta is smaller — set expectations now, and note generic-mode A/B numbers are **not** comparable to native-mode numbers (S3).

**Kill switch / rollback:** Throwaway only; `ip link set dev <iface> xdp off` detaches. No persistent change.

**Effort:** 0.5 day.

---

## PHASE 1 — XDP C program + bpf2go codegen + embed

**Objective:** Produce a verifier-correct, fragment-aware, VLAN-aware XDP program that drops on exact IPv4/IPv6 source-IP HASH-map hits (and optional LPM/CIDR), with **explicit `max_entries` sizing**, and wire up `bpf2go` so the compiled object is embedded into the Go binary (single artifact preserved).

**Tasks**
- Create package dir `internal/banner/` with a `bpf/` subdir for C + vendored headers.
- Write the XDP C program. Use the verified skeleton from research: `SEC("xdp.frags")`, VLAN walk to `VLAN_MAX_DEPTH=2`, the `(ptr + 1) > data_end` bounds idiom before every deref, and the maps below. Program returns only `XDP_PASS`/`XDP_DROP`. **No L4 dereference anywhere** (S10). Mandatory `char _license[] SEC("license") = "GPL";`.
- **Map definitions (explicit, sized — fixes M1/M5/N5):**
  - `banned_v4`: `BPF_MAP_TYPE_HASH`, **key = raw `__u8 addr[4]` (NOT `__u32`)** so there is *zero* endianness reasoning (M1), value `__u8`, `max_entries = 1<<20` (1M), `BPF_F_NO_PREALLOC`, `pinning = LIBBPF_PIN_BY_NAME`. **Shared (NOT per-CPU)** — per-CPU for ban state would require writing all CPUs (N5).
  - `banned_v6`: `BPF_MAP_TYPE_HASH`, key `struct in6_key { __u8 addr[16]; }`, value `__u8`, `max_entries = 1<<20`, `BPF_F_NO_PREALLOC`, pinned, shared.
  - optional `banned_v4_cidr`/`banned_v6_cidr`: `LPM_TRIE`, key `{__u32 prefixlen; __u8 data[N];}`, `BPF_F_NO_PREALLOC`, pinned.
  - **`stats`: `BPF_MAP_TYPE_PERCPU_ARRAY`, 2 entries (`pkts_passed`, `pkts_dropped`), incremented every PASS/DROP — shipped ON by default** (it is the headline metric; per-CPU array keeps the increment cheap and lock-free, re-validated in Phase 5 B-vs-A). (per-CPU is correct *here*; ban maps are not — N5.)
  - **`schema_version`: `BPF_MAP_TYPE_ARRAY`, 1 entry, pinned** — holds a `__u32` layout version stamp written at load (M5/version-stamp). On startup mismatch, daemon unlinks all pins and recreates.
- The v4 program reads `iphdr.saddr` as 4 wire bytes and looks up `banned_v4` by those bytes directly. The Go side stores the same 4 bytes (`ip.To4()`), so **no byte-order conversion exists on either side** (M1).
- Vendor a **minimal, stable** `headers/vmlinux.h` and rely on CO-RE relocations — we only touch stable fields `ethhdr.h_proto`, `iphdr.saddr`, `ipv6hdr.saddr` (S6/M1 risk note). Vendor libbpf `bpf/bpf_helpers.h`, `bpf/bpf_endian.h`.
- Add `//go:generate` in `internal/banner/gen.go` invoking `bpf2go` with `-type in6_key -type lpm_v4_key -type lpm_v6_key` and `-- -I./bpf/headers -I./bpf/headers/bpf -O2 -g -Wall -Werror`.
- Run `go generate ./...`; commit the generated `bpf_bpfel.go`/`bpf_bpfeb.go` and `.o` objects (commit-vs-CI decision in Phase 4).

**Files to create**
- `internal/banner/bpf/xdp_ban.c`
- `internal/banner/bpf/headers/vmlinux.h`, `.../bpf/bpf_helpers.h`, `.../bpf/bpf_endian.h`
- `internal/banner/gen.go`:
  ```go
  //go:build ignore

  package banner

  //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux \
  //   -type in6_key -type lpm_v4_key -type lpm_v6_key \
  //   bpf bpf/xdp_ban.c -- -I./bpf/headers -I./bpf/headers/bpf -O2 -g -Wall -Werror
  ```
- Generated (committed): `internal/banner/bpf_bpfel.go`, `bpf_bpfel.o`, `bpf_bpfeb.go`, `bpf_bpfeb.o`.

**Code skeleton (C, key correctness points baked in):**
```c
#define VLAN_MAX_DEPTH 2

struct in6_key { __u8 addr[16]; };

struct { __uint(type, BPF_MAP_TYPE_HASH);
         __type(key, __u8[4]); __type(value, __u8);
         __uint(max_entries, 1 << 20);
         __uint(map_flags, BPF_F_NO_PREALLOC);
         __uint(pinning, LIBBPF_PIN_BY_NAME); } banned_v4 SEC(".maps");
/* banned_v6, stats (PERCPU_ARRAY), schema_version similarly */

SEC("xdp.frags")
int xdp_ban_func(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;          /* fail open */
    __u16 proto = eth->h_proto; void *cur = eth + 1;
    /* VLAN walk to depth 2, RE-READ inner proto (trunk-port banned host) */
    /* depth>2 (QinQ) -> XDP_PASS (documented fail-open gap, S10) */
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = cur;
        if ((void *)(ip + 1) > end) return XDP_PASS;
        __u8 *v = bpf_map_lookup_elem(&banned_v4, &ip->saddr); /* 4 wire bytes */
        if (v) { stats_inc(DROP); return XDP_DROP; }
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = cur;
        if ((void *)(ip6 + 1) > end) return XDP_PASS;
        __u8 *v = bpf_map_lookup_elem(&banned_v6, &ip6->saddr);
        if (v) { stats_inc(DROP); return XDP_DROP; }
    }
    stats_inc(PASS); return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
```
Correctness notes baked in: VLAN re-read of inner EtherType (trunked-port banned host would otherwise bypass); source addr lives in the fixed L3 header of *every* IPv4 fragment and in the base IPv6 header of every IPv6 fragment, so **no reassembly is needed** (S10); `xdp.frags` lets it load on multi-buffer drivers while we only touch the linear head.

**Acceptance criteria**
- `go generate ./...` reproduces the committed generated `.go` files byte-for-byte (CI check, Phase 4 — `.o` byte-identity NOT required, see Phase 4 S6).
- The object loads under `cilium/ebpf` `loadBpfObjects` on the SUT kernel without verifier rejection (Phase 2 load test).
- C compiles with `-Wall -Werror`.
- v4 key path uses raw 4-byte key end-to-end (no `htonl`/`NativeEndian` anywhere).

**Risks:** verifier behavior varies by kernel — test on the lowest supported kernel (Phase 4 CI matrix). vmlinux.h kept minimal + CO-RE to avoid kernel coupling.

**Kill switch / rollback:** Pure new files; nothing wired in. Deleting `internal/banner/` reverts completely.

**Effort:** 1.5–2 days.

---

## PHASE 2 — Go `XdpEnforcer` implementing the existing `Enforcer` interface

**Objective:** A Linux-only `XdpEnforcer` that loads/attaches (native→generic, conflict-aware), pins maps for restart survival with **schema-version migration**, reads its own map for reconcile, and implements all four `action.Enforcer` methods exactly plus the by-convention `Init() error` and a `Close()`.

**Interface-matching note:** the existing `Enforcer` interface uses `net.IP` and returns `[]action.BanEntry{IP string; Duration time.Duration}` (`enforcer.go:8-20`). `XdpEnforcer.Ban(ip net.IP, _ time.Duration, _ string)` converts `net.IP` → 4/16 bytes (`ip.To4()`/`ip.To16()`), ignores `duration`/`reason` (same as `iptables.go:34-40`, `ipset.go:63-68` — expiry is the daemon's job), and `List()` returns `[]action.BanEntry{IP: ip.String()}` with zero `Duration` (matching both existing impls).

**Tasks**
- Add deps: `go get github.com/cilium/ebpf@latest`. Build is **already cgo-enabled** (go-sqlite3 + gopacket/pcap), so adding `cilium/ebpf` (pure-Go) doesn't change posture — `CGO_ENABLED=1` + gcc + libpcap-dev remain required.
- `internal/banner/enforcer_linux.go` (`//go:build linux`): struct + constructor + `Init`/`Name`/`Ban`/`Unban`/`List`/`Close` + `MapEntries()`/`Attached()`/`Mode()` diagnostics + `attachWithFallback` + **`reconcileLoad`** (handles stale/incompatible pin: on spec-mismatch error from `loadBpfObjects`, unlink pins under `pinDir` and reload — M5). `rlimit.RemoveMemlock()`. **All map mutations wrapped so a panic cannot escape** (`defer recover()` in `Ban`/`Unban`, mirroring `internal/ingest/pcap.go`'s recover pattern — panic isolation).
- `internal/banner/enforcer_stub.go` (`//go:build !linux`): stub whose `New()`/`Init()` returns `errors.New("xdp enforcer requires linux")` so the package compiles on darwin dev machines.
- v4 key marshaling: **raw `[4]byte` from `ip.To4()`** — no endianness logic (M1). v6: `[16]byte` from `ip.To16()`. `ip.To4() != nil` selects the v4 map.
- Map pinning under `/sys/fs/bpf/sipreaper` via `ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}`. **Write-probe the pin dir before load** (preflight; M6). On `Put` returning `ErrKeyExist`/`E2BIG` (map full), return a wrapped error so the daemon increments `metrics.EnforcerErrors` and alerts fire (M5).
- **`max_entries` is set in C (Phase 1)**, but the Go side asserts the loaded map's `MaxEntries()` matches expectation and logs the high-water mark.
- Tests:
  - **`BPF_PROG_TEST_RUN` packet-classification tests** (`//go:build linux`, skip if not root / no BTF) using `Program.Test` with crafted Ethernet frames: banned-v4 → `XDP_DROP`; non-banned → `XDP_PASS`; VLAN-tagged banned host → `XDP_DROP`; QinQ depth-3 banned host → `XDP_PASS` (documented gap); banned-v6 → `XDP_DROP`; non-IP EtherType → `XDP_PASS`; truncated/malformed frame → `XDP_PASS` (fail-open). **This is the primary correctness gate for the verifier-sensitive VLAN/bounds code** — the prior load+roundtrip test alone is insufficient.
  - **Kernel round-trip test** (M1 acceptance): `Ban(1.2.3.4)`, then `BPF_PROG_TEST_RUN` a frame from `1.2.3.4`, assert `XDP_DROP` — proves the userspace key bytes actually match what the program looks up (a self-consistent byte-helper test would pass while being wrong; this catches it).
  - Pure (no-kernel) `net.IP`↔key byte-layout test that runs on all platforms.
  - Pin-survival test: `Ban`, re-`Init`, assert entry present. Stale-pin test: load with a deliberately mismatched spec, assert recreate path (M5).

**Files to create**
- `internal/banner/enforcer_linux.go`, `internal/banner/enforcer_stub.go`, `internal/banner/enforcer_test.go`, `internal/banner/progtest_test.go`.

**Code skeleton (interface-conformant, `net.IP`-based, raw-byte v4 key):**
```go
//go:build linux

package banner

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/andycol/sipreaper/internal/action"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const pinDir = "/sys/fs/bpf/sipreaper"
const schemaVersion uint32 = 1

var _ action.Enforcer = (*XdpEnforcer)(nil)

type XdpEnforcer struct {
	mu       sync.Mutex
	ifindex  int
	iface    string
	auto     bool                // true = driver then generic
	mode     link.XDPAttachFlags // used only when !auto
	objs     bpfObjects
	xdp      link.Link
	attached bool
	curMode  string
}

func NewXdpEnforcer(iface, mode string) (*XdpEnforcer, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("xdp: interface %q: %w", iface, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("xdp: interface %q is down", iface)
	}
	auto, m, err := parseMode(mode) // "" -> auto; "native"/"generic" -> explicit
	if err != nil {
		return nil, err
	}
	return &XdpEnforcer{ifindex: ifi.Index, iface: iface, auto: auto, mode: m}, nil
}

func (e *XdpEnforcer) Name() string { return "xdp" }

func (e *XdpEnforcer) Init() error {
	if err := preflight(pinDir); err != nil { // bpffs + BTF + write-probe (M6)
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("xdp: remove memlock: %w", err)
	}
	if err := e.reconcileLoad(); err != nil { // handles stale/incompatible pin (M5)
		return err
	}
	if err := e.attachWithFallback(); err != nil {
		e.objs.Close()
		return err
	}
	return nil
}

// reconcileLoad loads objects, recreating pins on schema mismatch (never fail-closed).
func (e *XdpEnforcer) reconcileLoad() error {
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}
	err := loadBpfObjects(&e.objs, opts)
	if err != nil && isPinIncompatible(err) {
		if uerr := unlinkPins(pinDir); uerr != nil {
			return fmt.Errorf("xdp: unlink stale pins: %w", uerr)
		}
		err = loadBpfObjects(&e.objs, opts)
	}
	if err != nil {
		return fmt.Errorf("xdp: load objects: %w", err)
	}
	_ = e.objs.SchemaVersion.Put(uint32(0), schemaVersion)
	return nil
}

func (e *XdpEnforcer) attachWithFallback() error {
	modes := []struct{ name string; f link.XDPAttachFlags }{
		{"driver", link.XDPDriverMode}, {"generic", link.XDPGenericMode},
	}
	if !e.auto {
		modes = []struct{ name string; f link.XDPAttachFlags }{{modeName(e.mode), e.mode}}
	}
	var last error
	for _, m := range modes {
		l, err := link.AttachXDP(link.XDPOptions{
			Program: e.objs.XdpBanFunc, Interface: e.ifindex, Flags: m.f,
		})
		if err == nil {
			e.xdp, e.attached, e.curMode = l, true, m.name
			return nil
		}
		last = err
		// EBUSY/EEXIST => another XDP prog attached; retrying generic won't help.
		if errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("xdp: another XDP program is already attached to %s; "+
				"detach it or set enforcer.xdp.enabled=false: %w", e.iface, err)
		}
		// EOPNOTSUPP/ENOTSUP => native unsupported; loop falls through to generic.
	}
	return fmt.Errorf("xdp: attach failed (native+generic) on %s: %w", e.iface, last)
}

func (e *XdpEnforcer) Ban(ip net.IP, _ time.Duration, _ string) (err error) {
	defer func() { if r := recover(); r != nil { err = fmt.Errorf("xdp ban panic: %v", r) } }()
	e.mu.Lock(); defer e.mu.Unlock()
	one := uint8(1)
	if v4 := ip.To4(); v4 != nil {
		var k [4]byte; copy(k[:], v4)
		if perr := e.objs.BannedV4.Put(k, one); perr != nil {
			return fmt.Errorf("xdp: ban v4 %s: %w", ip, perr) // E2BIG surfaces here (M5)
		}
		return nil
	}
	var k [16]byte; copy(k[:], ip.To16())
	if perr := e.objs.BannedV6.Put(bpfIn6Key{Addr: k}, one); perr != nil {
		return fmt.Errorf("xdp: ban v6 %s: %w", ip, perr)
	}
	return nil
}

func (e *XdpEnforcer) Unban(ip net.IP) (err error) {
	defer func() { if r := recover(); r != nil { err = fmt.Errorf("xdp unban panic: %v", r) } }()
	e.mu.Lock(); defer e.mu.Unlock()
	if v4 := ip.To4(); v4 != nil {
		var k [4]byte; copy(k[:], v4)
		if derr := e.objs.BannedV4.Delete(k); derr != nil && !errors.Is(derr, ebpf.ErrKeyNotExist) {
			return derr
		}
		return nil
	}
	var k [16]byte; copy(k[:], ip.To16())
	if derr := e.objs.BannedV6.Delete(bpfIn6Key{Addr: k}); derr != nil && !errors.Is(derr, ebpf.ErrKeyNotExist) {
		return derr
	}
	return nil
}

func (e *XdpEnforcer) List() ([]action.BanEntry, error) {
	e.mu.Lock(); defer e.mu.Unlock()
	var out []action.BanEntry
	var k4 [4]byte; var v uint8
	it4 := e.objs.BannedV4.Iterate()
	for it4.Next(&k4, &v) { out = append(out, action.BanEntry{IP: net.IP(k4[:]).String()}) }
	if err := it4.Err(); err != nil { return nil, err }
	var k6 bpfIn6Key
	it6 := e.objs.BannedV6.Iterate()
	for it6.Next(&k6, &v) { out = append(out, action.BanEntry{IP: net.IP(k6.Addr[:]).String()}) }
	return out, it6.Err()
}

// MapEntries / Attached / Mode are diagnostics for Phase 6 metrics + reconcile.
func (e *XdpEnforcer) Attached() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.attached }
func (e *XdpEnforcer) Mode() string   { e.mu.Lock(); defer e.mu.Unlock(); return e.curMode }

func (e *XdpEnforcer) Close() error {
	e.mu.Lock(); defer e.mu.Unlock()
	var errs []error
	if e.xdp != nil { errs = append(errs, e.xdp.Close()) } // detach link; pins survive
	errs = append(errs, e.objs.Close())
	return errors.Join(errs...)
}
```

**Acceptance criteria**
- `var _ action.Enforcer = (*XdpEnforcer)(nil)` compiles.
- `go build ./...` succeeds on linux and darwin (stub).
- **`BPF_PROG_TEST_RUN` classification suite passes** (banned→DROP, non-banned→PASS, VLAN→DROP, QinQ>2→PASS, v6→DROP, non-IP→PASS, truncated→PASS).
- **Kernel round-trip ban→DROP test passes** (catches any v4 key byte-order bug — M1).
- Pinned maps survive restart; stale-pin recreate path verified (M5).
- A forced `E2BIG`/full-map `Ban` returns an error (does not silently no-op).
- A panic inside `Ban`/`Unban` is recovered, not propagated.

**Risks:** map iteration during concurrent writes can repeat keys — harmless for `List` (a state view). On kernels < 5.11 `RLIMIT_MEMLOCK` matters — handled by `RemoveMemlock` (+ `CAP_SYS_RESOURCE` on old kernels, N3).

**Kill switch / rollback:** Self-contained, not yet wired in. `Close()` detaches; `rm -rf /sys/fs/bpf/sipreaper` clears kernel map state (does NOT detach a running program — see Phase 3 kill switch).

**Effort:** 2.5–3 days.

---

## PHASE 3 — Wire into the daemon (composite + config + reconcile + kill switch)

**Objective:** Introduce `CompositeEnforcer`, extend config, add a **programmatic preflight**, route the ban lifecycle through the composite, add the **startup reconcile** (M2), the **`restoreBans` whitelist skip** (M3), a **runtime kill switch** (SIGHUP detach), graceful `Close`, and an admin status surface.

**Tasks**

**3a. CompositeEnforcer** — `internal/action/composite.go`. Wraps `[]Enforcer`. `Ban`/`Unban` call each member best-effort and `errors.Join` (one backend failing must not block the other; log per-backend). `List` returns **member[0]'s** list (iptables/ipset/DB view stays authoritative for the user-facing API — avoids doubled rows). **To support reconcile (M2), expose per-member access:**
```go
package action

import ("errors"; "net"; "strings"; "time")

type CompositeEnforcer struct{ members []Enforcer }

func NewCompositeEnforcer(members ...Enforcer) *CompositeEnforcer { return &CompositeEnforcer{members} }
func (c *CompositeEnforcer) Members() []Enforcer { return c.members } // for reconcile/diagnostics
func (c *CompositeEnforcer) Name() string {
	n := make([]string, len(c.members)); for i, m := range c.members { n[i] = m.Name() }
	return "composite(" + strings.Join(n, ",") + ")"
}
func (c *CompositeEnforcer) Ban(ip net.IP, d time.Duration, reason string) error {
	var errs []error
	for _, m := range c.members { if err := m.Ban(ip, d, reason); err != nil { errs = append(errs, err) } }
	return errors.Join(errs...)
}
func (c *CompositeEnforcer) Unban(ip net.IP) error {
	var errs []error
	for _, m := range c.members { if err := m.Unban(ip); err != nil { errs = append(errs, err) } }
	return errors.Join(errs...)
}
func (c *CompositeEnforcer) List() ([]BanEntry, error) {
	if len(c.members) == 0 { return nil, nil }
	return c.members[0].List() // member[0] = base (iptables/ipset). See S2 diagnostics.
}
```

**3b. Config** — extend `EnforcerConfig` at `internal/config/config.go:136-147`:
```go
type EnforcerConfig struct {
	Type      string          `mapstructure:"type"`
	Chain     string          `mapstructure:"chain"`
	SetName   string          `mapstructure:"set_name"`
	DryRun    bool            `mapstructure:"dry_run"`
	PreFilter PreFilterConfig `mapstructure:"prefilter"`
	XDP       XDPConfig       `mapstructure:"xdp"` // NEW
}

type XDPConfig struct {
	Enabled    bool   `mapstructure:"enabled"`    // additive: layer XDP on top of Type
	Interface  string `mapstructure:"interface"`  // default to ingest.pcap.interface if empty
	Mode       string `mapstructure:"mode"`       // "" (auto) | "native" | "generic"
	Standalone bool   `mapstructure:"standalone"` // if true, XDP is the ONLY backend
}
```
- Defaults near `config.go:199-201`: `enforcer.xdp.enabled=false`, `enforcer.xdp.mode=""`, `enforcer.xdp.standalone=false`.
- Validation near `config.go:362-367`: `mode` ∈ {"", "native", "generic"}; if `xdp.enabled` and both `xdp.interface=="" && ingest.pcap.interface==""`, error. Existing `Type` validation unchanged.

**3c. Programmatic preflight + setupEnforcer** — modify `internal/daemon/daemon.go:306-339`. Keep the existing switch building the base (iptables/ipset) into `base action.Enforcer`. **`base` is ALWAYS built, even when `standalone=true`**, so fail-open has a real fallback (S9). Then:
```go
// after the existing switch sets `base`:
d.enforcer = base
if d.cfg.Enforcer.XDP.Enabled {
	iface := d.cfg.Enforcer.XDP.Interface
	if iface == "" { iface = d.cfg.Ingest.Pcap.Interface }
	if reason := banner.Preflight(iface); reason != "" { // kernel/btf/bpffs/iface (table up top)
		log.Printf("warning: xdp preflight failed (%s); staying on %s", reason, base.Name())
	} else if xe, err := banner.NewXdpEnforcer(iface, d.cfg.Enforcer.XDP.Mode); err != nil {
		log.Printf("warning: xdp enforcer init failed, staying on %s: %v", base.Name(), err)
	} else if err := xe.Init(); err != nil {
		log.Printf("warning: xdp attach failed, staying on %s: %v", base.Name(), err) // FAIL OPEN
	} else {
		d.xdp = xe // keep concrete handle for Close()/metrics/kill-switch (Close not on interface)
		metrics.XdpAttached.WithLabelValues(xe.Mode()).Set(1)
		log.Printf("enforcer: xdp attached on %s mode=%s", iface, xe.Mode()) // loud (Phase 0 Q)
		if d.cfg.Enforcer.XDP.Standalone {
			d.enforcer = xe
		} else {
			d.enforcer = action.NewCompositeEnforcer(base, xe)
		}
		log.Printf("enforcer: active = %s", d.enforcer.Name())
	}
}
```
XDP failure (any cause) leaves the proven `base` in `d.enforcer` (system-level fail-open). The concrete `*banner.XdpEnforcer` is stored in a new `d.xdp` field because `action.Enforcer` has no `Close()` — the daemon must hold the concrete type for `Close`/metrics/kill-switch (resolves the hand-waved type-assert).

**3d. Startup reconcile (M2/M3) — runs BEFORE `restoreBans`:**
```go
func (d *daemon) reconcileXdp() {
	if d.xdp == nil { return }
	active, _ := d.store.ListBans("active")
	want := map[string]bool{}
	for _, b := range active {
		ip := net.ParseIP(b.IP)
		if ip == nil || d.whitelist.Contains(ip) { continue } // M3: whitelist wins
		want[ip.String()] = true
	}
	have, _ := d.xdp.List() // reads the XDP map directly (NOT composite member[0]) — M2 fix
	removed := 0
	for _, e := range have {
		if !want[e.IP] { _ = d.xdp.Unban(net.ParseIP(e.IP)); removed++ } // stale / whitelisted
	}
	metrics.XdpReconcileRemoved.Add(float64(removed))
	log.Printf("xdp reconcile: %d stale/whitelisted map entries removed", removed)
}
```
- **`restoreBans` (M3):** add `if d.whitelist.Contains(net.ParseIP(ban.IP)) { /* mark expired in store, skip */ continue }` so a banned-then-whitelisted-while-down IP is never re-applied to *any* backend. `restoreBans` calls `d.enforcer.Ban` (composite → both backends).
- Order in startup: build enforcer (3c) → `reconcileXdp()` → `restoreBans()`.

**3e. Lifecycle reuse** — the composite slots into the four existing call sites unchanged:
- **Apply:** `handleThreat` (`daemon.go:425-435`) gates on `!d.engine.DryRun()`, calls `d.enforcer.Ban`; whitelist already filtered upstream (`engine.go:41-45`).
- **Restore:** `restoreBans` (`daemon.go:508-525`) re-applies `active` bans — now with the M3 whitelist skip, preceded by `reconcileXdp`.
- **Expiry:** `runBanExpiry` (`daemon.go:464-506`) calls `d.enforcer.Unban` for non-dry-run expired bans.
- **Manual unban / atomic whitelist:** `srv.SetUnbanFunc(d.enforcer.Unban)` (`daemon.go:172-174`) now wires the composite `Unban`.

**3f. Periodic reconcile tick (S1):** because per-backend `Unban` can leave the two backends inconsistent (iptables removed, XDP not), run `reconcileXdp()` on a low-frequency ticker (e.g. every 5 min) in addition to startup, so drift self-heals well before the next restart.

**3g. Runtime kill switch (gap fix).** The daemon already supports `ExecReload=/bin/kill -HUP`. Add a SIGHUP handler branch (or extend the existing one) that, if `d.xdp != nil`, calls `d.xdp.Close()` (detaches link, pins survive) and sets `d.enforcer = base`, logging "xdp detached by SIGHUP; now on <base>". This is the **safe, no-restart kill switch**. Document that the bare `ip link set dev <iface> xdp off` also detaches but the daemon will re-attach on next restart; `rm -rf /sys/fs/bpf/sipreaper` clears bans but does **not** detach a running program (so it is NOT a way to stop over-dropping — SIGHUP or `ip link ... xdp off` is). Optionally expose the same detach via the admin API (3h).

**3h. Admin API status (S2 + gap fix):** add a read-only `GET /xdp/status` (and a metric) reporting `{attached, mode, map_entries_v4, map_entries_v6, last_reconcile_removed}`. The user-facing ban `List` stays member[0]; this endpoint is where divergence is visible. Optionally a `POST /xdp/detach` mirroring 3g.

**3i. Graceful shutdown.** In the daemon stop path, `if d.xdp != nil { d.xdp.Close() }` — detaches the link, **keeps maps pinned** (restart survival). The link is deliberately **not** pinned: on `SIGKILL` the prog detaches when the last fd closes (fail-open), while the pinned maps persist — exactly the case the startup `reconcileXdp` (3d) cleans up (M2/S8 made coherent).

**Files to modify**
- `internal/config/config.go` — `:136-147`, `:199-201`, `:362-367`.
- `internal/daemon/daemon.go` — `:306-339` (setupEnforcer + preflight + `d.xdp` field at `:34`), startup order (`reconcileXdp` before `restoreBans`), `restoreBans` whitelist skip (`:508-525`), SIGHUP handler, periodic reconcile ticker, shutdown `Close`.
- `config.example.yaml` — annotated `enforcer.xdp` block.

**Files to create**
- `internal/action/composite.go` + `internal/action/composite_test.go` (fake `Enforcer` members assert fan-out + error-join + member[0] `List`).
- `internal/banner/preflight_linux.go` / `preflight_stub.go` (`Preflight(iface) string`).

**Acceptance criteria**
- `enforcer.xdp.enabled=false` → byte-identical to today (composite never constructed).
- `enabled=true` → ban creates iptables/ipset rule AND map entry; unban/expiry/whitelist-of-banned removes both.
- **Forced XDP attach failure with `enabled=true` AND `standalone=true` → `base` enforcer is active and functional** (not a no-op) (S9 test).
- **Startup reconcile:** a pinned map entry that is (a) not in `active`, or (b) now whitelisted, is removed at boot — verified by pre-seeding the map then booting (M2/M3).
- **`restoreBans` skips whitelisted IPs** — pre-whitelist an `active`-row IP, boot, assert it is NOT in any backend (M3).
- **Whitelisted IP under flood never enters the map** — e2e: whitelist an IP in the flood range, run F1, assert `bpftool map dump` never contains it (security test, gap fix).
- SIGHUP detaches XDP and reverts to `base` with no restart (3g).
- Dry-run: `Status="dry_run"` bans produce neither rule nor map entry.
- `go test ./internal/action/... ./internal/config/...` passes.

**Risks:** default-interface fallback to the pcap interface must log the chosen NIC loudly and is validated up-front. Composite `List` = member[0] is intentional; `/xdp/status` closes the observability gap.

**Kill switch / rollback:** `enforcer.xdp.enabled=false` + restart fully disables. `standalone=false` keeps iptables as the safety net. SIGHUP detaches live. **Rollback from `standalone=true`:** set `standalone=false` (or `enabled=false`) and restart; `restoreBans` re-populates the iptables/ipset backend from `ListBans("active")` (it already re-applies via `d.enforcer.Ban`). Documented in Phase 7 as the rollback procedure. **Retiring iptables rules at cutover to standalone** is an explicit step (Phase 7 runbook): after standalone is proven, flush the per-IP rules via `iptables -F SIPREAPER` / `ipset flush <set>`; the inverse (rollback) re-creates them via `restoreBans`.

**Effort:** 2.5 days.

---

## PHASE 4 — Build / CI changes

**Objective:** Preserve the single-binary, manual-deploy model, make the embedded XDP object reproducible, add runtime capabilities to the deploy unit, and add a **lowest-kernel verifier job**. (There is no Dockerfile, no `.github/`, no CI today; only the `Makefile`.)

**Tasks**

**4a. Makefile** — `/Users/andrewcolin/git/sipreaper/Makefile` has only `build/test/clean` with plain `go build -o sipreaper ./cmd/sipreaper`. Add `generate`; `build` gains no new dependency (the `.o` is committed, so plain `go build` works without clang):
```make
.PHONY: build test clean generate

generate:
	go generate ./...

build:
	go build -o $(BINARY) ./cmd/sipreaper
```
Document: `make generate` needs clang/LLVM ≥ 11 + bpftool; `make build` does not.

**4b. Commit-the-object decision (chosen): commit generated `.go` + `.o`.** Rationale: no CI to regenerate, manual release, keeps `make build` toolchain-light (existing gcc + libpcap-dev only). `//go:embed` in the generated `bpf_bpfel.go` bakes the `.o` into the ~20MB binary, preserving the single-artifact property.

**4c. CI from scratch** — add `.github/workflows/ci.yml`:
- Job `build-test`: install `gcc libpcap-dev`, `go build ./...`, `go test ./... -race`. `CGO_ENABLED=1`.
- Job `bpf-regen-check`: install **version-pinned** `clang llvm libbpf-dev linux-headers` + bpftool, run `go generate ./...`, then `git diff --exit-code -- internal/banner/*.go` — **diff only the generated `.go`, NOT the `.o`** (the `.o` carries debug-info/endianness noise that differs across toolchain patch versions and would produce chronic spurious failures — S6). Pin the exact clang/llvm/bpftool versions in the image.
- Job `bpf-verifier-matrix` (S6/lowest-kernel gap): on at least the **lowest supported kernel** (e.g. a 5.7 and a current-LTS image/VM), run a tiny loader that `loadBpfObjects` + attaches the committed `.o` and runs the `BPF_PROG_TEST_RUN` suite — catches verifier regressions the single-image build can't.

**4d. Build prerequisites** — update `README.md:45-65`: add the **generate-time-only** toolchain (`clang llvm libbpf-dev linux-headers-$(uname -r)` / `clang llvm libbpf-devel kernel-headers`), clearly marked "only to regenerate the XDP object, not to build."

**4e. systemd capabilities + bpffs** — `/Users/andrewcolin/git/sipreaper/sipreaper.service` runs `User=root`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/sipreaper`, and **currently declares no capabilities**. For XDP add:
- `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_NET_RAW` (+ `CAP_SYS_ADMIN CAP_SYS_RESOURCE` for kernels < 5.8 — N3).
- `CapabilityBoundingSet=` the same set (non-root path).
- `ReadWritePaths=/var/lib/sipreaper /sys/fs/bpf` (pins live there; required under `ProtectSystem=strict`).
- **`RequiresMountsFor=/sys/fs/bpf`** — mandatory (not "or") so the unit refuses to start without bpffs, instead of silently degrading at runtime (M6). The daemon *additionally* write-probes the pin dir in preflight (Phase 3) and degrades rather than crashes if the probe fails.
- **Test the non-root + `ProtectSystem=strict` + bpffs *pinning* combination explicitly** (M6) — 4e acceptance below covers pinning, not just attach.

**Files to modify/create**
- `Makefile`, `.github/workflows/ci.yml` (new), `README.md` (`:45-65`, `:513-597`), `sipreaper.service`.

**Acceptance criteria**
- `make build` succeeds with only gcc + libpcap-dev (committed `.o`).
- `make generate` reproduces the committed generated `.go` (CI `git diff --exit-code -- internal/banner/*.go` clean).
- `bpf-verifier-matrix` loads + attaches + passes `BPF_PROG_TEST_RUN` on the lowest supported kernel.
- Resulting binary is a single file with the XDP object embedded.
- Daemon under the updated unit can load + attach **and pin** XDP non-root with `CAP_BPF CAP_NET_ADMIN` + bpffs writable in its namespace.

**Risks:** `linux-headers`/clang version skew CI vs SUT — pinned image. Committed `.o` is endian-specific but bpf2go emits both `bpfel`/`bpfeb` with build constraints, so cross-arch is covered.

**Kill switch / rollback:** CI is non-blocking to deploy (manual release). Capability + bpffs additions are inert when `enforcer.xdp.enabled=false`.

**Effort:** 1.5 days.

---

## PHASE 5 — sipp before/after benchmark (proves no OpenSIPS regression)

**Objective:** Empirically prove (1) **no overhead**: attaching XDP + per-packet map lookups + the default-on stats counter doesn't tax the legit path; (2) **headroom**: under a source-IP flood, XDP yields strictly higher legit throughput and lower `%soft` than the iptables/ipset baseline. Gating phase — `standalone=true` rollout is only allowed after all numeric criteria pass.

**Topology:** 3 hosts on an isolated L2 segment — **SUT** (OpenSIPS + sipreaper + XDP), **LOAD** (legit sipp), **ATTACK** (flood). LOAD and ATTACK on separate NICs/hosts so the flood can't starve the legit generator.

**Confounder controls (S3) — applied identically to ALL cells:**
- **Pin IRQ affinity** of the SIP-facing NIC queues to fixed CPUs (`/proc/irq/*/smp_affinity`); record `ethtool -l`/`-x`.
- **Fix GRO/LRO/RSS state identically** across A/B/C/D (`ethtool -K <iface> gro on/off lro off` — same value every cell). Note: generic XDP runs *after* GRO, native before — so generic-mode A/B numbers are **not** compared against native-mode numbers (state it in the report).
- **Size the neighbor/route cache for the flood:** raise `net.ipv4.neigh.default.gc_thresh{1,2,3}` and route cache so the spoofed-source volume doesn't perturb CPU independently of the enforcer. **Confirm the spoofed 198.18.0.0/15 sources are off-link** (routed via the test gateway) so there is no ARP-per-source storm.
- **Runs:** discard first/last 10s; **≥5 runs per cell** (not 3 — 2% is within 3-run variance); report mean ± stddev.

**OpenSIPS-not-the-bottleneck setup:** workers ≥ SUT cores (`children`/`udp_workers`), trivial REGISTER/INVITE script (no DB on hot path); confirm OpenSIPS `load` < ~75% in cell A. **Verify the exact MI stat names for the target OpenSIPS major version (2.x vs 3.x differ — N4).** If pegged, lower legit rate.

**5a. SIPp scenarios**
- REGISTER w/ digest auth (`register.xml`, `users.csv` via `-inf`):
  ```bash
  sipp 10.0.0.10:5060 -sf register.xml -inf users.csv \
    -r 200 -rp 1000 -l 2000 -m 18000 \
    -trace_stat -fd 1 -trace_err -i 10.0.0.20 -p 5060 -nd -timeout 5s
  ```
- Basic call (built-in): `sipp 10.0.0.10:5060 -sn uac -r 100 -rp 1000 -l 1000 -m 12000 -d 5000 -trace_stat -fd 1 -trace_err -i 10.0.0.20 -p 5061` (`-sn uas` sink as needed).
- **TLS/TCP (5061) case (S7):** a SIP-over-TCP/TLS REGISTER scenario (`-t l1` for TLS) so the TCP drop path is exercised; assert in-flight calls from a banned source tear down (documents mid-stream behavior).
- Hold legit load **constant** across all cells. Capacity ceiling ramp: `-r 50 -rate_increase 50 -rate_interval 10 -rate_max 1500` (fall back to `+`/`*` hot keys if the sipp build lacks `-rate_increase`).

**5b. Flood generators — both must produce *bannable* (bounded-source) traffic so the map is non-empty (S4):**
- **F1 — scapy well-formed INVITE**, spoofed sources from a **bounded pool in 198.18.0.0/15** (RFC 2544 bench range, never real space), ~5–10k distinct IPs/s — triggers real bans + fills the map.
- **F2 — line-rate saturation**, but **bounded sources** (reuse the 198.18/15 pool, *not* `--rand-source`): `hping3 --udp -p 5060 --flood -d 350 -E invite_payload.txt --rand-source` **is rejected** — instead drive F2 from the same bounded pool, OR **pre-seed the map** to the target size first so XDP actually has entries to drop. (`--rand-source` floods the entire IPv4 space; sipreaper never bans those, the map stays empty, and F2 would measure raw UDP-receive cost, not the enforcer — S4.)
- **Pre-seed** the map/ipset to 1k/10k/50k entries to measure steady-state lookup cost independent of ban ramp (validates O(1) hash vs growing iptables chain), and to give F2 something to drop.

**5c. Measurement (per run, discard first/last 10s)**
- SIPp throughput/failures from `-trace_stat` CSV: `SuccessfulCall(P)`/`CallRate(P)`, `FailedCall`, `FailedMaxUDPRetrans`, `FailedTimeoutOnRecv`, `ResponseTime`.
- `mpstat -P ALL 1 90` (`%soft`) + `mpstat -I SCPU -P ALL 1 90` (NET_RX breakdown).
- `pidstat -p $(pgrep -d, opensips) 1 90` and the sipreaper PID.
- `tcpdump -ni eth0 -w trace.pcap 'udp port 5060'` → count INVITEs reaching userspace. **Note (M4): XDP runs before the AF_PACKET tap, so captured flood volume falling to ~0 with XDP on is the *same mechanism* that blinds sipreaper's detectors to a banned source — it is both the success signal AND the detection-blindness behavior. Record both interpretations.**
- **stats map** (`bpftool map dump pinned /sys/fs/bpf/sipreaper/stats`) → `pkts_dropped` per window confirms XDP is doing the dropping (cross-check vs the tcpdump ~0).
- OpenSIPS MI deltas: `rcv_requests`, `drop_requests`, `err_requests`, `load:` snapshotted start/end of window (version-correct stat names — N4).

**5d. Matrix (legit load constant; ≥5× each; mean ± stddev)**

| Cell | XDP | Attack | Primary read |
|---|---|---|---|
| A | off | none | baseline reg/s & calls/s, `%soft`, OpenSIPS `%CPU`/`load` |
| B | on | none | **overhead test** vs A (includes default-on stats counter) |
| C | off | F1/F2 (bounded) | legit collapse + `%soft` spike (ipset/iptables drop) |
| D | on | F1/F2 (bounded) | **headroom test** vs C |

Optional cells E/F: existing `ipset` drop and `hashlimit` prefilter (`internal/action/prefilter.go`) under flood, comparing XDP against shipping code.

**5e. Numeric pass criteria**
1. **No overhead (B vs A):** legit sustained reg/s and calls/s within **`|B − A| / A < 5%`** (threshold raised from 2% — 2% is within run-to-run SIP variance even at ≥5 runs; S3) AND `FailedCall` rate unchanged AND OpenSIPS worker `%CPU` within ~1 point. Same threshold applies separately to the TLS/TCP 5061 case.
2. **Headroom (D vs C):** legit sustained throughput **strictly higher** in D than C under identical flood; target D ≈ A (flood fully absorbed). Corroborated by lower host `%soft`, near-zero captured flood INVITEs in D, `stats.pkts_dropped` ≈ flood volume, and OpenSIPS `rcv_requests`/`load` in D ≈ A while C climbs.
3. **Map-fill independence:** D repeated at 1k/10k/50k pre-seeded bans shows no legit-throughput degradation with map size.

**Files to create** (`bench/`): `bench/register.xml`, `bench/register_tls.xml`, `bench/users.csv`, `bench/flood.py`, `bench/preseed.sh`, `bench/run-matrix.sh` (drives cells; pins IRQ/GRO/RSS; collects mpstat/pidstat/tcpdump/MI/stats-map; emits CSV), `bench/README.md`.

**Acceptance criteria:** all three numeric criteria met on the SUT; signed-off report attached to the PR. Failure blocks `standalone=true` (composite-with-iptables stays the shipped default).

**Risks:** generic-mode XDP (Phase 0) shrinks the `%soft` win — if so, headroom is judged against the ipset baseline, not zero, and generic A/B is not compared to native A/B. Keep 198.18/15 *out* of the whitelist for the real flood, but *include* one whitelisted IP in the flood range for the security test (Phase 3 acceptance).

**Kill switch / rollback:** benchmark is offline; no production impact.

**Effort:** 2.5–3 days (incl. host setup).

---

## PHASE 6 — Observability / debugging / alerting

**Objective:** Make the XDP layer inspectable, expose health/metrics consistent with existing Prometheus instrumentation (`metrics.EnforcerErrors`, `metrics.ActiveBans` at `daemon.go:432,489,492`), and ship **alerting rules** for the dangerous silent-degradation case.

**Tasks**
- **Drop counter ON by default (gap fix):** the `stats` PERCPU_ARRAY (`pkts_passed`/`pkts_dropped`, Phase 1) is read on each metrics scrape and exposed as `metrics.XdpPacketsDropped`/`XdpPacketsPassed` counters. This is the headline value-prop metric, so it is **default-on**; the Phase 5 B-vs-A test must pass *with it on*.
- **Metrics (new gauges/counters):**
  - `metrics.XdpAttached` gauge (1/0) with a `mode` label (driver/generic) — the silent-degradation signal.
  - `metrics.XdpMapEntries{family}` gauge (len of v4/v6 maps on scrape).
  - `metrics.XdpReconcileRemoved` counter (entries removed by reconcile — surfaces DB↔map drift; S2).
  - `metrics.XdpMapFull` / reuse `metrics.EnforcerErrors{op="ban"}` when `Put` returns `E2BIG` (M5).
  - Composite ban/unban errors already flow through `metrics.EnforcerErrors`.
- **Alerting rules (gap fix — shipped as `docs`/`deploy/alerts.yml`):**
  - `enforcer.xdp.enabled` true in config but `XdpAttached == 0` → **critical** (silent fail-open to iptables — the dangerous case the design creates).
  - `XdpAttached{mode="generic"}` when native expected → warning.
  - `XdpMapEntries / max_entries > 0.8` → warning (near saturation; M5).
  - `rate(EnforcerErrors{op="ban"}) > 0` sustained → warning (likely map full).
- **/healthz:** extend the existing health path (`store.HealthCheck`) with an XDP check (link still attached + map openable). **Degrade-don't-fail** (fail-open ethos).
- **Admin endpoint** `GET /xdp/status` (Phase 3h) for at-a-glance attached/mode/map-size/last-reconcile.
- **Runbook commands (verification, tied to acceptance — gap fix):** `xdpdump -i <iface>` (DROP vs PASS at the hook), `bpftool prog show`, `bpftool map dump pinned /sys/fs/bpf/sipreaper/banned_v4`, `ip -d link show <iface>` (attached + mode). **Note `xdpdump` may be unavailable on generic-mode NICs** — fall back to the `stats` map + tcpdump-userspace count.
- **Logging:** loud one-line startup log of chosen interface + attach mode (Phase 3c) — answers Phase 0's "did it go native?".

**Files to modify/create**
- `internal/banner/enforcer_linux.go` (stats read, `Attached`/`Mode`/`MapEntries`, health method).
- `internal/metrics/...` (new metrics — match existing registration style).
- `internal/api/` (health + `/xdp/status`).
- `internal/banner/bpf/xdp_ban.c` (stats map — Phase 1).
- `deploy/alerts.yml` (new).

**Acceptance criteria:**
- `bpftool map dump` shows banned IPs matching `store.ListBans("active")` ∖ whitelist (i.e. matches the reconcile result).
- **xdpdump (or stats-map fallback) showing DROP for a banned source and PASS for others is a rollout gate, not just a doc** — captured in the Phase 5 sign-off.
- `/healthz` and `/xdp/status` report attached + mode; Prometheus exposes attach state, map size, drop count, reconcile-removed.
- Alert fires in a test when `enabled=true` but attach is forced to fail.

**Risks:** per-packet stats increment adds cost — measured by the default-on Phase 5 B-vs-A check; if it regresses, gate behind config and re-run.

**Kill switch / rollback:** observability is read-only/additive; the only mutating piece (stats inc) reverts to pure PASS/DROP if the stats map is removed.

**Effort:** 1.5 days.

---

## PHASE 7 — Docs & runbook

**Objective:** Document the enforcer end-to-end — the additive rollout, safety model, the two behavioral changes (M4/S7), the DB↔map source-of-truth model, and a **failure-scenario incident runbook**.

**Tasks**
- `docs/how-it-works.md` (referenced by commit `9fcf293`): add an **"XDP fast-path drop"** section — where it sits vs ipset/iptables and the hashlimit prefilter; composite rollout; fail-open semantics; **whitelist guarantee at all three producers (M2/M3)**; **DB-is-authoritative, pinned-map-is-reconciled** model (what wins on conflict, what `rm -rf /sys/fs/bpf/sipreaper` does to in-flight bans); restart survival via pinned maps; native-vs-generic; **detection blindness (M4)** and **mid-stream TCP/TLS teardown (S7)** explicitly stated as accepted behaviors; **QinQ>2 fail-open gap (S10)**.
- **Incident runbook** (`docs/runbook-xdp.md`): step-by-step for —
  - "XDP attached but legit traffic dropping → detach NOW" (`kill -HUP <pid>` (3g) or `ip link set dev <iface> xdp off`; then `enabled=false` + restart).
  - "Map full / `XdpMapEntries` near `max_entries`" (impact, how to confirm via `bpftool`, raise `max_entries` in C + regen, or rely on composite iptables).
  - "After kernel upgrade the program won't load" (verifier reject → daemon degrades to iptables automatically; regenerate `vmlinux.h`/`.o` on the new kernel).
  - "Bans in DB but not in map (or vice versa)" (run/observe the reconcile; `XdpReconcileRemoved`; `/xdp/status`).
  - **Rollback from `standalone=true`** (set `standalone=false`/`enabled=false`, restart → `restoreBans` re-populates iptables from `ListBans("active")`) and **cutover to standalone** (flush retired rules: `iptables -F SIPREAPER` / `ipset flush`).
- `README.md`: new `enforcer.xdp` config keys + example; build prereqs split "build" vs "regenerate XDP object" (Phase 4); capabilities (`CAP_BPF CAP_NET_ADMIN`, bpffs `RequiresMountsFor`) for root and non-root (`README.md:513-597`); the "clear all XDP bans" (`rm -rf /sys/fs/bpf/sipreaper`, **does not detach**) vs "stop dropping" (SIGHUP / `ip link ... xdp off`) distinction.
- `config.example.yaml`: annotated `enforcer.xdp` block (matches the existing heavily-annotated style).
- Link the Phase 5 benchmark report.

**Files to modify/create**
- `docs/how-it-works.md`, `docs/runbook-xdp.md` (new), `README.md`, `config.example.yaml`.

**Acceptance criteria:** a new operator can enable XDP additively from the README alone, understands the safety model and the two behavioral changes, knows how to verify (`bpftool`/`xdpdump`/stats), how to **stop dropping immediately** vs clear bans, and how to roll back from standalone.

**Effort:** 0.5–1 day.

---

## Summary: rollout order, risks, totals

**Rollout sequence (additive → standalone):**
1. Ship with `enforcer.xdp.enabled=false` (no behavior change).
2. Enable `enabled=true, standalone=false` → **composite**: iptables/ipset stays as the safety net, XDP runs alongside; reconcile + alerts active.
3. Run Phase 5 benchmark; only if all numeric criteria pass, flip `standalone=true` and flush the retired per-IP iptables/ipset rules (runbook). Rollback = `standalone=false`/`enabled=false` + restart (re-populates iptables via `restoreBans`).

**Top risks (all mitigated by fail-open):** v4 key endianness (fixed by raw-`[4]byte` key + kernel round-trip test — M1); stale-pin-drops-whitelisted-IP after restart (startup + periodic reconcile against DB∖whitelist — M2/M3); detection blindness from XDP preempting AF_PACKET (accepted + documented — M4); map full / stale incompatible pin (explicit `max_entries`, `E2BIG` surfacing, unlink-and-recreate, schema-version stamp — M5); bpffs not mounted under hardened systemd (`RequiresMountsFor` + write-probe preflight — M6); attach conflict / wrong NIC (errno-aware fallback, iface-up + loud-log preflight — M7); generic-only NIC (Phase 0 gates expectations); verifier reject on lowest kernel (CI matrix); silent degradation to iptables (alert on `enabled && !XdpAttached`).

**Prerequisites:** kernel ≥ 5.7 (5.8 for `CAP_BPF`), bpffs at `/sys/fs/bpf` (`RequiresMountsFor`), `CAP_BPF`+`CAP_NET_ADMIN`(+`CAP_SYS_ADMIN`/`CAP_SYS_RESOURCE` <5.8), clang/LLVM ≥ 11 + bpftool at generate time only, isolated 3-host bench lab with IRQ/GRO/RSS pinned and neighbor-table sized.

**Effort estimate (engineer-days):** P0 0.5 · P1 1.5–2 · P2 2.5–3 · P3 2.5 · P4 1.5 · P5 2.5–3 · P6 1.5 · P7 0.5–1 → **~13–15 days** total, with P5 the gating milestone for the standalone rollout.