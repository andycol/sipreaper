# Runbook: XDP enforcer

Operational guide for the `enforcer.xdp` kernel-fastpath drop. Read
[how-it-works.md](how-it-works.md#xdp-fast-path-drop-enforcerxdp) for the design;
this is the do-X-when-Y reference.

## Prerequisites

- Kernel ≥ 5.7 (≥ 5.8 for `CAP_BPF`; older kernels need `CAP_SYS_ADMIN` +
  `CAP_SYS_RESOURCE` instead — edit `sipreaper.service`).
- Kernel BTF at `/sys/kernel/btf/vmlinux`.
- bpffs mounted at `/sys/fs/bpf` (the systemd unit sets
  `RequiresMountsFor=/sys/fs/bpf`; mount manually with
  `sudo mount -t bpf bpf /sys/fs/bpf`).
- Capabilities `CAP_BPF CAP_NET_ADMIN CAP_NET_RAW` (already in the unit).
- A binary built with XDP support:
  `make generate && make build-xdp`.

Run `bench/phase0-hostcheck.sh <iface>` first to confirm all of the above and
whether the NIC supports **native** vs only **generic** XDP.

## Enabling (additive, the safe default)

```yaml
enforcer:
  type: ipset          # base safety net stays
  xdp:
    enabled: true
    interface: eth0    # or leave "" to inherit ingest.pcap.interface
    mode: ""           # auto: native, fall back to generic
    standalone: false  # composite — iptables/ipset AND xdp
```

Restart, then confirm:

```bash
curl -s localhost:8080/api/v1/xdp/status -H "Authorization: Bearer $TOKEN" | jq
# expect: {"attached":true,"mode":"driver", ...}
ip -d link show eth0 | grep -i xdp     # shows prog id + mode
journalctl -u sipreaper | grep 'enforcer: xdp attached'
```

If `enabled: true` but the daemon logs `xdp preflight/attach failed ... staying
on <base>`, XDP **failed open** — traffic is still protected by the base
enforcer. Fix the reported cause and restart. The `XdpSilentlyDegraded` alert
(`deploy/alerts.yml`) catches this.

## Going standalone (after the Phase 5 benchmark passes)

Only after `bench/` proves all three numeric criteria:

```yaml
enforcer.xdp.standalone: true
```

Restart, then flush the now-redundant per-IP rules:

```bash
iptables -F SIPREAPER     # or: ipset flush sipreaper
```

## Verifying it's actually dropping

```bash
# Banned IPs in the kernel map (should match active bans minus whitelist):
bpftool map dump pinned /sys/fs/bpf/sipreaper/banned_v4
# Per-CPU PASS/DROP counters:
bpftool map dump pinned /sys/fs/bpf/sipreaper/stats
# Live DROP vs PASS at the hook (native-mode NICs):
xdpdump -i eth0              # NOTE: often unavailable on generic-mode NICs —
                            # fall back to the stats map + a userspace tcpdump count
```

A correct setup shows DROP for a banned source and PASS for everyone else, and
the `dropped` counter climbing under a flood while `tcpdump` at userspace sees
~0 of that flood.

---

## Incident: XDP attached but legit traffic is being dropped → DETACH NOW

The no-restart kill switch (detaches the program, reverts to the base
enforcer; pinned maps survive):

```bash
curl -XPOST localhost:8080/api/v1/xdp/detach -H "Authorization: Bearer $TOKEN"
# or, without the API:
ip link set dev eth0 xdp off
```

Then disable persistently and restart:

```yaml
enforcer.xdp.enabled: false
```

> `kill -HUP <pid>` does **not** detach XDP — SIGHUP reloads config. Use the
> detach endpoint or `ip link ... xdp off`.

## Incident: map full / `sipreaper_xdp_map_entries` near 1,048,576

New bans return `E2BIG` and only the composite iptables backend absorbs them
(`sipreaper_enforcer_errors_total{op="ban"}` climbs; `XdpMapNearFull` /
`XdpEnforcerBanErrors` fire). Confirm:

```bash
bpftool map dump pinned /sys/fs/bpf/sipreaper/banned_v4 | grep -c 'key:'
```

Fix: raise `MAX_BANS` in `internal/banner/bpf/xdp_ban.c`, bump `schemaVersion`
in `enforcer_linux.go`, run `make generate && make build-xdp`, redeploy (the
daemon unlinks the old pins on the schema bump). Or simply rely on the
composite iptables backend.

## Incident: after a kernel upgrade the program won't load

The daemon logs `xdp load/attach failed` and **degrades to iptables
automatically** (fail-open). To restore the fast path, regenerate the object on
the new kernel and rebuild with XDP support: `make generate && make build-xdp`
(needs clang/LLVM + libbpf-dev + `linux-headers-$(uname -r)`), redeploy.

## Incident: bans in the DB but not in the map (or vice versa)

The startup + 5-minute reconcile self-heals this (DB wins). Inspect:

```bash
curl -s localhost:8080/api/v1/xdp/status -H "Authorization: Bearer $TOKEN" | jq .last_reconcile_removed
# sipreaper_xdp_reconcile_removed_total in Prometheus
```

A restart forces an immediate reconcile.

## Rollback from standalone

```yaml
enforcer.xdp.standalone: false   # (or enabled: false)
```

Restart. `restoreBans` re-populates the iptables/ipset backend from
`ListBans("active")`, so the base enforcer is fully repopulated. If you flushed
the chain when going standalone, the restart re-creates the rules.

## Clearing all XDP bans vs stopping dropping — they're different

- **Clear bans:** `rm -rf /sys/fs/bpf/sipreaper` wipes the kernel map state but
  does **not** detach a running program (so it does NOT stop over-dropping).
- **Stop dropping:** `POST /api/v1/xdp/detach` or `ip link set dev <iface> xdp
  off` detaches the program.
