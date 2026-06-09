# How SIPReaper Works

A narrative explanation of the system end-to-end: what problem it solves, how
a packet becomes a ban, and the design choices that distinguish it from a
generic intrusion-prevention tool.

If you only want to *use* sipreaper, the [README](../README.md) is the right
starting point. This document is for operators and contributors who want to
understand *why* it does what it does.

---

## 1. The problem

A public-facing SIP server (Asterisk, OpenSIPS, Kamailio, FreeSWITCH) is one
of the noisiest endpoints on the internet. Within minutes of bringing one
online you will see:

- **REGISTER brute-force** — automated tools cycling through extension/password
  combinations, sometimes thousands per minute.
- **INVITE floods** — toll-fraud bots looking for misconfigured trunks they
  can use to dial premium-rate numbers.
- **OPTIONS / scanner probes** — `sipvicious`, `sipcli`, `friendly-scanner`,
  custom one-offs, fingerprinting your stack before they attack it.
- **DID / extension enumeration** — slowly probing for valid usernames so the
  attacker can target later passes.
- **Geographic anomalies** — registrations from countries no real user of yours
  has ever been in.

The traditional answer is **fail2ban** with hand-rolled regexes against
`/var/log/asterisk/messages` or `/var/log/kamailio/kamailio.log`. That works,
sort of, but has three real problems:

1. **It's blind to anything not logged.** SIP servers don't log every request;
   most don't log auth challenges by default. A REGISTER brute-force where
   every attempt produces a 401 may produce *zero* log lines.
2. **No protocol understanding.** A regex matches a string. It can't pair a
   401 response back to the IP that sent the request, can't notice that one
   IP is hitting many distinct DIDs, and can't tell `sipvicious` from a
   misbehaving softphone.
3. **All-or-nothing bans.** Whatever fail2ban regex you wrote either fires or
   doesn't. There's no concept of "this is the third time this IP has tried
   in a week — escalate the ban length."

SIPReaper is built around the assumption that for a SIP server, you want
something protocol-aware, multi-signal, and stateful. That changes how each
piece of the pipeline is built.

---

## 2. Pipeline at a glance

```
┌─────────┐   ┌─────────┐
│ pcap    │   │ log     │   Ingest      — get SIP events from the wire
│ capture │   │ tailer  │     and from server logs.
└────┬────┘   └────┬────┘
     │             │
     └──────┬──────┘
            ▼
       ┌─────────┐
       │  dedup  │           Dedup        — collapse the same event seen
       └────┬────┘                          twice (once via pcap, once via log).
            ▼
       ┌─────────┐
       │ detect  │           Detect       — 10 detectors run in parallel,
       └────┬────┘                          each producing zero-or-one threat.
            ▼
       ┌─────────┐
       │ decide  │           Decide       — apply whitelist, look up prior
       └────┬────┘                          bans, choose ban duration.
            ▼
   ┌─────────────────┐
   │ enforce  notify │       Act          — write a firewall rule, send an
   │ persist  metric │                      alert, save to SQLite, bump
   └─────────────────┘                      Prometheus counters.
```

Every stage is a Go channel between goroutines. A panic in any detector
or notifier is recovered (`internal/daemon/daemon.go` `safeDetect`,
`runActionPipeline`) so a single bug can't take the daemon down.

---

## 3. End-to-end: one attack, traced through the system

Suppose a host at `203.0.113.50` starts hammering you with REGISTER attempts
across a range of extensions. Here's what happens.

### 3a. Packet arrives

A REGISTER UDP packet hits your NIC. Either:

- **The pcap capture goroutine** (`internal/ingest/pcap.go`) sees it via
  libpcap. The BPF filter is `udp port 5060 or udp port 5061`, so non-SIP
  traffic never enters userspace. The transport-layer payload is parsed with
  the in-tree SIP parser (`sipparser.go`) — note that `gopacket`'s built-in
  SIP decoder is bypassed, because it consumes headers into struct fields and
  hands back only the message body, which is empty for header-only requests
  like REGISTER. We use the raw UDP payload instead.
- **The log tailer goroutine** (`internal/ingest/logtailer.go`) reads
  `/var/log/opensips.log` (or kamailio's) line by line, like `tail -f`, and
  runs each line through both kamailio and opensips regex parsers — they
  cascade, so a format mismatch never silently drops events.

Both produce the same internal `models.SIPEvent{}` — IP, method, response code
(if any), Call-ID, From-User, To-User, User-Agent, source ("pcap" or "log").

### 3b. Pcap pairs requests with responses

For pcap specifically, requests are stashed by Call-ID into an inflight map
(capped at 100k entries with FIFO eviction; pruned every minute, 5-minute
timeout). When a 401 / 403 / 4xx response from your SIP server flies past,
sipreaper looks it up by Call-ID and synthesises a `Rejected=true` event
attributed to the **original sender's** IP — not the response's source, which
is your own server.

This is the move that gives SIPReaper its highest-confidence signal. Your
SIP server already decided this request was bad (wrong password, no such
extension, blocked by ACL). We take that decision and turn it into actionable
input — without needing the SIP server to log anything.

### 3c. Dedup

Both the log tailer and pcap can see the same event. The dedup cache
(`internal/ingest/dedup.go`) keys on `Call-ID + Method + ResponseCode` with a
5-second window. The first arrival wins; the second is dropped silently.

The response code is part of the key on purpose: the request `REGISTER` and
the synthesised `REGISTER/401` are *different* events to the dedup cache, even
though they share Call-ID + Method.

### 3d. Detection

The deduped event fans out to all enabled detectors. Each runs in the same
goroutine as the pipeline but is wrapped in `safeDetect` so a panic in one
detector doesn't take the others down. A few examples:

| Detector | What it does with this event |
|---|---|
| `brute_force` | If the event is `Method=REGISTER` and `ResponseCode=401\|403`, increments a sliding-window counter for this IP. Returns a threat at 5 hits in 60s. |
| `invite_flood` | Skips — this is a REGISTER, not an INVITE. |
| `scanner` | Inspects the User-Agent. If it matches `sipvicious` / `friendly-scanner` / `sipcli` (case-insensitive), returns a threat *immediately*. Otherwise tracks OPTIONS rate. |
| `geo_anomaly` | Looks the IP up in the GeoLite2 database. If it's outside the allowed-countries list, returns a threat. |
| `user_enum` | Tracks distinct To-User values per source IP. 10 distinct extensions in 60s = threat. |
| `server_rejected` | Triggers on `Rejected=true` events. The SIP server's own rejection signal — single-hit, very high confidence. |
| `did_scanner` | Tracks distinct DIDs (To-User on inbound INVITEs) per source IP. 20 in 5m = threat. |
| `failed_call_ratio` | Tracks failed-vs-total INVITEs per IP. 80%+ failures over 20+ calls in 5m = threat. |
| `honeypot` | If To-User matches a configured decoy extension ("1000", "admin", "test"...), instant threat. |
| `invalid_request` | Empty / unknown SIP method. 3 in 60s = threat. |

Each detector returns either `nil` or one `models.Threat{}`.  Threats are
non-blocking-pushed into the threats channel (dropped if it's full, with a
log line; this is bounded backpressure, not silent failure).

### 3e. Decision

`internal/decision/engine.go::Evaluate` runs for every threat:

1. **Whitelist check.** If the threat's IP is in the static whitelist
   (config file) or dynamic whitelist (SQLite, runtime-managed), log
   `decision: threat from whitelisted IP …, skipping ban` and return `nil`.
   This is the most common reason a "real" attack doesn't lead to a ban —
   accidentally too-broad whitelist entries.
2. **Already-banned check.** If the IP has an active ban already, do
   nothing. Repeated detections during a ban don't extend it.
3. **Escalation.** Count this IP's prior bans within the cooldown window
   (default 48h). The number of prior bans picks the duration from
   `bans.durations`: 1st = 5m, 2nd = 30m, 3rd = 2h, 4th = 24h, 5th+ = permanent.
   Repeat offenders get progressively longer bans automatically.
4. **Persist.** Insert a row into the `bans` table (status `active`, or
   `dry_run` if the engine is in shadow mode).
5. **Emit.** Return a `BanAction{}` for the action pipeline to consume.

### 3f. Action

The action pipeline runs three things per ban:

1. **Enforce.** Call the enforcer (`iptables` or `ipset`).
   - `iptables`: append a `-j DROP` rule in the `SIPREAPER` chain. Linear
     lookup, fine for hundreds of bans.
   - `ipset`: add the IP to a `hash:net` set. The single match-rule that
     jumps to that set is installed once at chain init. Lookup is O(1)
     regardless of size — recommended for thousands of bans.

   In `dry_run` mode this step is **skipped**. The ban is still recorded
   (with status `dry_run`) and metrics still increment, but the firewall is
   never touched. This is the safe way to tune detector thresholds against
   real traffic before turning enforcement on.

2. **Notify.** Each configured notifier gets a copy. `syslog` writes a
   structured line to the system log. `email` sends SMTP if the threat's
   severity is at or above the configured `min_severity`. Failures in one
   notifier don't block the others.

3. **Metric.** `sipreaper_bans_total{detector=...}` and
   `sipreaper_active_bans` are bumped. These are exposed at
   `/metrics` for Prometheus to scrape.

The IP is now blocked at the kernel firewall. The next packet from
`203.0.113.50` to UDP/5060 hits the DROP rule and is silently discarded.
Your SIP server never sees it.

### 3g. Expiry

A ticker (`bans.check_interval`, default 30s) scans for expired bans, calls
`enforcer.Unban` to remove the firewall rule (or the ipset entry), and updates
the row in SQLite. The escalation counter is *not* reset — that requires
`bans.cooldown` (48h) of clean behaviour.

---

## 4. Why each design choice

A few non-obvious decisions and the reasoning behind them.

### Pcap *and* log ingest, both default

Pcap gives you signals the log file doesn't have (e.g., 401 challenges that
aren't logged) and works even if your SIP server crashed and stopped writing
logs. Log ingest catches things pcap can't easily see (e.g., explicit
"Rejected inbound carrier INVITE from non-whitelisted source" lines from
OpenSIPS where the rejection happens at the script level and may not even
emit a SIP response). The dedup cache means running both has no
double-counting cost.

### Synthesising attacker events from server responses

Pairing requests to responses by Call-ID is the single highest-value piece
of logic in the system. It turns "your SIP server emitted a 4xx" — which is
trivial to detect — into "this specific external IP got rejected by your
server", which is the actual fact you want to act on. Without this, you'd
need every SIP server config to log every rejection in a parser-friendly
format, which they don't.

### Sliding window with bounded inflight map

The Call-ID → request map is hard-capped at 100k entries. A scanner that
uses a fresh Call-ID for every probe could otherwise grow this without bound
until the 5-minute prune runs. At ~200 bytes per entry that's ~20 MB worst
case before FIFO eviction kicks in. Bounded memory under adversarial input
is a property of the system, not an implementation detail.

### Constant-time API token compare

`crypto/subtle.ConstantTimeCompare`. A timing oracle on bearer-token
auth would let an attacker brute-force the token byte-by-byte. The cost of
constant-time compare is negligible; the cost of *not* doing it is
catastrophic. So we just do it.

### Escalating bans with cooldown

A 5-minute first ban for a one-off misconfiguration; a permanent ban for the
fifth offence. This rewards "self-correcting" sources (a flaky softphone
that restarts and works) and punishes persistent attackers (the same IP
trying again the moment the ban expires). The cooldown means an IP that
fixes itself is forgiven; it's stateful, not just a counter.

### Pluggable enforcer (iptables vs ipset) plus a kernel pre-filter

Most deployments will live with `iptables`. But if you accumulate thousands
of bans, every packet costs a linear walk through that chain — at some point
this becomes measurable load. `ipset` is O(1) regardless of count; opt in
when ban count starts to matter.

The pre-filter is separate again: it's an `iptables -m hashlimit` rule
installed at the *top* of the chain that drops over-rate INVITEs at the
kernel before userspace even sees them. It does *not* replace the userspace
detector — it's a stopgap that keeps the box upright during volumetric
floods while the detector still earns proper escalating bans for repeat
offenders.

### XDP fast-path drop (`enforcer.xdp`)

iptables/ipset and the hashlimit pre-filter all run in netfilter, at the
`INPUT` hook — which sits *after* two things that matter: the per-CPU NET_RX
softirq has already allocated an `sk_buff`, and the AF_PACKET tap (the same one
`pcap.OpenLive` uses for ingest) has already copied the packet. So a flood still
pays the softirq cost even when every packet is destined for `DROP`, and the
dropped packets still show up in `tcpdump`/`sngrep`.

The optional **XDP enforcer** attaches an eBPF program at the NIC/driver layer
(native XDP) or, where the driver lacks it, in `__netif_receive_skb_core`
(generic XDP). Either way it runs *before* both the softirq sk_buff allocation
and the AF_PACKET tap. A banned source's packets are returned `XDP_DROP` and
simply cease to exist — no softirq, no userspace copy.

**Composite, additive rollout.** XDP does not replace iptables; it joins it. A
`CompositeEnforcer` fans every `Ban`/`Unban` out to both the existing
iptables/ipset backend *and* the XDP map, so enabling it is purely additive and
the proven path stays as a safety net. Only after the Phase 5 benchmark proves
parity-or-better do you flip `standalone: true` and retire the per-IP iptables
rules.

**Safe by construction.** The program only ever returns `XDP_PASS` or
`XDP_DROP` — no redirect, no packet mutation, no L4 dereference. It **fails
open** everywhere: any source not in a ban map, any non-IP EtherType, any VLAN
nesting past depth 2, any bounds-check miss, and any load/attach/preflight
failure all leave traffic flowing (and the daemon on its iptables base). The
v4 map is keyed by the four raw wire bytes of the source address and the Go
side stores `ip.To4()` — the same bytes — so there is *zero* byte-order
reasoning anywhere (the classic XDP endianness bug can't occur).

**The whitelist can never enter the drop map.** Bans reach the enforcer from
three producers — the decision engine, the manual ban API, and `restoreBans`
at startup — and all three skip whitelisted IPs. On top of that, a startup
(and periodic) **reconcile** deletes from the kernel map any entry that is not
an active ban or is now whitelisted.

**DB is authoritative; the map is reconciled to it.** The pinned kernel maps
(under `/sys/fs/bpf/sipreaper`) are a *second* copy of ban state that survives
restarts, but the SQLite store always wins: at every startup the daemon
reconciles the map against `ListBans("active")` minus the whitelist before
re-applying anything. A schema-version stamp guards against an incompatible
pinned layout (the daemon unlinks and recreates rather than failing closed).
`rm -rf /sys/fs/bpf/sipreaper` clears the kernel ban state but does **not**
detach a running program — to *stop dropping* use `kill -HUP` is **not** it
(HUP reloads config); use `POST /api/v1/xdp/detach` or `ip link set dev <iface>
xdp off`.

**Two behavioral changes you accept by turning it on:**

1. **Detection blindness.** Because XDP drops before the AF_PACKET tap,
   sipreaper's own detectors stop seeing a source once it's banned — so
   recidivism/escalation counting can't re-trigger on an already-banned IP.
   That's fine (it's already banned), but it is a semantic change. (An iptables
   `INPUT` DROP has the same effect relative to the tap, so this isn't unique
   to XDP.)
2. **Mid-stream TCP/TLS teardown.** `XDP_DROP` on a banned source kills its
   in-flight TCP/TLS (SIP-over-TLS, 5061) connections abruptly — identical to
   an iptables DROP.

See `docs/runbook-xdp.md` for enabling, verifying (`bpftool`/`xdpdump`/stats),
the kill switch, and rollback.

### Dry-run / shadow mode

A common reason fail2ban deployments end in tears is that someone tunes the
regex too hot and bans half their customers. SIPReaper's `enforcer.dry_run:
true` runs the entire pipeline — events, detectors, decision, persistence,
notifications, metrics — except for the actual firewall write. You can run
it for a week and read `sipreaper bans --status dry_run` to see what would
have been banned, then tune thresholds before flipping it to live.

### Two-tier whitelist with bidirectional guards

Static whitelist (config file, declarative, survives anything) and dynamic
whitelist (SQLite, runtime-managed via CLI/API). Both accept IPs and CIDRs.
The bidirectional guards are the interesting bit:

- Trying to **whitelist an IP that's currently banned** returns HTTP 409
  unless `--clear-ban` is passed. Otherwise you'd silently end up with a
  ban rule still in iptables and an "I'm whitelisted" entry in SQLite —
  the foot-gun that fail2ban operators eventually all hit.
- Trying to **manually ban an IP that's whitelisted** also returns 409.
  Same idea, opposite direction.

Both checks are cheap and prevent classes of operational mistakes.

### Bounded channels with explicit drop logging

The events and threats channels are fixed-size buffered. If a downstream
goroutine stalls, producers don't block — they drop and log. This trades
"100% delivery" for "the rest of the system stays responsive". Under attack
conditions, that's almost always the right tradeoff.

### Structured logging with `zerolog` everywhere

Old `log.Printf` call sites are routed through zerolog (see
`internal/logging/`). Output is either pretty for `journalctl -u sipreaper -f`
during dev, or single-line JSON for log shippers (Loki, Vector, Filebeat).
There is no half-text, half-JSON middle ground.

### Prometheus metrics, no auth on /metrics or /healthz

Both endpoints are intentionally unauthenticated — Prometheus and orchestrator
liveness probes don't want to deal with bearer tokens. Everything else
requires `Authorization: Bearer <token>` and the compare is constant-time.

---

## 5. Operational properties

Things that fall out of the design and matter for running it in production.

### Crash safety

Active bans, dynamic whitelist entries, and ban history all live in SQLite
(WAL mode, single-writer, busy timeout 5s). On startup, every active ban is
re-applied to the firewall — so if the daemon crashes and is restarted,
nothing falls off. Dry-run records are persisted but **not** re-applied:
they're for tuning, not for enforcement.

### SIGHUP reload

The static whitelist, detector thresholds, and notifier configuration can be
reloaded without restarting the daemon: `kill -HUP $(pgrep sipreaper)`.
The pcap/log ingesters are not reloaded — for those you do need a restart,
because libpcap handles and tailed file descriptors are bound at start.

### Observability

- `sipreaper_events_total{source,method}` — input rate, broken down by
  ingest source. Dropping to zero on `source=pcap` is a fast smoke alarm.
- `sipreaper_threats_total{detector,severity}` — what the detectors are
  actually firing on. Useful for tuning.
- `sipreaper_bans_total{detector}` — bans by detector. If one detector is
  doing all the work, the others may be misconfigured.
- `sipreaper_active_bans` — gauge of the current iptables/ipset population.
- `sipreaper_log_lines_matched_total` / `_unmatched_total` — log-tailer
  health. If `unmatched` is growing without `matched` growing, your SIP
  server's log format probably changed under you.
- `sipreaper_enforcer_errors_total{op}` — firewall calls that failed.
  Should always be zero in steady state.
- `sipreaper_detector_panics_total{component}` — bug indicator. Should
  always be zero.
- `sipreaper_xdp_attached{mode}` — 1 while the XDP program is attached
  (`mode=driver`/`generic`). **The critical silent-degradation signal:** if
  `enforcer.xdp.enabled` is true but this is 0, XDP failed open to iptables.
- `sipreaper_xdp_map_entries{family}` — live IP count in each ban map; alert
  near the 1,048,576-entry cap.
- `sipreaper_xdp_packets{result}` — cumulative `passed`/`dropped` packet counts
  the kernel program maintains; `dropped` is the headline value-prop metric.
- `sipreaper_xdp_reconcile_removed_total` — map entries evicted by reconcile
  (stale or newly-whitelisted); surfaces DB↔map drift.

`deploy/alerts.yml` ships Prometheus rules for these, led by
`XdpSilentlyDegraded`.

### Hardening

- Bounded inflight pcap map (DoS-resistant).
- Bounded events / threats channels (backpressure with explicit drop, not
  unbounded queueing).
- Panic recovery wrappers around every detector, the action pipeline, and
  the pcap goroutine itself — a single bad packet can't kill the daemon.
- Constant-time API token compare.
- Config validation at startup: empty ingest, zero windows, unknown
  enforcer type, missing `bans.durations` — refused with a clear error
  before the daemon goes live.
- libpcap snaplen is 65535, capture is non-promiscuous (we only want
  packets to/from this host), `BlockForever` for predictable scheduling.

---

## 6. Why this is a good tool

In one paragraph: SIPReaper turns a SIP server's own rejection decisions
into automatic firewall actions, with an order-of-magnitude richer signal
set than fail2ban can produce, persistence and escalation that match how
attackers actually behave (they retry), and a dry-run path so you can tune
it without breaking your users. It's purpose-built for SIP, but the
internals are written like a normal Go service — channels, goroutines,
SQLite, Prometheus, structured logging, REST API — so on-call rotation
doesn't need a SIP-specific mental model to operate it.

Concretely:

- **Catches what fail2ban can't.** Pairing pcap-side requests to responses
  attributes server-side rejections back to the attacker without needing
  the SIP server to log anything.
- **Escalating bans match real attacker behaviour.** A first-time banned
  IP gets 5 minutes; the same IP back for a fifth offence gets banned
  permanently. Persistent attackers run out of road.
- **Dry-run mode.** Run the whole detection pipeline against real traffic
  for a week, inspect what *would* have been banned, then turn it on. No
  guessing.
- **Two-tier whitelist with guards.** Static + dynamic, both supporting
  CIDRs, with HTTP 409 errors that prevent the classic "whitelisted but
  still banned" foot-gun.
- **Pluggable enforcement.** iptables for small deployments, ipset for
  large ones, kernel hashlimit pre-filter for floods. Pick the right
  weapon for the threat shape.
- **Operationally normal.** Prometheus, structured JSON logs,
  unauthenticated `/healthz` and `/metrics`, bearer-token auth with
  constant-time compare on everything else, SIGHUP reload, systemd-friendly
  service file. Nothing exotic.
- **Hardened internals.** Bounded memory, panic recovery on every hot
  path, config validation at startup, SQLite WAL, single-writer connection
  cap. It's designed to *stay up*, even when the thing it's defending
  against is actively trying to take it down.
