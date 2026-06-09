<img width="1254" height="1254" alt="image" src="https://github.com/user-attachments/assets/23df436c-fe0a-4fc5-8a9e-87536ae64754" />


SIP attack detection and automatic IP banning for Kamailio and OpenSIPS. Think fail2ban, but purpose-built for SIP with deep protocol awareness, configurable thresholds, and a management API.

For a narrative explanation of how the system works end-to-end and the design choices behind it, see [`docs/how-it-works.md`](docs/how-it-works.md).

## Features

- **Dual ingest** — log files (kamailio + opensips formats, auto-cascade) and live packet capture
- **10 detection engines** — brute force, INVITE flood, scanner, invalid requests, geo-anomaly, user enumeration, **server_rejected**, **honeypot**, **failed_call_ratio**, **did_scanner**
- **Pcap response pairing** — 4xx responses are attributed back to the original sender via Call-ID, so SIP-server rejections become high-confidence threats automatically
- **Configurable thresholds** — per-detector enable/disable, rate limits, and time windows
- **Two-tier whitelist** — static (config file) and dynamic (runtime via CLI/API), supports IPs and CIDRs, with guards against accidentally banning whitelisted IPs and against whitelisting still-banned IPs
- **Escalating bans** — repeat offenders get progressively longer bans (5m → 30m → 2h → 24h → permanent)
- **Pluggable enforcement** — `iptables` and `ipset` (O(1) lookup), with optional **kernel-side INVITE pre-filter** (`hashlimit`) to absorb floods before userspace
- **Pluggable notifications** — syslog and email (SMTP) built-in, with severity filtering
- **Dry-run / shadow mode** — record would-be bans without touching the firewall, for safe threshold tuning against real traffic
- **REST API + CLI** — full management API with bearer token auth (constant-time compare); the `sipreaper` CLI wraps every operation, plus `sipreaper test-line` for diagnosing log lines
- **Observability** — Prometheus `/metrics`, unauthenticated `/healthz`, structured (JSON) logging via zerolog, sampled debug log of unmatched lines
- **Hardened internals** — bounded pcap inflight map (DoS-resistant), goroutine panic recovery, SQLite WAL + busy timeout, config validation at startup
- **SQLite persistence** — bans, events, and whitelist survive restarts
- **SIGHUP reload** — reload config without restarting the daemon

## Quick Start

```bash
# Build
make build

# Copy and edit the config
sudo mkdir -p /etc/sipreaper /var/lib/sipreaper
sudo cp config.example.yaml /etc/sipreaper/config.yaml
sudo vim /etc/sipreaper/config.yaml

# Set required environment variables
export SIPREAPER_API_TOKEN="your-secret-token"
export SIPREAPER_SMTP_PASS="your-smtp-password"  # if email notifications enabled

# Run the daemon
sudo ./sipreaper daemon --config /etc/sipreaper/config.yaml
```

## Building from Source

### Prerequisites

- Go 1.22 or later
- libpcap development headers
- C compiler (required by go-sqlite3 and gopacket)

**Debian/Ubuntu:**
```bash
sudo apt-get install -y libpcap-dev gcc
```

**RHEL/CentOS/Rocky:**
```bash
sudo yum install -y libpcap-devel gcc
```

**macOS:**
```bash
# libpcap is included with macOS, no extra install needed
xcode-select --install  # for C compiler if not present
```

### Build

```bash
git clone https://github.com/andycol/sipreaper.git
cd sipreaper
make build
```

This produces a `sipreaper` binary in the project root. The compiled XDP
backend is intentionally excluded from the default binary, so `make build`
needs only the runtime toolchain above — **not** the eBPF toolchain. This is
the recommended build for normal OpenSIPS deployments using `iptables` or
`ipset`.

### Building With XDP (optional)

You only need this if you want the optional kernel-fastpath XDP backend. It
requires clang/LLVM ≥ 11, libbpf headers and kernel headers, and runs only on
Linux:

**Debian/Ubuntu:**
```bash
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
make generate
make build-xdp
```

**RHEL/CentOS/Rocky:**
```bash
sudo yum install -y clang llvm libbpf-devel kernel-headers bpftool
make generate
make build-xdp
```

The generated `internal/banner/bpf_bpf*.{go,o}` files are local build artifacts
for XDP-enabled binaries.

### Run Tests

```bash
make test
```

The XDP load/attach/classification tests (`internal/banner`) are Linux-only and
only compile in XDP builds; run them privileged to exercise the kernel path:
`sudo -E go test -tags xdp ./internal/banner/ -run TestClassification`.

## Configuration

SIPReaper uses a single YAML config file. See [`config.example.yaml`](config.example.yaml) for a fully annotated reference.

### Ingest

Configure where SIPReaper reads SIP traffic from.

```yaml
ingest:
  log:
    enabled: true
    path: "/var/log/kamailio/kamailio.log"
    format: "kamailio"       # kamailio | opensips
  pcap:
    enabled: true
    interface: "eth0"
    ports: [5060, 5061]
    bpf_filter: ""           # optional custom BPF override
```

- **Log tailer** reads Kamailio or OpenSIPS log files and extracts SIP events using regex patterns. It tails the file (like `tail -f`) so it only processes new entries.
- **Pcap capture** sniffs SIP packets directly off the wire using libpcap. A BPF filter restricts capture to SIP ports.
- Both can run simultaneously. A deduplication cache (5s window, keyed on Call-ID + Method) prevents the same event being processed twice.

### Detectors

Each detector can be independently enabled/disabled and has its own threshold configuration.

```yaml
detectors:
  brute_force:
    enabled: true
    max_attempts: 5          # failed REGISTERs (401/403) before ban
    window: 60s

  invite_flood:
    enabled: true
    max_requests: 50         # INVITEs per IP before ban
    window: 10s

  scanner:
    enabled: true
    max_probes: 10           # OPTIONS probes before ban
    window: 30s
    known_agents:            # immediate ban on match (case-insensitive)
      - "friendly-scanner"
      - "sipcli"
      - "sipvicious"

  invalid_request:
    enabled: true
    max_invalid: 3           # invalid SIP methods before ban
    window: 60s

  geo_anomaly:
    enabled: true
    allowed_countries: ["GB", "US"]
    geoip_db: "/usr/share/GeoIP/GeoLite2-Country.mmdb"

  user_enum:
    enabled: true
    max_extensions: 10       # distinct To-User targets before ban
    window: 60s

  # The SIP server's own rejection signal — the highest-confidence threat there
  # is. Catches things like "Rejected inbound carrier INVITE from non-whitelisted
  # source 1.2.3.4 for DID …" with a single hit.
  server_rejected:
    enabled: true
    max_hits: 1
    window: 5m

  # Decoy extensions / DIDs no real user dials. First request to any of these
  # bans the source. Zero false positives.
  honeypot:
    enabled: false
    extensions: ["1000", "0000", "admin", "test"]

  # Toll-fraud reconnaissance: high failure rate on outbound INVITEs from one IP.
  failed_call_ratio:
    enabled: false
    min_calls: 20            # need this many INVITEs in window before evaluating
    min_ratio: 0.8           # 80%+ failed = threat
    window: 5m

  # One IP reaching for many distinct DIDs in a short window — dial-plan probing.
  did_scanner:
    enabled: false
    max_dids: 20
    window: 5m
```

**Detector details:**

| Detector | Triggers on | Default | Severity |
|---|---|---|---|
| `brute_force` | Failed REGISTER (401/403) responses per IP | 5 in 60s | high |
| `invite_flood` | INVITE request rate per IP | 50 in 10s | high |
| `scanner` | Known tool user-agents (immediate) or OPTIONS probe rate | 10 in 30s | high/medium |
| `invalid_request` | Unknown SIP methods or empty method field | 3 in 60s | medium |
| `geo_anomaly` | Requests from countries not in the allowed list | any | medium |
| `user_enum` | Distinct To-User (extension) targets from one IP | 10 in 60s | high |
| `server_rejected` | SIP server emitted a 4xx / "rejected" log line for this source | 1 in 5m | high |
| `honeypot` | Traffic to a configured decoy extension | 1 hit | high |
| `failed_call_ratio` | High failed:total INVITE ratio over a meaningful sample | 80% of 20 in 5m | high |
| `did_scanner` | One IP targeting many distinct DIDs (called numbers) | 20 DIDs in 5m | high |

The `server_rejected` detector pulls from two sources automatically:

- **Log tailer**: matches OpenSIPS/Kamailio rejection lines (e.g. `Rejected inbound carrier INVITE from non-whitelisted source 1.2.3.4 for DID …`). The parsers cascade — kamailio + opensips are tried for every line regardless of the configured `format` — so a format mismatch no longer silently drops events.
- **Pcap**: tracks request → final-response pairs by Call-ID. When the SIP server emits a 4xx, sipreaper synthesises an event attributed to the *original sender*, with `Rejected=true`. No log scraping required.

### Whitelist

Whitelisted IPs are never banned, but their activity is still logged for visibility.

```yaml
whitelist:
  static:
    - ip: "10.0.0.0/8"
      comment: "Internal network"
    - ip: "203.0.113.50"
      comment: "SIP trunk provider"
```

Static entries are loaded from the config file. Dynamic entries can be added at runtime via CLI or API and are stored in SQLite.

Both support single IPs (`203.0.113.50`) and CIDR ranges (`10.0.0.0/8`).

### Ban Escalation

Repeat offenders get progressively longer bans. The escalation counter resets after a cooldown period.

```yaml
bans:
  durations: [5m, 30m, 2h, 24h, 0]  # 0 = permanent
  cooldown: 48h                       # reset after 48h clean
  check_interval: 30s                 # how often to check for expired bans
```

| Offence | Duration |
|---|---|
| 1st ban | 5 minutes |
| 2nd ban | 30 minutes |
| 3rd ban | 2 hours |
| 4th ban | 24 hours |
| 5th+ ban | permanent |

### Enforcement

```yaml
enforcer:
  type: "iptables"           # iptables | ipset
  chain: "SIPREAPER"
  set_name: "sipreaper"      # only used when type=ipset

  # Dry-run / shadow mode — record would-be bans, fire notifiers, increment
  # metrics, but never touch the firewall. Use for a week to tune detector
  # thresholds against your real traffic. Records show up in the store with
  # status=dry_run.
  dry_run: false

  # Kernel-side per-IP INVITE rate limit. Drops volumetric INVITE floods at the
  # firewall *before* userspace sees them. Defaults off.
  prefilter:
    enabled: false
    rate: 5                  # INVITEs per second per source IP
    burst: 10
    ports: [5060, 5061]

  # XDP kernel-fastpath drop. Drops banned IPs at the NIC/driver layer
  # (XDP_DROP), before netfilter AND before the AF_PACKET tap. Additive and
  # fail-open: if it can't attach, the daemon stays on `type` above.
  # See docs/runbook-xdp.md. Needs kernel >= 5.7, bpffs, CAP_BPF+CAP_NET_ADMIN.
  xdp:
    enabled: false
    interface: ""            # default: ingest.pcap.interface
    mode: ""                 # "" auto (native->generic) | native | generic
    standalone: false        # true = ONLY backend (after Phase 5 benchmark)
```

**Three enforcer backends:**

- **`iptables`** (default): one `-j DROP` rule per banned IP, in a dedicated `SIPREAPER` chain linked from `INPUT`. Simple, universal. Linear lookup per packet — fine up to a few thousand bans.
- **`ipset`**: a single `hash:net` set; one match-rule jumps to it. Lookup is O(1) regardless of ban count. Recommended for any production deployment that's likely to accumulate >1k bans. Requires the `ipset` binary on the host.

- **`xdp`** (optional, layered via `enforcer.xdp.enabled`, requires a binary built with `make build-xdp`): an eBPF program at the NIC/driver layer that returns `XDP_DROP` for banned source IPs *before* netfilter and *before* the AF_PACKET tap, so a flood pays no softirq cost and dropped packets never reach `tcpdump`/userspace. Rollout is **additive** — a composite enforcer applies each ban to both the iptables/ipset backend AND the XDP map, with iptables as the safety net — and **fail-open**: any load/attach failure leaves the base backend in charge. Flip `standalone: true` only after the `bench/` benchmark proves parity. See [docs/runbook-xdp.md](docs/runbook-xdp.md). Two accepted behavioral changes: detection-blindness on already-banned IPs, and abrupt mid-stream TCP/TLS teardown — both documented in the runbook. Inspect at runtime via `GET /api/v1/xdp/status`; kill switch is `POST /api/v1/xdp/detach`.

Either backend can be paired with the **prefilter** (an iptables `-m hashlimit` rule installed at chain init that drops INVITEs above `rate` per source IP). Userspace detection still runs on whatever traffic isn't dropped, so repeat offenders still earn a proper escalating ban.

On startup, active bans from SQLite are re-applied (and, for XDP, the pinned map is reconciled against the DB — the DB always wins). `dry_run` records are skipped; whitelisted IPs are skipped and marked expired.

### Notifications

```yaml
notifiers:
  syslog:
    enabled: true
  email:
    enabled: true
    smtp_host: "smtp.example.com"
    smtp_port: 587
    tls: true
    from: "sipreaper@example.com"
    to: ["admin@example.com"]
    username: "sipreaper@example.com"
    password_env: "SIPREAPER_SMTP_PASS"  # reads password from env var
    min_severity: "medium"               # only email for medium+ threats
```

The SMTP password is read from an environment variable (not the config file) to avoid storing secrets in plain text.

### API

```yaml
api:
  listen: "127.0.0.1:8080"
  token_env: "SIPREAPER_API_TOKEN"       # reads token from env var
```

The API only listens on localhost by default. Change the listen address if you need remote access (and ensure you're behind a firewall or VPN).

Token compares are constant-time. The daemon refuses to start if the configured token environment variable is missing. `/healthz` and `/metrics` are intentionally **unauthenticated** so monitoring probes and Prometheus scrape jobs don't need to hold the bearer token; everything else requires `Authorization: Bearer <token>`.

### Storage

```yaml
storage:
  path: "/var/lib/sipreaper/sipreaper.db"
  event_retention: 168h
```

SQLite is opened with WAL journal mode, `busy_timeout=5000`, `synchronous=NORMAL`, and a single-writer connection cap. This eliminates `database is locked` under bursty traffic.

Stored data: bans (incl. `dry_run` records), recent event evidence, dynamic whitelist entries. `event_retention` controls how long SIP event evidence is kept for drilldown/debugging; set it to `0s` to disable pruning.

### Logging

```yaml
logging:
  level: "info"              # trace | debug | info | warn | error
  output: "stdout"           # stdout | stderr | console | file
  file: "/var/log/sipreaper/sipreaper.log"   # only used when output=file
```

Output formats:

- `stdout` / `stderr` / `file` — JSON, one event per line. The right shape for log shippers (Loki, Vector, Filebeat).
- `console` — colourised pretty output. Good for `journalctl -u sipreaper -f` during dev / rollout.

Existing `log.Printf` call sites are routed through zerolog so even older code paths emit timestamped, levelled output.

### Config validation

The daemon refuses to start if the config is obviously broken — empty ingest, zero windows, unknown enforcer type, missing `bans.durations`, etc. You'll see the error at startup, not silently in production.

## Usage

### Daemon

```bash
# Start with default config location
sudo sipreaper daemon

# Start with custom config
sudo sipreaper daemon --config /path/to/config.yaml

# Reload config without restart (from another terminal)
sudo kill -HUP $(pgrep sipreaper)
```

### Ban Management

```bash
# List active bans
sipreaper bans

# List all bans (including expired)
sipreaper bans --all

# Manually ban an IP for 1 hour
sipreaper ban 203.0.113.100 1h

# Manually ban an IP permanently (no duration = permanent)
sipreaper ban 203.0.113.100

# Unban an IP
sipreaper unban 203.0.113.100
```

### Whitelist Management

```bash
# List whitelisted IPs
sipreaper whitelist

# Add an IP to the dynamic whitelist
sipreaper whitelist add 198.51.100.0/24 --comment "Partner SIP trunk"

# Add an IP that's currently banned — clears the ban first
sipreaper whitelist add 203.0.113.50 --clear-ban --comment "false positive"

# Remove from whitelist
sipreaper whitelist remove 198.51.100.0/24
```

The daemon refuses (HTTP 409) to whitelist an IP that is currently banned unless `--clear-ban` is set. This avoids the silent foot-gun of whitelisting an IP whose firewall rule is still in place. Symmetrically, manual bans (`sipreaper ban …`) are refused with HTTP 409 if the IP is in the static or dynamic whitelist.

### Monitoring

```bash
# Check daemon status
sipreaper status

# View detection statistics (includes log_tailer matched/unmatched counts)
sipreaper stats

# Query recent stored event evidence
sipreaper events --last 1h

# Filter events by IP
sipreaper events --ip 203.0.113.100

# Filter events by detector
sipreaper events --detector brute_force

# Inspect dry-run records (would-be bans during a tuning window)
sipreaper bans --status dry_run

# Unauthenticated probes for orchestration / monitoring
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/metrics
```

### Diagnosing log lines

`test-line` runs a single line through every parser and prints what was extracted, so you can confirm a particular log message will produce a ban-worthy event before deploying a config change:

```bash
# Single line
sipreaper test-line "WARNING:Rejected inbound carrier INVITE from non-whitelisted source 77.68.33.97 for DID 64300441975359019"

# Bulk: pipe a recent log file through and find lines no parser is matching
tail -n 5000 /var/log/opensips.log | sipreaper test-line --stdin | grep "NO MATCH"
```

Successful matches print a JSON object (`parser`, `source_ip`, `method`, `rejected`, `to_user`, etc.). Unmatched lines print `NO MATCH: <line>`.

### Global Flags

All CLI commands (except `daemon`) connect to the running daemon's API:

```bash
# Custom API address
sipreaper --api-addr http://10.0.0.1:8080 status

# Pass API token directly (alternative to SIPREAPER_API_TOKEN env var)
sipreaper --api-token mysecret bans
```

## REST API

All `/api/v1/*` endpoints require `Authorization: Bearer <token>`. `/healthz` and `/metrics` are unauthenticated.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/status` | yes | Daemon health, uptime, active ban count |
| `GET` | `/api/v1/bans` | yes | List bans. Defaults to `status=current` (`active` + `manual`). Query params: `status` (`current`/`active`/`expired`/`manual`/`dry_run`), `ip` |
| `POST` | `/api/v1/bans` | yes | Manual ban. Body: `{"ip": "1.2.3.4", "duration": "1h"}`. Applies the firewall rule before returning success. Returns **409** if IP is whitelisted or already banned, **400** if invalid. |
| `DELETE` | `/api/v1/bans/{ip}` | yes | Unban an IP from the active enforcer and mark its ban expired |
| `GET` | `/api/v1/whitelist` | yes | List whitelist entries |
| `POST` | `/api/v1/whitelist` | yes | Add to whitelist. Body: `{"ip": "10.0.0.0/8", "comment": "...", "clear_ban": false}`. Returns **409** if the IP/CIDR overlaps current bans unless `clear_ban: true`; accepts both single IPs and CIDRs. |
| `DELETE` | `/api/v1/whitelist/{ip-or-cidr}` | yes | Remove from whitelist (and reload running engine) |
| `GET` | `/api/v1/events` | yes | Query stored event evidence. Params: `ip`, `detector`, `last` (duration) |
| `GET` | `/api/v1/stats` | yes | Detection stats, bans by detector, top offenders, log-tailer matched/unmatched counts |
| `GET` | `/api/v1/xdp/status` | yes | XDP enforcer status: `attached`, `mode`, `map_entries_v4/v6`, `packets_passed/dropped`, `last_reconcile_removed` |
| `POST` | `/api/v1/xdp/detach` | yes | No-restart kill switch: detach XDP, revert to the base enforcer |
| `GET` | `/healthz` | no | Subsystem health (store, log tailer, enforcer, xdp). 503 only on hard-down; `degraded:` checks (e.g. XDP enabled-but-not-attached) stay non-fatal. |
| `GET` | `/metrics` | no | Prometheus exposition format |

### Prometheus metrics

| Metric | Type | Labels |
|---|---|---|
| `sipreaper_events_total` | counter | `source` (log/pcap), `method` |
| `sipreaper_threats_total` | counter | `detector`, `severity` |
| `sipreaper_bans_total` | counter | `detector` |
| `sipreaper_unbans_total` | counter | — |
| `sipreaper_active_bans` | gauge | — |
| `sipreaper_log_lines_matched_total` | counter | — |
| `sipreaper_log_lines_unmatched_total` | counter | — |
| `sipreaper_enforcer_errors_total` | counter | `op` (ban/unban) |
| `sipreaper_detector_panics_total` | counter | `component` (detector name or `action_pipeline`) |
| `sipreaper_xdp_attached` | gauge | `mode` (driver/generic) — the silent-degradation signal |
| `sipreaper_xdp_map_entries` | gauge | `family` (v4/v6) |
| `sipreaper_xdp_packets` | gauge | `result` (passed/dropped) — cumulative |
| `sipreaper_xdp_reconcile_removed_total` | counter | — |

Prometheus alert rules for the XDP layer ship in [`deploy/alerts.yml`](deploy/alerts.yml) (led by `XdpSilentlyDegraded`).

### Examples

```bash
# Check status
curl -H "Authorization: Bearer $SIPREAPER_API_TOKEN" http://127.0.0.1:8080/api/v1/status

# List active bans
curl -H "Authorization: Bearer $SIPREAPER_API_TOKEN" http://127.0.0.1:8080/api/v1/bans

# List dry-run records (during a tuning window)
curl -H "Authorization: Bearer $SIPREAPER_API_TOKEN" \
  "http://127.0.0.1:8080/api/v1/bans?status=dry_run"

# Manual ban
curl -X POST -H "Authorization: Bearer $SIPREAPER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.100", "duration": "2h"}' \
  http://127.0.0.1:8080/api/v1/bans

# Add to whitelist (refused with 409 if 10.0.0.5 is currently banned)
curl -X POST -H "Authorization: Bearer $SIPREAPER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.0/8", "comment": "Internal"}' \
  http://127.0.0.1:8080/api/v1/whitelist

# Whitelist a currently-banned IP, atomically clearing the ban
curl -X POST -H "Authorization: Bearer $SIPREAPER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.50", "comment": "false positive", "clear_ban": true}' \
  http://127.0.0.1:8080/api/v1/whitelist

# Health & metrics — no token required
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/metrics
```

### Generating an API token

There's no token generator — sipreaper compares the env var to the `Authorization: Bearer …` header. Any high-entropy random string works:

```bash
openssl rand -base64 32        # 256 bits, plenty
# or
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Place it in `/etc/sipreaper/env` (mode 600) so systemd picks it up. Use a different token per host — a leaked token only compromises that host's bans/whitelist.

## Deployment

### Requirements

- Linux (for iptables enforcement and pcap capture)
- `CAP_NET_RAW` capability (for pcap) or run as root
- `CAP_NET_ADMIN` capability (for iptables) or run as root
- MaxMind GeoLite2-Country database (if geo_anomaly detector is enabled)
- **For `enforcer.xdp` only:** build with `make generate && make build-xdp`; kernel ≥ 5.7, kernel BTF, bpffs at `/sys/fs/bpf`, and `CAP_BPF` + `CAP_NET_ADMIN` (on kernels < 5.8, `CAP_SYS_ADMIN` + `CAP_SYS_RESOURCE` instead of `CAP_BPF`). The shipped `sipreaper.service` already declares these and `RequiresMountsFor=/sys/fs/bpf`; they're inert when XDP is disabled. Run `bench/phase0-hostcheck.sh <iface>` to verify support.

### systemd Service

Create `/etc/systemd/system/sipreaper.service`:

```ini
[Unit]
Description=SIPReaper - SIP Attack Detection and Banning
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sipreaper daemon --config /etc/sipreaper/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Environment
EnvironmentFile=-/etc/sipreaper/env
# Or set directly:
# Environment=SIPREAPER_API_TOKEN=your-token
# Environment=SIPREAPER_SMTP_PASS=your-password

# Security
User=root
# Or use capabilities instead of root:
# User=sipreaper
# AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
# CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
# For enforcer.xdp, add CAP_BPF and (under ProtectSystem=strict) bpffs RW:
# AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
# ReadWritePaths=/var/lib/sipreaper /sys/fs/bpf
# RequiresMountsFor=/sys/fs/bpf
# (the repo's sipreaper.service already includes these)

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/sipreaper
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Create `/etc/sipreaper/env`:

```bash
SIPREAPER_API_TOKEN=your-secret-token-here
SIPREAPER_SMTP_PASS=your-smtp-password-here
```

Secure the env file:

```bash
sudo chmod 600 /etc/sipreaper/env
```

Install and start:

```bash
sudo cp sipreaper /usr/local/bin/
sudo mkdir -p /etc/sipreaper /var/lib/sipreaper
sudo cp config.example.yaml /etc/sipreaper/config.yaml
# Edit config as needed
sudo systemctl daemon-reload
sudo systemctl enable sipreaper
sudo systemctl start sipreaper
sudo systemctl status sipreaper
```

### Running with Capabilities (Non-Root)

If you prefer not to run as root:

```bash
sudo useradd -r -s /usr/sbin/nologin sipreaper
sudo chown sipreaper:sipreaper /var/lib/sipreaper
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/sipreaper
```

Then update the systemd service to use `User=sipreaper`.

### GeoIP Database Setup

The geo_anomaly detector requires a MaxMind GeoLite2-Country database.

1. Create a free MaxMind account at https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2-Country.mmdb
3. Place it at the path configured in `geoip_db` (default: `/usr/share/GeoIP/GeoLite2-Country.mmdb`)

To keep it updated, use MaxMind's `geoipupdate` tool:

```bash
sudo apt-get install -y geoipupdate
# Configure /etc/GeoIP.conf with your MaxMind account ID and license key
sudo geoipupdate
```

### File Layout

```
/usr/local/bin/sipreaper          # binary
/etc/sipreaper/config.yaml        # configuration
/etc/sipreaper/env                # environment variables (secrets)
/var/lib/sipreaper/sipreaper.db   # SQLite database
/var/log/sipreaper/sipreaper.log  # log file (if configured)
```

### Verifying It Works

After starting the daemon:

```bash
# Check the daemon is running
sipreaper status

# Subsystem health (no token needed)
curl -s http://127.0.0.1:8080/healthz | jq

# Check logs (JSON if logging.output=stdout/file, pretty if console)
sudo journalctl -u sipreaper -f

# Confirm log lines are being parsed (matched should climb when traffic flows)
sipreaper stats | jq .log_tailer

# Sanity-check the parsers against your real log format
tail -n 200 /var/log/opensips.log | sipreaper test-line --stdin | grep "NO MATCH"

# Verify the firewall chain / set was created
sudo iptables -L SIPREAPER -n          # iptables enforcer
sudo ipset list sipreaper              # ipset enforcer

# Test a manual ban/unban
sipreaper ban 192.0.2.1 5m
sudo iptables -L SIPREAPER -n          # should show the DROP rule (or ipset member)
sipreaper unban 192.0.2.1
sudo iptables -L SIPREAPER -n          # rule should be gone

# Tuning workflow with dry-run mode:
#   1. set enforcer.dry_run: true in config
#   2. restart daemon
#   3. let it run for a representative window (a day, a week)
#   4. inspect would-be bans:
sipreaper bans --status dry_run
#   5. tune detector thresholds in config based on what you see
#   6. set dry_run: false and restart
```

### Firewall Considerations

SIPReaper adds rules to its own iptables chain. Make sure your existing firewall rules don't conflict:

- The `SIPREAPER` chain is inserted at the top of `INPUT`
- Only `DROP` rules are added (no `REJECT`)
- Rules target specific source IPs only
- The chain is synced with SQLite on startup, so stale rules are cleaned up

If you're using `ufw` or `firewalld`, they should coexist fine since SIPReaper manages its own chain.

## Architecture

```
Ingest                                   Detection                Decision               Action
──────                                   ─────────                ────────               ──────
log tailer  ┐                                                                          ┌─ iptables / ipset
            ├─→ Dedup ──→ Events ──→ 10 detectors ──→ Threats ──→ Engine ──→ Bans ─┼─ notifiers (syslog,email)
pcap        ┘                              │                  (whitelist +          └─ store (SQLite)
                                           │                   escalation)
                                  panic recovery                    │
                                                                  (dry-run skips enforcer)
```

- All components communicate through Go channels. Each detector runs in the detection goroutine; `safeDetect` wraps each call so a panic in one detector doesn't take the others down.
- The pcap layer pairs requests with their final responses by `Call-ID` and synthesises `Rejected=true` events on 4xx/5xx, attributing them back to the original sender. The inflight Call-ID map is bounded (100k entries) with FIFO eviction to stay DoS-resistant.
- SQLite provides persistence across restarts. `dry_run` records are persisted but never get re-applied to the firewall.
- The pre-filter (when enabled) sits one layer below userspace: it's a kernel `hashlimit` rule that drops over-rate INVITEs at the firewall before they ever reach the detection pipeline.

## License

AGPL-3.0. See [LICENSE](LICENSE) for the full text.
