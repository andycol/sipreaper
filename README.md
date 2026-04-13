# SIPReaper

SIP attack detection and automatic IP banning for Kamailio and OpenSIPS. Think fail2ban, but purpose-built for SIP with deep protocol awareness, configurable thresholds, and a management API.

## Features

- **Dual ingest** — monitors both log files and live packet capture simultaneously
- **6 detection engines** — brute force, INVITE flood, scanner detection, invalid requests, geo-anomaly, user enumeration
- **Configurable thresholds** — per-detector enable/disable, rate limits, and time windows
- **Two-tier whitelist** — static (config file) and dynamic (runtime via CLI/API), supports IPs and CIDRs
- **Escalating bans** — repeat offenders get progressively longer bans (5m → 30m → 2h → 24h → permanent)
- **Pluggable enforcement** — iptables out of the box, interface-based for adding nftables or others
- **Pluggable notifications** — syslog and email (SMTP) built-in, with severity filtering
- **REST API** — full management API with bearer token auth
- **CLI** — `sipreaper` command for all operations (talks to the API)
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

This produces a `sipreaper` binary in the project root.

### Run Tests

```bash
make test
```

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
  type: "iptables"
  chain: "SIPREAPER"
```

The iptables enforcer creates a dedicated chain (`SIPREAPER`) linked from `INPUT`. Bans add `DROP` rules; unbans remove them. On startup, active bans from SQLite are re-applied to the chain.

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

### Storage

```yaml
storage:
  path: "/var/lib/sipreaper/sipreaper.db"
```

SQLite database storing bans, event history, and dynamic whitelist entries.

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

# Remove from whitelist
sipreaper whitelist remove 198.51.100.0/24
```

### Monitoring

```bash
# Check daemon status
sipreaper status

# View detection statistics
sipreaper stats

# Query recent events
sipreaper events --last 1h

# Filter events by IP
sipreaper events --ip 203.0.113.100

# Filter events by detector
sipreaper events --detector brute_force
```

### Global Flags

All CLI commands (except `daemon`) connect to the running daemon's API:

```bash
# Custom API address
sipreaper --api-addr http://10.0.0.1:8080 status

# Pass API token directly (alternative to SIPREAPER_API_TOKEN env var)
sipreaper --api-token mysecret bans
```

## REST API

All endpoints require `Authorization: Bearer <token>` header.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/status` | Daemon health, uptime, active ban count |
| `GET` | `/api/v1/bans` | List bans. Query params: `status` (active/expired/manual), `ip` |
| `POST` | `/api/v1/bans` | Manual ban. Body: `{"ip": "1.2.3.4", "duration": "1h"}` |
| `DELETE` | `/api/v1/bans/{ip}` | Unban an IP |
| `GET` | `/api/v1/whitelist` | List whitelist entries |
| `POST` | `/api/v1/whitelist` | Add to whitelist. Body: `{"ip": "10.0.0.0/8", "comment": "..."}` |
| `DELETE` | `/api/v1/whitelist/{ip}` | Remove from whitelist |
| `GET` | `/api/v1/events` | Query events. Params: `ip`, `detector`, `last` (duration) |
| `GET` | `/api/v1/stats` | Detection stats, bans by detector, top offenders |

### Examples

```bash
# Check status
curl -H "Authorization: Bearer $SIPREAPER_API_TOKEN" http://127.0.0.1:8080/api/v1/status

# List active bans
curl -H "Authorization: Bearer $SIPREAPER_API_TOKEN" http://127.0.0.1:8080/api/v1/bans

# Manual ban
curl -X POST -H "Authorization: Bearer $SIPREAPER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.100", "duration": "2h"}' \
  http://127.0.0.1:8080/api/v1/bans

# Add to whitelist
curl -X POST -H "Authorization: Bearer $SIPREAPER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.0/8", "comment": "Internal"}' \
  http://127.0.0.1:8080/api/v1/whitelist
```

## Deployment

### Requirements

- Linux (for iptables enforcement and pcap capture)
- `CAP_NET_RAW` capability (for pcap) or run as root
- `CAP_NET_ADMIN` capability (for iptables) or run as root
- MaxMind GeoLite2-Country database (if geo_anomaly detector is enabled)

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

# Check logs
sudo journalctl -u sipreaper -f

# Verify the iptables chain was created
sudo iptables -L SIPREAPER -n

# Test a manual ban/unban
sipreaper ban 192.0.2.1 5m
sudo iptables -L SIPREAPER -n    # should show the DROP rule
sipreaper unban 192.0.2.1
sudo iptables -L SIPREAPER -n    # rule should be gone
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
Ingest (log + pcap)  ->  Dedup  ->  Detection (6 detectors)
                                         |
                                    Decision Engine
                                    (whitelist + escalation)
                                         |
                                    Action Layer
                                    (enforcer + notifiers)
```

All components communicate through Go channels. Each detector runs as its own goroutine. SQLite provides persistence across restarts.

## License

AGPL-3.0. See [LICENSE](LICENSE) for the full text.
