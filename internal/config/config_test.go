package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	yaml := `
ingest:
  log:
    enabled: true
    path: "/var/log/kamailio/kamailio.log"
    format: "kamailio"
  pcap:
    enabled: true
    interface: "eth0"
    ports: [5060]
detectors:
  brute_force:
    enabled: true
    max_attempts: 5
    window: 60s
  invite_flood:
    enabled: false
whitelist:
  static:
    - ip: "10.0.0.0/8"
      comment: "Internal"
bans:
  durations: [5m, 30m, 2h]
  cooldown: 48h
  check_interval: 30s
enforcer:
  type: "iptables"
  chain: "SIPREAPER"
notifiers:
  syslog:
    enabled: true
  email:
    enabled: true
    smtp_host: "smtp.example.com"
    smtp_port: 587
    tls: true
    from: "test@example.com"
    to: ["admin@example.com"]
    username: "test@example.com"
    password_env: "SMTP_PASS"
    min_severity: "medium"
api:
  listen: "127.0.0.1:9090"
  token_env: "API_TOKEN"
storage:
  path: "/tmp/test.db"
logging:
  level: "debug"
  output: "stdout"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Ingest.Log.Path != "/var/log/kamailio/kamailio.log" {
		t.Errorf("log path = %q, want /var/log/kamailio/kamailio.log", cfg.Ingest.Log.Path)
	}
	if !cfg.Ingest.Log.Enabled {
		t.Error("log should be enabled")
	}
	if cfg.Ingest.Pcap.Interface != "eth0" {
		t.Errorf("pcap interface = %q, want eth0", cfg.Ingest.Pcap.Interface)
	}
	if !cfg.Detectors.BruteForce.Enabled {
		t.Error("brute_force should be enabled")
	}
	if cfg.Detectors.BruteForce.MaxAttempts != 5 {
		t.Errorf("brute_force max_attempts = %d, want 5", cfg.Detectors.BruteForce.MaxAttempts)
	}
	if cfg.Detectors.BruteForce.Window != 60*time.Second {
		t.Errorf("brute_force window = %v, want 60s", cfg.Detectors.BruteForce.Window)
	}
	if cfg.Detectors.InviteFlood.Enabled {
		t.Error("invite_flood should be disabled")
	}
	if len(cfg.Whitelist.Static) != 1 {
		t.Fatalf("whitelist static len = %d, want 1", len(cfg.Whitelist.Static))
	}
	if cfg.Whitelist.Static[0].IP != "10.0.0.0/8" {
		t.Errorf("whitelist ip = %q, want 10.0.0.0/8", cfg.Whitelist.Static[0].IP)
	}
	if len(cfg.Bans.Durations) != 3 {
		t.Errorf("bans durations len = %d, want 3", len(cfg.Bans.Durations))
	}
	if cfg.Bans.Cooldown != 48*time.Hour {
		t.Errorf("bans cooldown = %v, want 48h", cfg.Bans.Cooldown)
	}
	if cfg.API.Listen != "127.0.0.1:9090" {
		t.Errorf("api listen = %q, want 127.0.0.1:9090", cfg.API.Listen)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	yaml := `{}`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.API.Listen != "127.0.0.1:8080" {
		t.Errorf("default api listen = %q, want 127.0.0.1:8080", cfg.API.Listen)
	}
	if cfg.Enforcer.Chain != "SIPREAPER" {
		t.Errorf("default chain = %q, want SIPREAPER", cfg.Enforcer.Chain)
	}
	if cfg.Bans.CheckInterval != 30*time.Second {
		t.Errorf("default check_interval = %v, want 30s", cfg.Bans.CheckInterval)
	}
	if cfg.Storage.Path != "/var/lib/sipreaper/sipreaper.db" {
		t.Errorf("default storage path = %q, want /var/lib/sipreaper/sipreaper.db", cfg.Storage.Path)
	}
}
