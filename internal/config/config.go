package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Ingest    IngestConfig    `mapstructure:"ingest"`
	Detectors DetectorsConfig `mapstructure:"detectors"`
	Whitelist WhitelistConfig `mapstructure:"whitelist"`
	Bans      BansConfig      `mapstructure:"bans"`
	Enforcer  EnforcerConfig  `mapstructure:"enforcer"`
	Notifiers NotifiersConfig `mapstructure:"notifiers"`
	API       APIConfig       `mapstructure:"api"`
	Storage   StorageConfig   `mapstructure:"storage"`
	Logging   LoggingConfig   `mapstructure:"logging"`
}

type IngestConfig struct {
	Log    LogIngestConfig    `mapstructure:"log"`
	Syslog SyslogIngestConfig `mapstructure:"syslog"`
	Pcap   PcapIngestConfig   `mapstructure:"pcap"`
}

type LogIngestConfig struct {
	Enabled        bool     `mapstructure:"enabled"`
	Path           string   `mapstructure:"path"`
	Format         string   `mapstructure:"format"`
	CustomPatterns []string `mapstructure:"custom_patterns"`
}

type SyslogIngestConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"`
}

type PcapIngestConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Interface string `mapstructure:"interface"`
	Ports     []int  `mapstructure:"ports"`
	BPFFilter string `mapstructure:"bpf_filter"`
}

type DetectorsConfig struct {
	BruteForce     BruteForceConfig     `mapstructure:"brute_force"`
	InviteFlood    InviteFloodConfig    `mapstructure:"invite_flood"`
	Scanner        ScannerConfig        `mapstructure:"scanner"`
	InvalidRequest InvalidRequestConfig `mapstructure:"invalid_request"`
	GeoAnomaly     GeoAnomalyConfig     `mapstructure:"geo_anomaly"`
	UserEnum       UserEnumConfig       `mapstructure:"user_enum"`
}

type BruteForceConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	MaxAttempts int           `mapstructure:"max_attempts"`
	Window      time.Duration `mapstructure:"window"`
}

type InviteFloodConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	MaxRequests int           `mapstructure:"max_requests"`
	Window      time.Duration `mapstructure:"window"`
}

type ScannerConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	MaxProbes   int           `mapstructure:"max_probes"`
	Window      time.Duration `mapstructure:"window"`
	KnownAgents []string     `mapstructure:"known_agents"`
}

type InvalidRequestConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	MaxInvalid int           `mapstructure:"max_invalid"`
	Window     time.Duration `mapstructure:"window"`
}

type GeoAnomalyConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	AllowedCountries []string `mapstructure:"allowed_countries"`
	GeoIPDB          string   `mapstructure:"geoip_db"`
}

type UserEnumConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	MaxExtensions int           `mapstructure:"max_extensions"`
	Window        time.Duration `mapstructure:"window"`
}

type WhitelistConfig struct {
	Static []StaticWhitelistEntry `mapstructure:"static"`
}

type StaticWhitelistEntry struct {
	IP      string `mapstructure:"ip"`
	Comment string `mapstructure:"comment"`
}

type BansConfig struct {
	Durations     []time.Duration `mapstructure:"durations"`
	Cooldown      time.Duration   `mapstructure:"cooldown"`
	CheckInterval time.Duration   `mapstructure:"check_interval"`
}

type EnforcerConfig struct {
	Type  string `mapstructure:"type"`
	Chain string `mapstructure:"chain"`
}

type NotifiersConfig struct {
	Syslog SyslogNotifierConfig `mapstructure:"syslog"`
	Email  EmailNotifierConfig  `mapstructure:"email"`
}

type SyslogNotifierConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type EmailNotifierConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	SMTPHost    string   `mapstructure:"smtp_host"`
	SMTPPort    int      `mapstructure:"smtp_port"`
	TLS         bool     `mapstructure:"tls"`
	From        string   `mapstructure:"from"`
	To          []string `mapstructure:"to"`
	Username    string   `mapstructure:"username"`
	PasswordEnv string   `mapstructure:"password_env"`
	MinSeverity string   `mapstructure:"min_severity"`
}

type APIConfig struct {
	Listen   string `mapstructure:"listen"`
	TokenEnv string `mapstructure:"token_env"`
}

type StorageConfig struct {
	Path string `mapstructure:"path"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Output string `mapstructure:"output"`
	File   string `mapstructure:"file"`
}

func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)

	// Defaults
	v.SetDefault("api.listen", "127.0.0.1:8080")
	v.SetDefault("api.token_env", "SIPREAPER_API_TOKEN")
	v.SetDefault("enforcer.type", "iptables")
	v.SetDefault("enforcer.chain", "SIPREAPER")
	v.SetDefault("bans.durations", []string{"5m", "30m", "2h", "24h", "0s"})
	v.SetDefault("bans.cooldown", "48h")
	v.SetDefault("bans.check_interval", "30s")
	v.SetDefault("storage.path", "/var/lib/sipreaper/sipreaper.db")
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("ingest.log.format", "kamailio")
	v.SetDefault("ingest.syslog.listen", "0.0.0.0:1514")
	v.SetDefault("ingest.pcap.ports", []int{5060, 5061})
	v.SetDefault("notifiers.syslog.enabled", true)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, nil
}
