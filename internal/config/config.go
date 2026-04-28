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
	ServerRejected ServerRejectedConfig `mapstructure:"server_rejected"`
	Honeypot       HoneypotConfig       `mapstructure:"honeypot"`
	FailedCallRatio FailedCallRatioConfig `mapstructure:"failed_call_ratio"`
	DIDScanner     DIDScannerConfig     `mapstructure:"did_scanner"`
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

type ServerRejectedConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	MaxHits int           `mapstructure:"max_hits"`
	Window  time.Duration `mapstructure:"window"`
}

type HoneypotConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	Extensions []string `mapstructure:"extensions"`
}

type FailedCallRatioConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	MinCalls int           `mapstructure:"min_calls"`
	MinRatio float64       `mapstructure:"min_ratio"`
	Window   time.Duration `mapstructure:"window"`
}

type DIDScannerConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	MaxDIDs int           `mapstructure:"max_dids"`
	Window  time.Duration `mapstructure:"window"`
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
	Type    string `mapstructure:"type"`
	Chain   string `mapstructure:"chain"`
	SetName string `mapstructure:"set_name"`
	// PreFilter is the per-IP pre-filter rate limit applied at chain init for
	// INVITE traffic. Optional — leave Rate=0 to disable.
	PreFilter PreFilterConfig `mapstructure:"prefilter"`
}

type PreFilterConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Rate    int    `mapstructure:"rate"`        // INVITEs per second per IP
	Burst   int    `mapstructure:"burst"`       // hashlimit burst
	Ports   []int  `mapstructure:"ports"`       // SIP ports to apply to
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
	v.SetDefault("enforcer.set_name", "sipreaper")
	v.SetDefault("enforcer.prefilter.enabled", false)
	v.SetDefault("enforcer.prefilter.rate", 5)
	v.SetDefault("enforcer.prefilter.burst", 10)
	v.SetDefault("enforcer.prefilter.ports", []int{5060, 5061})
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
	v.SetDefault("detectors.server_rejected.enabled", true)
	v.SetDefault("detectors.server_rejected.max_hits", 1)
	v.SetDefault("detectors.server_rejected.window", "5m")
	v.SetDefault("detectors.honeypot.enabled", false)
	v.SetDefault("detectors.failed_call_ratio.enabled", false)
	v.SetDefault("detectors.failed_call_ratio.min_calls", 20)
	v.SetDefault("detectors.failed_call_ratio.min_ratio", 0.8)
	v.SetDefault("detectors.failed_call_ratio.window", "5m")
	v.SetDefault("detectors.did_scanner.enabled", false)
	v.SetDefault("detectors.did_scanner.max_dids", 20)
	v.SetDefault("detectors.did_scanner.window", "5m")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// Validate checks the loaded config for obvious operator mistakes and refuses
// to start with a bad config rather than fail silently at runtime.
func (c *Config) Validate() error {
	// Ingest must produce events from somewhere.
	if !c.Ingest.Log.Enabled && !c.Ingest.Pcap.Enabled && !c.Ingest.Syslog.Enabled {
		return fmt.Errorf("ingest: at least one of log/pcap/syslog must be enabled")
	}

	if c.Ingest.Log.Enabled {
		if c.Ingest.Log.Path == "" {
			return fmt.Errorf("ingest.log.path is required when log ingest is enabled")
		}
		switch c.Ingest.Log.Format {
		case "kamailio", "opensips", "":
			// "" is acceptable — cascade tries both anyway.
		default:
			return fmt.Errorf("ingest.log.format %q: must be kamailio or opensips", c.Ingest.Log.Format)
		}
	}

	if c.Ingest.Pcap.Enabled {
		if c.Ingest.Pcap.Interface == "" {
			return fmt.Errorf("ingest.pcap.interface is required when pcap ingest is enabled")
		}
		if len(c.Ingest.Pcap.Ports) == 0 && c.Ingest.Pcap.BPFFilter == "" {
			return fmt.Errorf("ingest.pcap: ports or bpf_filter required")
		}
	}

	d := c.Detectors
	if d.BruteForce.Enabled {
		if d.BruteForce.MaxAttempts < 1 {
			return fmt.Errorf("detectors.brute_force.max_attempts must be >= 1")
		}
		if d.BruteForce.Window <= 0 {
			return fmt.Errorf("detectors.brute_force.window must be > 0")
		}
	}
	if d.InviteFlood.Enabled {
		if d.InviteFlood.MaxRequests < 1 {
			return fmt.Errorf("detectors.invite_flood.max_requests must be >= 1")
		}
		if d.InviteFlood.Window <= 0 {
			return fmt.Errorf("detectors.invite_flood.window must be > 0")
		}
	}
	if d.Scanner.Enabled {
		if d.Scanner.MaxProbes < 1 {
			return fmt.Errorf("detectors.scanner.max_probes must be >= 1")
		}
		if d.Scanner.Window <= 0 {
			return fmt.Errorf("detectors.scanner.window must be > 0")
		}
	}
	if d.InvalidRequest.Enabled {
		if d.InvalidRequest.MaxInvalid < 1 {
			return fmt.Errorf("detectors.invalid_request.max_invalid must be >= 1")
		}
		if d.InvalidRequest.Window <= 0 {
			return fmt.Errorf("detectors.invalid_request.window must be > 0")
		}
	}
	if d.GeoAnomaly.Enabled {
		if d.GeoAnomaly.GeoIPDB == "" {
			return fmt.Errorf("detectors.geo_anomaly.geoip_db is required when enabled")
		}
		if len(d.GeoAnomaly.AllowedCountries) == 0 {
			return fmt.Errorf("detectors.geo_anomaly.allowed_countries must list at least one country")
		}
	}
	if d.UserEnum.Enabled {
		if d.UserEnum.MaxExtensions < 1 {
			return fmt.Errorf("detectors.user_enum.max_extensions must be >= 1")
		}
		if d.UserEnum.Window <= 0 {
			return fmt.Errorf("detectors.user_enum.window must be > 0")
		}
	}
	if d.ServerRejected.Enabled {
		if d.ServerRejected.MaxHits < 1 {
			return fmt.Errorf("detectors.server_rejected.max_hits must be >= 1")
		}
		if d.ServerRejected.Window <= 0 {
			return fmt.Errorf("detectors.server_rejected.window must be > 0")
		}
	}
	if d.Honeypot.Enabled && len(d.Honeypot.Extensions) == 0 {
		return fmt.Errorf("detectors.honeypot.extensions must list at least one extension when enabled")
	}
	if d.FailedCallRatio.Enabled {
		if d.FailedCallRatio.MinCalls < 1 {
			return fmt.Errorf("detectors.failed_call_ratio.min_calls must be >= 1")
		}
		if d.FailedCallRatio.MinRatio <= 0 || d.FailedCallRatio.MinRatio > 1 {
			return fmt.Errorf("detectors.failed_call_ratio.min_ratio must be in (0,1]")
		}
		if d.FailedCallRatio.Window <= 0 {
			return fmt.Errorf("detectors.failed_call_ratio.window must be > 0")
		}
	}
	if d.DIDScanner.Enabled {
		if d.DIDScanner.MaxDIDs < 1 {
			return fmt.Errorf("detectors.did_scanner.max_dids must be >= 1")
		}
		if d.DIDScanner.Window <= 0 {
			return fmt.Errorf("detectors.did_scanner.window must be > 0")
		}
	}

	if len(c.Bans.Durations) == 0 {
		return fmt.Errorf("bans.durations must list at least one duration")
	}
	for i, d := range c.Bans.Durations {
		if d < 0 {
			return fmt.Errorf("bans.durations[%d] = %s: must be >= 0 (0 = permanent)", i, d)
		}
	}

	switch c.Enforcer.Type {
	case "iptables", "ipset", "":
		// blank acceptable; daemon falls back to iptables
	default:
		return fmt.Errorf("enforcer.type %q: must be iptables or ipset", c.Enforcer.Type)
	}
	if c.Enforcer.PreFilter.Enabled {
		if c.Enforcer.PreFilter.Rate < 1 {
			return fmt.Errorf("enforcer.prefilter.rate must be >= 1 when enabled")
		}
		if c.Enforcer.PreFilter.Burst < 1 {
			return fmt.Errorf("enforcer.prefilter.burst must be >= 1 when enabled")
		}
	}

	if c.API.Listen == "" {
		return fmt.Errorf("api.listen is required")
	}

	if c.Storage.Path == "" {
		return fmt.Errorf("storage.path is required")
	}

	return nil
}
