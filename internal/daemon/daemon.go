package daemon

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/andycol/sipreaper/internal/action"
	"github.com/andycol/sipreaper/internal/api"
	"github.com/andycol/sipreaper/internal/config"
	"github.com/andycol/sipreaper/internal/decision"
	"github.com/andycol/sipreaper/internal/detect"
	"github.com/andycol/sipreaper/internal/ingest"
	"github.com/andycol/sipreaper/internal/models"
	"github.com/andycol/sipreaper/internal/store"
	"github.com/andycol/sipreaper/internal/whitelist"
)

type Daemon struct {
	cfg       *config.Config
	store     *store.Store
	whitelist *whitelist.Whitelist
	engine    *decision.Engine
	enforcer  action.Enforcer
	notifiers []action.Notifier
	detectors []detect.Detector
	events    chan models.SIPEvent
	threats   chan models.Threat
}

func Run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	s, err := store.New(cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer s.Close()

	wl, err := whitelist.New(cfg.Whitelist.Static, s)
	if err != nil {
		return err
	}

	d := &Daemon{
		cfg:       cfg,
		store:     s,
		whitelist: wl,
		events:    make(chan models.SIPEvent, 1000),
		threats:   make(chan models.Threat, 100),
	}

	d.setupDetectors()
	d.setupEnforcer()
	d.setupNotifiers()
	d.engine = decision.New(s, wl, cfg.Bans.Durations, cfg.Bans.Cooldown)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	var wg sync.WaitGroup

	// Start ingesters
	if cfg.Ingest.Log.Enabled {
		tailer, err := ingest.NewLogTailer(
			cfg.Ingest.Log.Path, cfg.Ingest.Log.Format,
			cfg.Ingest.Log.CustomPatterns, d.events,
		)
		if err != nil {
			log.Printf("warning: log tailer init failed: %v", err)
		} else {
			wg.Add(1)
			go func() { defer wg.Done(); tailer.Run() }()
			defer tailer.Stop()
		}
	}

	if cfg.Ingest.Pcap.Enabled {
		pcap := ingest.NewPcapCapture(
			cfg.Ingest.Pcap.Interface, cfg.Ingest.Pcap.Ports,
			cfg.Ingest.Pcap.BPFFilter, d.events,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pcap.Run(); err != nil {
				log.Printf("pcap error: %v", err)
			}
		}()
		defer pcap.Stop()
	}

	// Start dedup + detection pipeline
	dedup := ingest.NewDedup(5 * time.Second)
	defer dedup.Stop()

	wg.Add(1)
	go func() {
		defer wg.Done()
		d.runDetectionPipeline(ctx, dedup)
	}()

	// Start decision + action pipeline
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.runActionPipeline(ctx)
	}()

	// Start ban expiry ticker
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.runBanExpiry(ctx, cfg.Bans.CheckInterval)
	}()

	// Restore active bans to enforcer
	d.restoreBans()

	// Start API server
	token := os.Getenv(cfg.API.TokenEnv)
	srv := api.NewServer(s, token, cfg.API.Listen)
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("API listening on %s", cfg.API.Listen)
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("API server error: %v", err)
		}
	}()

	log.Println("sipreaper daemon started")

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			log.Println("reloading config...")
			newCfg, err := config.Load(cfgPath)
			if err != nil {
				log.Printf("config reload failed: %v", err)
				continue
			}
			wl.ReloadStatic(newCfg.Whitelist.Static)
			wl.ReloadDynamic()
			log.Println("config reloaded")
			continue
		}
		log.Printf("received %s, shutting down...", sig)
		cancel()
		break
	}

	wg.Wait()
	log.Println("sipreaper daemon stopped")
	return nil
}

func (d *Daemon) setupDetectors() {
	cfg := d.cfg.Detectors

	if cfg.BruteForce.Enabled {
		d.detectors = append(d.detectors, detect.NewBruteForce(cfg.BruteForce.MaxAttempts, cfg.BruteForce.Window))
	}
	if cfg.InviteFlood.Enabled {
		d.detectors = append(d.detectors, detect.NewInviteFlood(cfg.InviteFlood.MaxRequests, cfg.InviteFlood.Window))
	}
	if cfg.Scanner.Enabled {
		d.detectors = append(d.detectors, detect.NewScanner(cfg.Scanner.MaxProbes, cfg.Scanner.Window, cfg.Scanner.KnownAgents))
	}
	if cfg.InvalidRequest.Enabled {
		d.detectors = append(d.detectors, detect.NewInvalidRequest(cfg.InvalidRequest.MaxInvalid, cfg.InvalidRequest.Window))
	}
	if cfg.GeoAnomaly.Enabled && cfg.GeoAnomaly.GeoIPDB != "" {
		resolver, err := detect.NewMaxMindResolver(cfg.GeoAnomaly.GeoIPDB)
		if err != nil {
			log.Printf("warning: geo anomaly disabled: %v", err)
		} else {
			d.detectors = append(d.detectors, detect.NewGeoAnomaly(cfg.GeoAnomaly.AllowedCountries, resolver))
		}
	}
	if cfg.UserEnum.Enabled {
		d.detectors = append(d.detectors, detect.NewUserEnum(cfg.UserEnum.MaxExtensions, cfg.UserEnum.Window))
	}

	log.Printf("loaded %d detectors", len(d.detectors))
}

func (d *Daemon) setupEnforcer() {
	switch d.cfg.Enforcer.Type {
	case "iptables":
		e := action.NewIPTablesEnforcer(d.cfg.Enforcer.Chain)
		if err := e.Init(); err != nil {
			log.Printf("warning: iptables init failed: %v", err)
		}
		d.enforcer = e
	default:
		log.Printf("warning: unknown enforcer type %q, using iptables", d.cfg.Enforcer.Type)
		d.enforcer = action.NewIPTablesEnforcer(d.cfg.Enforcer.Chain)
	}
}

func (d *Daemon) setupNotifiers() {
	if d.cfg.Notifiers.Syslog.Enabled {
		d.notifiers = append(d.notifiers, action.NewSyslogNotifier())
	}
	if d.cfg.Notifiers.Email.Enabled {
		e := d.cfg.Notifiers.Email
		d.notifiers = append(d.notifiers, action.NewEmailNotifier(
			e.SMTPHost, e.SMTPPort, e.TLS, e.From, e.To,
			e.Username, e.PasswordEnv, e.MinSeverity,
		))
	}
	log.Printf("loaded %d notifiers", len(d.notifiers))
}

func (d *Daemon) runDetectionPipeline(ctx context.Context, dedup *ingest.Dedup) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-d.events:
			if evt.CallID != "" && dedup.IsDuplicate(evt.CallID, evt.Method) {
				continue
			}

			for _, det := range d.detectors {
				if threat := det.Detect(evt); threat != nil {
					select {
					case d.threats <- *threat:
					default:
						log.Println("threat channel full, dropping")
					}
				}
			}
		}
	}
}

func (d *Daemon) runActionPipeline(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case threat := <-d.threats:
			banAction := d.engine.Evaluate(threat)
			if banAction == nil {
				continue
			}

			if d.enforcer != nil {
				if err := d.enforcer.Ban(banAction.IP, banAction.Duration, banAction.Reason); err != nil {
					log.Printf("enforcer error: %v", err)
				}
			}

			notifyEvt := models.NotifyEvent{
				Type:      "ban",
				IP:        banAction.IP.String(),
				Detector:  banAction.Detector,
				Severity:  banAction.Severity,
				Duration:  banAction.Duration,
				Reason:    banAction.Reason,
				Timestamp: time.Now(),
			}
			for _, n := range d.notifiers {
				if err := n.Notify(notifyEvt); err != nil {
					log.Printf("notifier %s error: %v", n.Name(), err)
				}
			}

			log.Printf("BANNED %s (detector=%s, duration=%s, count=%d)",
				banAction.IP, banAction.Detector, banAction.Duration, banAction.BanCount)
		}
	}
}

func (d *Daemon) runBanExpiry(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			expired, err := d.store.GetExpiredBans()
			if err != nil {
				log.Printf("ban expiry check error: %v", err)
				continue
			}
			for _, ban := range expired {
				d.store.UpdateBanStatus(ban.ID, "expired")
				if d.enforcer != nil {
					d.enforcer.Unban(net.ParseIP(ban.IP))
				}

				for _, n := range d.notifiers {
					n.Notify(models.NotifyEvent{
						Type: "unban", IP: ban.IP, Detector: ban.Detector,
						Severity: ban.Severity, Timestamp: time.Now(),
					})
				}

				log.Printf("UNBANNED %s (expired)", ban.IP)
			}
		}
	}
}

func (d *Daemon) restoreBans() {
	bans, err := d.store.ListBans("active")
	if err != nil {
		log.Printf("error restoring bans: %v", err)
		return
	}
	for _, ban := range bans {
		if d.enforcer != nil {
			ip := net.ParseIP(ban.IP)
			if ip != nil {
				d.enforcer.Ban(ip, ban.Duration, ban.Reason)
			}
		}
	}
	if len(bans) > 0 {
		log.Printf("restored %d active bans to enforcer", len(bans))
	}
}
