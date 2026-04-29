package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"net/http"

	"github.com/andycol/sipreaper/internal/action"
	"github.com/andycol/sipreaper/internal/api"
	"github.com/andycol/sipreaper/internal/config"
	"github.com/andycol/sipreaper/internal/decision"
	"github.com/andycol/sipreaper/internal/detect"
	"github.com/andycol/sipreaper/internal/ingest"
	"github.com/andycol/sipreaper/internal/logging"
	"github.com/andycol/sipreaper/internal/metrics"
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
	startTime time.Time
}

func Run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	if err := logging.Init(cfg.Logging.Level, cfg.Logging.Output, cfg.Logging.File); err != nil {
		return fmt.Errorf("init logging: %w", err)
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
		startTime: time.Now(),
	}

	d.setupDetectors()
	d.setupEnforcer()
	d.setupNotifiers()
	d.engine = decision.New(s, wl, cfg.Bans.Durations, cfg.Bans.Cooldown)
	d.engine.SetDryRun(cfg.Enforcer.DryRun)
	if cfg.Enforcer.DryRun {
		log.Println("DRY RUN MODE: no firewall changes will be applied; bans recorded with status=dry_run")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	var wg sync.WaitGroup

	// Start ingesters
	var logTailer *ingest.LogTailer
	if cfg.Ingest.Log.Enabled {
		log.Printf("starting log tailer: path=%s format=%s", cfg.Ingest.Log.Path, cfg.Ingest.Log.Format)
		var err error
		logTailer, err = ingest.NewLogTailer(
			cfg.Ingest.Log.Path, cfg.Ingest.Log.Format,
			cfg.Ingest.Log.CustomPatterns, d.events,
		)
		if err != nil {
			log.Printf("warning: log tailer init failed: %v", err)
		} else {
			wg.Add(1)
			go func() { defer wg.Done(); logTailer.Run() }()
		}
	} else {
		log.Println("log tailer: disabled")
	}

	var pcapCapture *ingest.PcapCapture
	if cfg.Ingest.Pcap.Enabled {
		log.Printf("starting pcap capture: interface=%s ports=%v", cfg.Ingest.Pcap.Interface, cfg.Ingest.Pcap.Ports)
		pcapCapture = ingest.NewPcapCapture(
			cfg.Ingest.Pcap.Interface, cfg.Ingest.Pcap.Ports,
			cfg.Ingest.Pcap.BPFFilter, d.events,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("pcap goroutine PANICKED: %v (recovered) — pcap ingest is now DEAD until daemon restart", r)
				}
			}()
			err := pcapCapture.Run()
			if err != nil {
				log.Printf("pcap error: %v — pcap ingest is now DEAD until daemon restart", err)
			} else {
				log.Printf("pcap: Run() returned nil — pcap ingest is now DEAD until daemon restart")
			}
		}()
	} else {
		log.Println("pcap capture: disabled")
	}

	// Start dedup + detection pipeline
	dedup := ingest.NewDedup(5 * time.Second)

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
	if logTailer != nil {
		srv.SetLogTailerStats(func() (uint64, uint64) { return logTailer.Stats() })
	}
	srv.SetWhitelistGuard(wl.Contains)
	srv.SetReloadWhitelistFunc(func() {
		if err := wl.ReloadDynamic(); err != nil {
			log.Printf("dynamic whitelist reload failed: %v", err)
		}
	})
	if d.enforcer != nil {
		srv.SetUnbanFunc(d.enforcer.Unban)
	}
	srv.SetHealthChecks(func() map[string]string {
		out := map[string]string{}
		if logTailer != nil {
			matched, _ := logTailer.Stats()
			if matched == 0 && time.Since(d.startTime) > 5*time.Minute {
				// 5 minutes with not a single matched line is suspicious — either
				// the file has rotated, the format changed, or we're reading the
				// wrong path. Either way an operator should investigate.
				out["log_tailer"] = "no matches in last 5m"
			} else {
				out["log_tailer"] = "ok"
			}
		}
		if d.enforcer != nil {
			out["enforcer"] = "ok"
		}
		return out
	})

	// Periodic parser-stats heartbeat — useful for spotting sudden drops in
	// matched lines (e.g. log format changed under us) and for confirming the
	// tailer is actually receiving data.
	if logTailer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					m, u := logTailer.Stats()
					log.Printf("log tailer stats: matched=%d unmatched=%d", m, u)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("API listening on %s", cfg.API.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
		break
	}

	// Stop everything before waiting on goroutines
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)

	if logTailer != nil {
		logTailer.Stop()
	}
	if pcapCapture != nil {
		pcapCapture.Stop()
	}
	dedup.Stop()

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
	if cfg.ServerRejected.Enabled {
		d.detectors = append(d.detectors, detect.NewServerRejected(cfg.ServerRejected.MaxHits, cfg.ServerRejected.Window))
	}
	if cfg.Honeypot.Enabled {
		d.detectors = append(d.detectors, detect.NewHoneypot(cfg.Honeypot.Extensions))
	}
	if cfg.FailedCallRatio.Enabled {
		d.detectors = append(d.detectors, detect.NewFailedCallRatio(
			cfg.FailedCallRatio.MinCalls, cfg.FailedCallRatio.MinRatio, cfg.FailedCallRatio.Window,
		))
	}
	if cfg.DIDScanner.Enabled {
		d.detectors = append(d.detectors, detect.NewDIDScanner(cfg.DIDScanner.MaxDIDs, cfg.DIDScanner.Window))
	}

	log.Printf("loaded %d detectors", len(d.detectors))
}

func (d *Daemon) setupEnforcer() {
	switch d.cfg.Enforcer.Type {
	case "ipset":
		e := action.NewIPSetEnforcer(d.cfg.Enforcer.SetName, d.cfg.Enforcer.Chain)
		if err := e.Init(); err != nil {
			log.Printf("warning: ipset init failed: %v", err)
		}
		d.enforcer = e
	case "iptables", "":
		e := action.NewIPTablesEnforcer(d.cfg.Enforcer.Chain)
		if err := e.Init(); err != nil {
			log.Printf("warning: iptables init failed: %v", err)
		}
		d.enforcer = e
	default:
		log.Printf("warning: unknown enforcer type %q, falling back to iptables", d.cfg.Enforcer.Type)
		d.enforcer = action.NewIPTablesEnforcer(d.cfg.Enforcer.Chain)
	}

	if d.cfg.Enforcer.PreFilter.Enabled {
		pf := action.NewPreFilter(
			d.cfg.Enforcer.Chain,
			d.cfg.Enforcer.PreFilter.Rate,
			d.cfg.Enforcer.PreFilter.Burst,
			d.cfg.Enforcer.PreFilter.Ports,
		)
		if err := pf.Apply(); err != nil {
			log.Printf("warning: prefilter setup failed: %v", err)
		} else {
			log.Printf("prefilter active: %d INVITEs/sec/IP burst=%d ports=%v",
				d.cfg.Enforcer.PreFilter.Rate, d.cfg.Enforcer.PreFilter.Burst, d.cfg.Enforcer.PreFilter.Ports)
		}
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
			if evt.CallID != "" && dedup.IsDuplicateEvent(evt.CallID, evt.Method, evt.ResponseCode) {
				continue
			}

			source := evt.Source
			if source == "" {
				source = "unknown"
			}
			method := evt.Method
			if method == "" {
				method = "UNKNOWN"
			}
			metrics.EventsTotal.WithLabelValues(source, method).Inc()

			for _, det := range d.detectors {
				d.safeDetect(det, evt)
			}
		}
	}
}

// safeDetect isolates a single detector invocation behind a panic boundary.
// A panic in one detector (bad regex match, nil deref on a malformed event)
// must not take the whole pipeline down — we log it and move on. Wrapped per
// detector rather than per event so we know which detector misbehaved.
func (d *Daemon) safeDetect(det detect.Detector, evt models.SIPEvent) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("detector %s panicked: %v", det.Name(), r)
			metrics.DetectorPanicsTotal.WithLabelValues(det.Name()).Inc()
		}
	}()

	threat := det.Detect(evt)
	if threat == nil {
		return
	}
	metrics.ThreatsTotal.WithLabelValues(threat.Detector, threat.Severity).Inc()
	select {
	case d.threats <- *threat:
	default:
		log.Println("threat channel full, dropping")
	}
}

func (d *Daemon) runActionPipeline(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case threat := <-d.threats:
			d.handleThreat(threat)
		}
	}
}

func (d *Daemon) handleThreat(threat models.Threat) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("action pipeline panicked handling %s threat: %v", threat.Detector, r)
			metrics.DetectorPanicsTotal.WithLabelValues("action_pipeline").Inc()
		}
	}()

	banAction := d.engine.Evaluate(threat)
	if banAction == nil {
		return
	}

	if d.enforcer != nil && !d.engine.DryRun() {
		if err := d.enforcer.Ban(banAction.IP, banAction.Duration, banAction.Reason); err != nil {
			metrics.EnforcerErrors.WithLabelValues("ban").Inc()
			log.Printf("enforcer error: %v", err)
		}
	}
	metrics.BansTotal.WithLabelValues(banAction.Detector).Inc()
	if !d.engine.DryRun() {
		metrics.ActiveBans.Inc()
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

	prefix := "BANNED"
	if d.engine.DryRun() {
		prefix = "DRY RUN"
	}
	log.Printf("%s %s (detector=%s, duration=%s, count=%d)",
		prefix, banAction.IP, banAction.Detector, banAction.Duration, banAction.BanCount)
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
				// Dry-run entries never had a firewall rule installed, so
				// skip the enforcer call (would error on non-existent rule).
				if d.enforcer != nil && ban.Status != "dry_run" {
					if err := d.enforcer.Unban(net.ParseIP(ban.IP)); err != nil {
						metrics.EnforcerErrors.WithLabelValues("unban").Inc()
					}
				}
				metrics.UnbansTotal.Inc()
				if ban.Status != "dry_run" {
					metrics.ActiveBans.Dec()
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
