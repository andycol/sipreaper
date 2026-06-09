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
	"github.com/andycol/sipreaper/internal/banner"
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
	// enfMu guards enforcer/xdp/base, which the kill-switch swaps at runtime
	// while the action pipeline and maintenance goroutine read them.
	enfMu    sync.RWMutex
	enforcer action.Enforcer
	// base is the iptables/ipset backend, always built so the XDP fail-open /
	// kill-switch paths have something proven to revert to.
	base action.Enforcer
	// xdp is the concrete XDP enforcer handle, kept separately because the
	// action.Enforcer interface has no Close()/diagnostics — the daemon needs
	// the concrete type for reconcile, metrics, the kill switch and shutdown.
	// nil whenever XDP is disabled or failed to attach (fail-open to base).
	xdp                  *banner.XdpEnforcer
	lastReconcileRemoved int
	notifiers            []action.Notifier
	detectors            []detect.Detector
	events               chan models.SIPEvent
	threats              chan models.Threat
	startTime            time.Time
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
	token := os.Getenv(cfg.API.TokenEnv)
	if token == "" {
		return fmt.Errorf("api token env %s is not set; refusing to expose management API without authentication", cfg.API.TokenEnv)
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

	var syslogIngest *ingest.SyslogIngest
	if cfg.Ingest.Syslog.Enabled {
		log.Printf("starting syslog ingest: listen=%s/udp", cfg.Ingest.Syslog.Listen)
		syslogIngest = ingest.NewSyslogIngest(cfg.Ingest.Syslog.Listen, d.events)
		wg.Add(1)
		go func() {
			defer wg.Done()
			syslogIngest.Run()
		}()
	} else {
		log.Println("syslog ingest: disabled")
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

	// Reconcile the pinned XDP map against the DB (DB wins) BEFORE re-applying
	// bans, so stale/whitelisted map entries from a previous run are evicted.
	d.reconcileXdp()
	d.refreshXdpMetrics()

	// Restore active bans to enforcer
	d.restoreBans()

	// Periodic XDP metrics refresh + drift-healing reconcile.
	if d.xdp != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runXdpMaintenance(ctx)
		}()
	}

	// Start API server
	srv := api.NewServer(s, token, cfg.API.Listen)
	if logTailer != nil {
		srv.SetLogTailerStats(func() (uint64, uint64) { return logTailer.Stats() })
	}
	if syslogIngest != nil {
		srv.SetSyslogStats(func() (uint64, uint64) { return syslogIngest.Stats() })
	}
	srv.SetWhitelistGuard(wl.Contains)
	srv.SetReloadWhitelistFunc(func() {
		if err := wl.ReloadDynamic(); err != nil {
			log.Printf("dynamic whitelist reload failed: %v", err)
		}
	})
	srv.SetBanFunc(func(ip net.IP, dur time.Duration, reason string) error {
		if enf := d.currentEnforcer(); enf != nil {
			return enf.Ban(ip, dur, reason)
		}
		return fmt.Errorf("no enforcer configured")
	})
	// Unban always routes through the *current* enforcer so the kill switch
	// (which swaps it for the base) is honoured.
	srv.SetUnbanFunc(func(ip net.IP) error {
		if enf := d.currentEnforcer(); enf != nil {
			return enf.Unban(ip)
		}
		return nil
	})
	srv.SetXdpStatusFunc(d.xdpStatusMap)
	srv.SetXdpDetachFunc(d.detachXDP)
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
		if syslogIngest != nil {
			matched, _ := syslogIngest.Stats()
			if matched == 0 && time.Since(d.startTime) > 5*time.Minute {
				out["syslog_ingest"] = "no matches in last 5m"
			} else {
				out["syslog_ingest"] = "ok"
			}
		}
		if d.currentEnforcer() != nil {
			out["enforcer"] = "ok"
		}
		// XDP health: degrade-don't-fail. If configured-on but not attached,
		// report it (silent fail-open to iptables is the dangerous case), but
		// keep /healthz green-ish — the base enforcer is still protecting.
		if d.cfg.Enforcer.XDP.Enabled {
			if xe := d.currentXdp(); xe != nil && xe.Attached() {
				out["xdp"] = "ok"
			} else {
				out["xdp"] = "degraded: enabled but not attached (on base enforcer)"
			}
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
	if syslogIngest != nil {
		syslogIngest.Stop()
	}
	if pcapCapture != nil {
		pcapCapture.Stop()
	}
	if d.xdp != nil {
		// Detach the link (program stops running); pinned maps survive so bans
		// are restored on next start and reconciled against the DB.
		if err := d.xdp.Close(); err != nil {
			log.Printf("xdp close error: %v", err)
		}
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
	// Always build the proven iptables/ipset base, even when XDP is configured
	// standalone, so fail-open has a real fallback to fall back TO.
	var base action.Enforcer
	switch d.cfg.Enforcer.Type {
	case "ipset":
		e := action.NewIPSetEnforcer(d.cfg.Enforcer.SetName, d.cfg.Enforcer.Chain)
		if err := e.Init(); err != nil {
			log.Printf("warning: ipset init failed: %v", err)
		}
		base = e
	case "iptables", "":
		e := action.NewIPTablesEnforcer(d.cfg.Enforcer.Chain)
		if err := e.Init(); err != nil {
			log.Printf("warning: iptables init failed: %v", err)
		}
		base = e
	default:
		log.Printf("warning: unknown enforcer type %q, falling back to iptables", d.cfg.Enforcer.Type)
		base = action.NewIPTablesEnforcer(d.cfg.Enforcer.Chain)
	}

	d.base = base
	d.enforcer = base

	if d.cfg.Enforcer.XDP.Enabled {
		d.setupXDP(base)
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

// currentEnforcer returns the active enforcer under the read lock — the
// kill-switch may swap it at runtime.
func (d *Daemon) currentEnforcer() action.Enforcer {
	d.enfMu.RLock()
	defer d.enfMu.RUnlock()
	return d.enforcer
}

// currentXdp returns the live XDP handle (nil if detached/disabled).
func (d *Daemon) currentXdp() *banner.XdpEnforcer {
	d.enfMu.RLock()
	defer d.enfMu.RUnlock()
	return d.xdp
}

// setupXDP attempts to layer the XDP enforcer on top of base. Every failure
// path is fail-open: the daemon keeps `base` in d.enforcer and logs a warning,
// exactly mirroring the iptables/ipset "log, don't be fatal" pattern.
func (d *Daemon) setupXDP(base action.Enforcer) {
	iface := d.cfg.Enforcer.XDP.Interface
	if iface == "" {
		iface = d.cfg.Ingest.Pcap.Interface
	}

	if reason := banner.Preflight(iface); reason != "" {
		log.Printf("warning: xdp preflight failed (%s); staying on %s", reason, base.Name())
		return
	}
	xe, err := banner.NewXdpEnforcer(iface, d.cfg.Enforcer.XDP.Mode)
	if err != nil {
		log.Printf("warning: xdp enforcer init failed, staying on %s: %v", base.Name(), err)
		return
	}
	if err := xe.Init(); err != nil {
		log.Printf("warning: xdp attach failed, staying on %s: %v", base.Name(), err)
		return
	}

	d.xdp = xe
	metrics.XdpAttached.WithLabelValues(xe.Mode()).Set(1)
	log.Printf("enforcer: xdp attached on %s mode=%s", iface, xe.Mode())

	if d.cfg.Enforcer.XDP.Standalone {
		d.enforcer = xe
	} else {
		d.enforcer = action.NewCompositeEnforcer(base, xe)
	}
	log.Printf("enforcer: active = %s", d.enforcer.Name())
}

// reconcileXdp makes the pinned kernel map agree with the DB source-of-truth:
// it removes any map entry that is not an active ban, or that is now
// whitelisted. The DB always wins. Runs at startup (before restoreBans) and on
// a low-frequency ticker so per-backend drift self-heals.
func (d *Daemon) reconcileXdp() {
	xe := d.currentXdp()
	if xe == nil {
		return
	}
	active, err := d.store.ListEnforcedBans()
	if err != nil {
		log.Printf("xdp reconcile: list bans failed: %v", err)
		return
	}
	want := map[string]bool{}
	for _, b := range active {
		ip := net.ParseIP(b.IP)
		if ip == nil || d.whitelist.Contains(ip) { // whitelist wins
			continue
		}
		want[ip.String()] = true
	}
	have, err := xe.List()
	if err != nil {
		log.Printf("xdp reconcile: read map failed: %v", err)
		return
	}
	removed := 0
	for _, e := range have {
		if want[e.IP] {
			continue
		}
		if ip := net.ParseIP(e.IP); ip != nil {
			_ = xe.Unban(ip)
			removed++
		}
	}
	metrics.XdpReconcileRemoved.Add(float64(removed))
	d.lastReconcileRemoved = removed
	if removed > 0 {
		log.Printf("xdp reconcile: %d stale/whitelisted map entries removed", removed)
	}
	if v4, v6, merr := xe.MapEntries(); merr == nil {
		metrics.XdpMapEntries.WithLabelValues("v4").Set(float64(v4))
		metrics.XdpMapEntries.WithLabelValues("v6").Set(float64(v6))
	}
}

// refreshXdpMetrics pulls the kernel stats/map sizes into Prometheus gauges.
func (d *Daemon) refreshXdpMetrics() {
	xe := d.currentXdp()
	if xe == nil {
		return
	}
	if passed, dropped, err := xe.Stats(); err == nil {
		metrics.XdpPackets.WithLabelValues("passed").Set(float64(passed))
		metrics.XdpPackets.WithLabelValues("dropped").Set(float64(dropped))
	}
	if v4, v6, err := xe.MapEntries(); err == nil {
		metrics.XdpMapEntries.WithLabelValues("v4").Set(float64(v4))
		metrics.XdpMapEntries.WithLabelValues("v6").Set(float64(v6))
	}
}

// runXdpMaintenance periodically refreshes metrics and re-runs reconcile so
// DB<->map drift self-heals well before the next restart.
func (d *Daemon) runXdpMaintenance(ctx context.Context) {
	if d.currentXdp() == nil {
		return
	}
	metricsTick := time.NewTicker(15 * time.Second)
	reconcileTick := time.NewTicker(5 * time.Minute)
	defer metricsTick.Stop()
	defer reconcileTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-metricsTick.C:
			d.refreshXdpMetrics()
		case <-reconcileTick.C:
			d.reconcileXdp()
		}
	}
}

// detachXDP is the no-restart kill switch: it detaches the program (pins/maps
// survive) and reverts d.enforcer to the base backend. Safe to call when XDP
// is already off. Re-attaching requires a daemon restart.
func (d *Daemon) detachXDP() string {
	d.enfMu.Lock()
	defer d.enfMu.Unlock()
	if d.xdp == nil {
		return "xdp not attached"
	}
	if err := d.xdp.Close(); err != nil {
		log.Printf("xdp detach: close error: %v", err)
	}
	d.xdp = nil
	d.enforcer = d.base
	metrics.XdpAttached.Reset()
	msg := fmt.Sprintf("xdp detached; now on %s", d.base.Name())
	log.Print(msg)
	return msg
}

// xdpStatusMap is the GET /api/v1/xdp/status payload.
func (d *Daemon) xdpStatusMap() map[string]interface{} {
	xe := d.currentXdp()
	if xe == nil {
		return map[string]interface{}{"enabled": d.cfg.Enforcer.XDP.Enabled, "attached": false}
	}
	v4, v6, _ := xe.MapEntries()
	passed, dropped, _ := xe.Stats()
	return map[string]interface{}{
		"enabled":                d.cfg.Enforcer.XDP.Enabled,
		"attached":               xe.Attached(),
		"mode":                   xe.Mode(),
		"standalone":             d.cfg.Enforcer.XDP.Standalone,
		"map_entries_v4":         v4,
		"map_entries_v6":         v6,
		"packets_passed":         passed,
		"packets_dropped":        dropped,
		"last_reconcile_removed": d.lastReconcileRemoved,
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

	if enf := d.currentEnforcer(); enf != nil && !d.engine.DryRun() {
		if err := enf.Ban(banAction.IP, banAction.Duration, banAction.Reason); err != nil {
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
				if enf := d.currentEnforcer(); enf != nil && ban.Status != "dry_run" {
					if err := enf.Unban(net.ParseIP(ban.IP)); err != nil {
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
	bans, err := d.store.ListEnforcedBans()
	if err != nil {
		log.Printf("error restoring bans: %v", err)
		return
	}
	restored := 0
	for _, ban := range bans {
		ip := net.ParseIP(ban.IP)
		if ip == nil {
			continue
		}
		// An IP banned-then-whitelisted while the daemon was down must never be
		// re-applied to ANY backend. Mark the stale row expired and skip it.
		if d.whitelist.Contains(ip) {
			d.store.UpdateBanStatus(ban.ID, "expired")
			log.Printf("restore: %s is now whitelisted; marking ban expired, not re-applying", ban.IP)
			continue
		}
		if d.enforcer != nil {
			d.enforcer.Ban(ip, ban.Duration, ban.Reason)
			restored++
		}
	}
	if restored > 0 {
		log.Printf("restored %d active bans to enforcer", restored)
	}
}
