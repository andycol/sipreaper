package decision

import (
	"log"
	"time"

	"github.com/andycol/sipreaper/internal/models"
	"github.com/andycol/sipreaper/internal/store"
	"github.com/andycol/sipreaper/internal/whitelist"
)

type Engine struct {
	store     *store.Store
	whitelist *whitelist.Whitelist
	durations []time.Duration
	cooldown  time.Duration
	dryRun    bool
}

func New(s *store.Store, wl *whitelist.Whitelist, durations []time.Duration, cooldown time.Duration) *Engine {
	return &Engine{
		store:     s,
		whitelist: wl,
		durations: durations,
		cooldown:  cooldown,
	}
}

// SetDryRun toggles shadow mode. When true, evaluations still record into the
// store with status="dry_run" so they can be queried for tuning, but the
// daemon will not invoke the enforcer. Existing dry_run records are not
// re-applied on restart.
func (e *Engine) SetDryRun(b bool) { e.dryRun = b }

// DryRun reports whether the engine is in shadow mode.
func (e *Engine) DryRun() bool { return e.dryRun }

func (e *Engine) Evaluate(threat models.Threat) *models.BanAction {
	ip := threat.SourceIP

	// Whitelist check
	if e.whitelist.Contains(ip) {
		log.Printf("decision: threat from whitelisted IP %s (%s), skipping ban", ip, threat.Detector)
		return nil
	}

	ipStr := ip.String()

	// Already banned check
	existing, err := e.store.GetActiveBanByIP(ipStr)
	if err != nil {
		log.Printf("decision: error checking existing ban for %s: %v", ipStr, err)
		return nil
	}
	if existing != nil {
		return nil
	}

	// Determine escalation level
	since := time.Now().Add(-e.cooldown)
	priorCount, err := e.store.BanCountByIP(ipStr, since)
	if err != nil {
		log.Printf("decision: error getting ban count for %s: %v", ipStr, err)
		priorCount = 0
	}

	banCount := priorCount + 1
	duration := e.durationForCount(priorCount)

	// Record ban
	var expiresAt *time.Time
	if duration > 0 {
		t := time.Now().Add(duration)
		expiresAt = &t
	}

	status := "active"
	if e.dryRun {
		status = "dry_run"
	}

	_, err = e.store.CreateBan(models.BanEntry{
		IP:        ipStr,
		Detector:  threat.Detector,
		Reason:    threat.Description,
		Severity:  threat.Severity,
		BannedAt:  time.Now(),
		Duration:  duration,
		ExpiresAt: expiresAt,
		BanCount:  banCount,
		Status:    status,
	})
	if err != nil {
		log.Printf("decision: error creating ban for %s: %v", ipStr, err)
		return nil
	}

	return &models.BanAction{
		IP:       ip,
		Duration: duration,
		Reason:   threat.Description,
		Detector: threat.Detector,
		Severity: threat.Severity,
		BanCount: banCount,
	}
}

func (e *Engine) durationForCount(priorCount int) time.Duration {
	if len(e.durations) == 0 {
		return 5 * time.Minute
	}
	idx := priorCount
	if idx >= len(e.durations) {
		idx = len(e.durations) - 1
	}
	return e.durations[idx]
}
