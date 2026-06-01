// Package metrics holds the Prometheus collectors. Anything that wants to
// observe something (events ingested, threats raised, bans issued) Inc()s a
// counter here and the /metrics endpoint serves the lot.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	EventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sipreaper_events_total",
		Help: "SIP events observed, labelled by ingest source and method.",
	}, []string{"source", "method"})

	ThreatsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sipreaper_threats_total",
		Help: "Threats emitted by detectors, labelled by detector and severity.",
	}, []string{"detector", "severity"})

	BansTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sipreaper_bans_total",
		Help: "Bans issued, labelled by detector.",
	}, []string{"detector"})

	UnbansTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sipreaper_unbans_total",
		Help: "Bans expired and lifted.",
	})

	ActiveBans = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sipreaper_active_bans",
		Help: "Number of currently-active bans.",
	})

	LogTailerMatched = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sipreaper_log_lines_matched_total",
		Help: "Log lines that matched at least one parser.",
	})

	LogTailerUnmatched = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sipreaper_log_lines_unmatched_total",
		Help: "Log lines no parser recognised.",
	})

	EnforcerErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sipreaper_enforcer_errors_total",
		Help: "Enforcer ban/unban errors, labelled by op.",
	}, []string{"op"})

	DetectorPanicsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sipreaper_detector_panics_total",
		Help: "Recovered panics in detector or action pipeline, labelled by component.",
	}, []string{"component"})

	// --- XDP enforcer -----------------------------------------------------

	// XdpAttached is 1 while the XDP program is attached, 0 otherwise, labelled
	// by attach mode (driver/generic). The critical silent-degradation alert
	// fires on `enforcer.xdp.enabled` true but this == 0.
	XdpAttached = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sipreaper_xdp_attached",
		Help: "1 when the XDP program is attached, labelled by mode (driver/generic).",
	}, []string{"mode"})

	// XdpMapEntries is the live size of each ban map, labelled by family.
	XdpMapEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sipreaper_xdp_map_entries",
		Help: "Number of IPs in the XDP ban map, labelled by family (v4/v6).",
	}, []string{"family"})

	// XdpPackets holds the cumulative per-result packet counts the kernel
	// program maintains (result=passed|dropped). Exposed as a gauge because the
	// value is the kernel's running total, refreshed on a ticker.
	XdpPackets = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sipreaper_xdp_packets",
		Help: "Cumulative packets handled by the XDP program, labelled by result (passed/dropped).",
	}, []string{"result"})

	// XdpReconcileRemoved counts map entries removed by reconcile (stale or
	// newly-whitelisted) — surfaces DB<->map drift.
	XdpReconcileRemoved = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sipreaper_xdp_reconcile_removed_total",
		Help: "XDP map entries removed by reconcile (stale or whitelisted).",
	})
)
