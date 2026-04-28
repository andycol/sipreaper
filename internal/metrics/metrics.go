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
)
