package api

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/andycol/sipreaper/internal/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	store           *store.Store
	token           string
	listen          string
	startTime       time.Time
	httpSrv         *http.Server
	logTailerStat   func() (matched, unmatched uint64)
	syslogStat      func() (matched, unmatched uint64)
	healthChecks    func() map[string]string
	isWhitelisted   func(net.IP) bool
	banFn           func(net.IP, time.Duration, string) error
	unbanFn         func(net.IP) error
	reloadWhitelist func()
	xdpStatus       func() map[string]interface{}
	xdpDetach       func() string
	countryLookup   func(net.IP) (code, name string, ok bool)
}

func NewServer(s *store.Store, token, listen string) *Server {
	srv := &Server{
		store:     s,
		token:     token,
		listen:    listen,
		startTime: time.Now(),
	}
	srv.httpSrv = &http.Server{
		Addr:    listen,
		Handler: srv.Handler(),
	}
	return srv
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/status", s.authMiddleware(s.handleStatus))
	mux.HandleFunc("GET /api/v1/bans", s.authMiddleware(s.handleListBans))
	mux.HandleFunc("POST /api/v1/bans", s.authMiddleware(s.handleCreateBan))
	mux.HandleFunc("DELETE /api/v1/bans/{ip}", s.authMiddleware(s.handleDeleteBan))
	mux.HandleFunc("GET /api/v1/whitelist", s.authMiddleware(s.handleListWhitelist))
	mux.HandleFunc("POST /api/v1/whitelist", s.authMiddleware(s.handleAddWhitelist))
	mux.HandleFunc("DELETE /api/v1/whitelist/{ip...}", s.authMiddleware(s.handleRemoveWhitelist))
	mux.HandleFunc("GET /api/v1/events", s.authMiddleware(s.handleListEvents))
	mux.HandleFunc("GET /api/v1/stats", s.authMiddleware(s.handleStats))
	mux.HandleFunc("GET /api/v1/xdp/status", s.authMiddleware(s.handleXdpStatus))
	mux.HandleFunc("POST /api/v1/xdp/detach", s.authMiddleware(s.handleXdpDetach))

	// /healthz is intentionally unauthenticated so monitoring (k8s probes,
	// load balancers) can hit it without secrets. It returns no sensitive
	// detail beyond up/down per subsystem.
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// /metrics is also unauthenticated by convention — Prometheus scrape jobs
	// expect a clean endpoint. If you want auth, front it with nginx and a
	// scrape-only credential.
	mux.Handle("GET /metrics", promhttp.Handler())

	return mux
}

func (s *Server) ListenAndServe() error {
	return s.httpSrv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// SetLogTailerStats wires the log tailer's parser counters to the /stats
// endpoint so operators can see at a glance whether the tailer is matching
// the lines it sees.
func (s *Server) SetLogTailerStats(fn func() (matched, unmatched uint64)) {
	s.logTailerStat = fn
}

func (s *Server) SetSyslogStats(fn func() (matched, unmatched uint64)) {
	s.syslogStat = fn
}

// SetHealthChecks registers a function that returns subsystem statuses keyed
// by subsystem name (e.g. "store" -> "ok", "log_tailer" -> "stalled"). Any
// non-"ok" value flips /healthz to 503.
func (s *Server) SetHealthChecks(fn func() map[string]string) {
	s.healthChecks = fn
}

// SetWhitelistGuard wires a whitelist-membership function so manual ban
// requests can be refused if the operator tried to ban a whitelisted IP.
func (s *Server) SetWhitelistGuard(fn func(net.IP) bool) {
	s.isWhitelisted = fn
}

// SetBanFunc wires the firewall enforcer's Ban so manual API bans have the
// same network-layer effect as detector-driven bans.
func (s *Server) SetBanFunc(fn func(net.IP, time.Duration, string) error) {
	s.banFn = fn
}

// SetUnbanFunc wires the firewall enforcer's Unban so the whitelist endpoint
// can atomically clear an existing ban when ?clear_ban=true is set.
func (s *Server) SetUnbanFunc(fn func(net.IP) error) {
	s.unbanFn = fn
}

// SetReloadWhitelistFunc wires a callback that reloads the dynamic whitelist
// into the running engine after it changes via the API.
func (s *Server) SetReloadWhitelistFunc(fn func()) {
	s.reloadWhitelist = fn
}

// SetXdpStatusFunc wires a callback returning the current XDP enforcer status
// (attached, mode, map sizes, last reconcile) for GET /api/v1/xdp/status.
func (s *Server) SetXdpStatusFunc(fn func() map[string]interface{}) {
	s.xdpStatus = fn
}

// SetXdpDetachFunc wires the no-restart kill switch behind
// POST /api/v1/xdp/detach: it detaches the XDP program and reverts to the base
// enforcer. Returns a human-readable status message.
func (s *Server) SetXdpDetachFunc(fn func() string) {
	s.xdpDetach = fn
}

func (s *Server) SetCountryLookupFunc(fn func(net.IP) (code, name string, ok bool)) {
	s.countryLookup = fn
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" {
			next(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Constant-time compare. Equal-length is required for ConstantTimeCompare
		// to actually do constant-time work — otherwise it short-circuits on the
		// length check.
		got := []byte(auth[7:])
		want := []byte(s.token)
		if subtle.ConstantTimeEq(int32(len(got)), int32(len(want))) != 1 ||
			subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
