package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/andycol/sipreaper/internal/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	store         *store.Store
	token         string
	listen        string
	startTime     time.Time
	httpSrv       *http.Server
	logTailerStat func() (matched, unmatched uint64)
	healthChecks  func() map[string]string
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
	mux.HandleFunc("DELETE /api/v1/whitelist/{ip}", s.authMiddleware(s.handleRemoveWhitelist))
	mux.HandleFunc("GET /api/v1/events", s.authMiddleware(s.handleListEvents))
	mux.HandleFunc("GET /api/v1/stats", s.authMiddleware(s.handleStats))

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

// SetHealthChecks registers a function that returns subsystem statuses keyed
// by subsystem name (e.g. "store" -> "ok", "log_tailer" -> "stalled"). Any
// non-"ok" value flips /healthz to 503.
func (s *Server) SetHealthChecks(fn func() map[string]string) {
	s.healthChecks = fn
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" {
			next(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || auth[7:] != s.token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
