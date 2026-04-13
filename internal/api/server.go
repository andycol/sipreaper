package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/andycol/sipreaper/internal/store"
)

type Server struct {
	store     *store.Store
	token     string
	listen    string
	startTime time.Time
}

func NewServer(s *store.Store, token, listen string) *Server {
	return &Server{
		store:     s,
		token:     token,
		listen:    listen,
		startTime: time.Now(),
	}
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

	return mux
}

func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.listen, s.Handler())
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
