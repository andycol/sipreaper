package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	bans, _ := s.store.ListBans("active")
	resp := map[string]interface{}{
		"status":      "running",
		"uptime":      time.Since(s.startTime).String(),
		"active_bans": len(bans),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "active"
	}
	bans, err := s.store.ListBans(status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if bans == nil {
		bans = []models.BanEntry{}
	}
	writeJSON(w, http.StatusOK, bans)
}

type createBanRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"`
}

func (s *Server) handleCreateBan(w http.ResponseWriter, r *http.Request) {
	var req createBanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var dur time.Duration
	if req.Duration != "" {
		var err error
		dur, err = time.ParseDuration(req.Duration)
		if err != nil {
			http.Error(w, "invalid duration", http.StatusBadRequest)
			return
		}
	}

	var expiresAt *time.Time
	if dur > 0 {
		t := time.Now().Add(dur)
		expiresAt = &t
	}

	entry := models.BanEntry{
		IP:        req.IP,
		Detector:  "manual",
		Reason:    "manual ban via API",
		Severity:  "medium",
		BannedAt:  time.Now(),
		Duration:  dur,
		ExpiresAt: expiresAt,
		BanCount:  1,
		Status:    "manual",
	}

	id, err := s.store.CreateBan(entry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	entry.ID = id
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleDeleteBan(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")

	ban, err := s.store.GetActiveBanByIP(ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ban == nil {
		http.Error(w, "ban not found", http.StatusNotFound)
		return
	}

	if err := s.store.UpdateBanStatus(ban.ID, "expired"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "ip": ip})
}

func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListWhitelist()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []models.WhitelistEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

type addWhitelistRequest struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req addWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	id, err := s.store.AddWhitelist(req.IP, req.Comment, "dynamic")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{"id": id, "ip": req.IP})
}

func (s *Server) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")

	if err := s.store.RemoveWhitelist(ip); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "ip": ip})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	detector := r.URL.Query().Get("detector")

	var since time.Duration
	if last := r.URL.Query().Get("last"); last != "" {
		if d, err := time.ParseDuration(last); err == nil {
			since = d
		}
	}

	events, err := s.store.ListEvents(ip, detector, since, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []models.SIPEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	bans, _ := s.store.ListBans("")
	activeBans, _ := s.store.ListBans("active")

	detectorCounts := make(map[string]int)
	ipCounts := make(map[string]int)
	for _, b := range bans {
		detectorCounts[b.Detector]++
		ipCounts[b.IP]++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_bans":       len(bans),
		"active_bans":      len(activeBans),
		"bans_by_detector": detectorCounts,
		"bans_by_ip":       ipCounts,
	})
}

func writeJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}
