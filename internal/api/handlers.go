package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	bans, _ := s.store.ListEnforcedBans()
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
		status = "current"
	}
	bans, err := s.store.ListBansFiltered(status, r.URL.Query().Get("ip"))
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

	ip := net.ParseIP(req.IP)
	if ip == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}

	if s.isWhitelisted != nil && s.isWhitelisted(ip) {
		http.Error(w, "ip is whitelisted; remove from whitelist before banning", http.StatusConflict)
		return
	}
	if existing, err := s.store.GetActiveBanByIP(ip.String()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if existing != nil {
		http.Error(w, "ip already has a current ban", http.StatusConflict)
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
		IP:        ip.String(),
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
	if s.banFn != nil {
		if err := s.banFn(ip, dur, entry.Reason); err != nil {
			_ = s.store.UpdateBanStatus(id, "expired")
			http.Error(w, fmt.Sprintf("ban was not applied by enforcer: %v", err), http.StatusInternalServerError)
			return
		}
	}

	entry.ID = id
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleDeleteBan(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	parsed := net.ParseIP(ip)
	if parsed == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}

	ban, err := s.store.GetActiveBanByIP(parsed.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ban == nil {
		http.Error(w, "ban not found", http.StatusNotFound)
		return
	}
	if s.unbanFn != nil && ban.Status != "dry_run" {
		if err := s.unbanFn(parsed); err != nil {
			http.Error(w, fmt.Sprintf("ban was not removed by enforcer: %v", err), http.StatusInternalServerError)
			return
		}
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
	IP       string `json:"ip"`
	Comment  string `json:"comment"`
	ClearBan bool   `json:"clear_ban"`
}

func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req addWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate the IP/CIDR string. Whitelist accepts both — try IP first, fall
	// back to CIDR. We don't normalise CIDRs here because the whitelist code
	// already handles bare-IP "/32"/"/128" expansion.
	if net.ParseIP(req.IP) == nil {
		if _, _, err := net.ParseCIDR(req.IP); err != nil {
			http.Error(w, "invalid ip or cidr", http.StatusBadRequest)
			return
		}
	}

	banned, err := s.currentBansCoveredBy(req.IP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(banned) > 0 {
		if !req.ClearBan {
			http.Error(w,
				fmt.Sprintf("whitelist overlaps %d current ban(s); pass clear_ban=true to atomically unban then whitelist", len(banned)),
				http.StatusConflict)
			return
		}
		for _, existing := range banned {
			ip := net.ParseIP(existing.IP)
			if ip == nil {
				continue
			}
			if s.unbanFn != nil && existing.Status != "dry_run" {
				if err := s.unbanFn(ip); err != nil {
					http.Error(w, fmt.Sprintf("ban for %s was not removed by enforcer: %v", existing.IP, err), http.StatusInternalServerError)
					return
				}
			}
			if err := s.store.UpdateBanStatus(existing.ID, "expired"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	entry, err := s.store.AddWhitelist(req.IP, req.Comment, "dynamic")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if s.reloadWhitelist != nil {
		s.reloadWhitelist()
	}

	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")

	if err := s.store.RemoveWhitelist(ip); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.reloadWhitelist != nil {
		s.reloadWhitelist()
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "ip": ip})
}

func (s *Server) currentBansCoveredBy(ipOrCIDR string) ([]models.BanEntry, error) {
	if ip := net.ParseIP(ipOrCIDR); ip != nil {
		ban, err := s.store.GetActiveBanByIP(ip.String())
		if err != nil || ban == nil {
			return nil, err
		}
		return []models.BanEntry{*ban}, nil
	}

	_, n, err := net.ParseCIDR(ipOrCIDR)
	if err != nil {
		return nil, err
	}
	current, err := s.store.ListBansFiltered("current", "")
	if err != nil {
		return nil, err
	}
	var out []models.BanEntry
	for _, ban := range current {
		ip := net.ParseIP(ban.IP)
		if ip != nil && n.Contains(ip) {
			out = append(out, ban)
		}
	}
	return out, nil
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
	activeBans, _ := s.store.ListEnforcedBans()

	detectorCounts := make(map[string]int)
	ipCounts := make(map[string]int)
	for _, b := range bans {
		detectorCounts[b.Detector]++
		ipCounts[b.IP]++
	}

	resp := map[string]interface{}{
		"total_bans":       len(bans),
		"active_bans":      len(activeBans),
		"bans_by_detector": detectorCounts,
		"bans_by_ip":       ipCounts,
	}

	if s.logTailerStat != nil {
		matched, unmatched := s.logTailerStat()
		resp["log_tailer"] = map[string]uint64{
			"matched":   matched,
			"unmatched": unmatched,
		}
	}
	if s.syslogStat != nil {
		matched, unmatched := s.syslogStat()
		resp["syslog_ingest"] = map[string]uint64{
			"matched":   matched,
			"unmatched": unmatched,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleXdpStatus(w http.ResponseWriter, r *http.Request) {
	if s.xdpStatus == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, s.xdpStatus())
}

func (s *Server) handleXdpDetach(w http.ResponseWriter, r *http.Request) {
	if s.xdpDetach == nil {
		http.Error(w, "xdp not enabled", http.StatusServiceUnavailable)
		return
	}
	msg := s.xdpDetach()
	writeJSON(w, http.StatusOK, map[string]string{"status": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	if err := s.store.HealthCheck(); err != nil {
		checks["store"] = "error: " + err.Error()
	} else {
		checks["store"] = "ok"
	}

	if s.healthChecks != nil {
		for k, v := range s.healthChecks() {
			checks[k] = v
		}
	}

	// A "degraded:"-prefixed value is informational and must NOT fail the probe
	// (fail-open ethos — e.g. XDP enabled-but-not-attached while the base
	// enforcer still protects). Only hard-down subsystems flip /healthz to 503.
	overall := http.StatusOK
	degraded := false
	for _, v := range checks {
		switch {
		case v == "ok":
		case strings.HasPrefix(v, "ok"), strings.HasPrefix(v, "degraded"):
			degraded = true
		default:
			overall = http.StatusServiceUnavailable
		}
	}

	resp := map[string]interface{}{
		"status": "ok",
		"checks": checks,
		"uptime": time.Since(s.startTime).String(),
	}
	if overall != http.StatusOK {
		resp["status"] = "unhealthy"
	} else if degraded {
		resp["status"] = "degraded"
	}
	writeJSON(w, overall, resp)
}

func writeJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}
