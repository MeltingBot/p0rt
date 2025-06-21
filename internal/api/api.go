package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/p0rt/p0rt/internal/domain"
	"github.com/p0rt/p0rt/internal/security"
	"github.com/p0rt/p0rt/internal/stats"
)

// SecurityProvider interface for getting security data
type SecurityProvider interface {
	GetSecurityStats() security.SecurityStats
	GetBannedIPs() []security.BannedIP
}

// Handler handles API requests
type Handler struct {
	reservationManager domain.ReservationManagerInterface
	statsManager       *stats.Manager
	securityProvider   SecurityProvider
	apiKey             string // Optional API key for authentication
}

// NewHandler creates a new API handler
func NewHandler(reservationManager domain.ReservationManagerInterface, statsManager *stats.Manager, apiKey string) *Handler {
	return &Handler{
		reservationManager: reservationManager,
		statsManager:       statsManager,
		apiKey:             apiKey,
	}
}

// NewHandlerWithSecurity creates a new API handler with security provider
func NewHandlerWithSecurity(reservationManager domain.ReservationManagerInterface, statsManager *stats.Manager, securityProvider SecurityProvider, apiKey string) *Handler {
	return &Handler{
		reservationManager: reservationManager,
		statsManager:       statsManager,
		securityProvider:   securityProvider,
		apiKey:             apiKey,
	}
}

// RegisterRoutes registers all API routes
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// API v1 routes
	mux.HandleFunc("/api/v1/reservations", h.handleReservations)
	mux.HandleFunc("/api/v1/reservations/", h.handleReservation)
	mux.HandleFunc("/api/v1/stats", h.handleStats)
	mux.HandleFunc("/api/v1/stats/tunnel/", h.handleTunnelStats)
	mux.HandleFunc("/api/v1/history", h.handleHistory)
	mux.HandleFunc("/api/v1/connections", h.handleConnections)
	mux.HandleFunc("/api/v1/security/stats", h.handleSecurityStats)
	mux.HandleFunc("/api/v1/security/bans", h.handleSecurityBans)
	mux.HandleFunc("/api/v1/status", h.handleStatus)
}

// authenticateRequest checks if the request is authenticated
func (h *Handler) authenticateRequest(r *http.Request) bool {
	if h.apiKey == "" {
		// No API key configured, allow all requests
		return true
	}

	providedKey := ""

	// Check API key in header
	if headerKey := r.Header.Get("X-API-Key"); headerKey != "" {
		providedKey = headerKey
		if headerKey == h.apiKey {
			return true
		}
	}

	// Check API key in query parameter
	if queryKey := r.URL.Query().Get("api_key"); queryKey != "" {
		providedKey = queryKey
		if queryKey == h.apiKey {
			return true
		}
	}

	// Log authentication failure only in verbose mode
	if os.Getenv("P0RT_VERBOSE") == "true" {
		log.Printf("API Authentication failed: expected=%s, provided=%s, from=%s",
			h.apiKey, providedKey, r.RemoteAddr)
	}

	return false
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error":     true,
		"message":   message,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleReservations handles /api/v1/reservations endpoint
func (h *Handler) handleReservations(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		// List all reservations
		reservations := h.reservationManager.ListReservations()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":      true,
			"reservations": reservations,
			"count":        len(reservations),
			"timestamp":    time.Now().Format(time.RFC3339),
		})

	case http.MethodPost:
		// Add new reservation
		var req struct {
			Domain      string `json:"domain"`
			Fingerprint string `json:"fingerprint"`
			Comment     string `json:"comment"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if req.Domain == "" || req.Fingerprint == "" {
			writeError(w, http.StatusBadRequest, "Domain and fingerprint are required")
			return
		}

		if err := h.reservationManager.AddReservation(req.Domain, req.Fingerprint, req.Comment); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"success":   true,
			"message":   fmt.Sprintf("Reservation created for domain %s", req.Domain),
			"domain":    req.Domain,
			"timestamp": time.Now().Format(time.RFC3339),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleReservation handles /api/v1/reservations/{domain} endpoint
func (h *Handler) handleReservation(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract domain from path
	domain := r.URL.Path[len("/api/v1/reservations/"):]
	if domain == "" {
		writeError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Check if reservation exists
		reservations := h.reservationManager.ListReservations()
		for _, res := range reservations {
			if res.Domain == domain {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"success":     true,
					"reservation": res,
					"timestamp":   time.Now().Format(time.RFC3339),
				})
				return
			}
		}
		writeError(w, http.StatusNotFound, "Reservation not found")

	case http.MethodDelete:
		// Remove reservation
		if err := h.reservationManager.RemoveReservation(domain); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":   true,
			"message":   fmt.Sprintf("Reservation removed for domain %s", domain),
			"domain":    domain,
			"timestamp": time.Now().Format(time.RFC3339),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleStats handles /api/v1/stats endpoint
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get global stats
	var globalStats interface{}
	if h.statsManager != nil {
		globalStats = h.statsManager.GetGlobalStats()
	}

	// Get reservation stats
	reservationStats := h.reservationManager.GetStats()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":           true,
		"global_stats":      globalStats,
		"reservation_stats": reservationStats,
		"timestamp":         time.Now().Format(time.RFC3339),
	})
}

// handleTunnelStats handles /api/v1/stats/tunnel/{domain} endpoint
func (h *Handler) handleTunnelStats(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract domain from path
	domain := r.URL.Path[len("/api/v1/stats/tunnel/"):]
	if domain == "" {
		writeError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	if h.statsManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Stats manager not available")
		return
	}

	tunnelStats := h.statsManager.GetTunnelStats(domain)
	if tunnelStats == nil {
		writeError(w, http.StatusNotFound, "No statistics found for this domain")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"tunnel_stats": tunnelStats,
		"timestamp":    time.Now().Format(time.RFC3339),
	})
}

// handleStatus handles /api/v1/status endpoint
func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Status endpoint doesn't require authentication
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	status := map[string]interface{}{
		"success":     true,
		"service":     "p0rt",
		"version":     "1.0.0",
		"timestamp":   time.Now().Format(time.RFC3339),
		"api_version": "v1",
	}

	// Add stats if available
	if h.statsManager != nil {
		globalStats := h.statsManager.GetGlobalStats()
		status["uptime"] = globalStats.Uptime
		status["active_tunnels"] = globalStats.ActiveTunnels
	}

	writeJSON(w, http.StatusOK, status)
}

// handleSecurityStats handles /api/v1/security/stats endpoint
func (h *Handler) handleSecurityStats(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var securityStats interface{}
	var note string

	if h.securityProvider != nil {
		// Get real security data from the SSH server
		stats := h.securityProvider.GetSecurityStats()
		securityStats = stats
		note = "Real-time security data from SSH server"
	} else {
		// Fallback to placeholder data
		securityStats = map[string]interface{}{
			"authentication_failures": 0,
			"blocked_ips_count":       0,
			"scanning_attempts":       0,
			"abuse_reports":           0,
			"last_24h_failures":       0,
			"geographic_blocks":       map[string]int{},
			"ban_reasons": map[string]int{
				"brute_force": 0,
				"scanning":    0,
				"abuse":       0,
			},
		}
		note = "No security provider configured - showing placeholder data"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"security_stats": securityStats,
		"timestamp":      time.Now().Format(time.RFC3339),
		"note":           note,
	})
}

// handleSecurityBans handles /api/v1/security/bans endpoint
func (h *Handler) handleSecurityBans(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var bannedIPs interface{}
	var note string

	if h.securityProvider != nil {
		// Get real ban data from the SSH server
		bans := h.securityProvider.GetBannedIPs()
		bannedIPs = bans
		note = "Real-time ban data from SSH server"
	} else {
		// Fallback to empty list
		bannedIPs = []map[string]interface{}{}
		note = "No security provider configured - showing placeholder data"
	}

	// Convert to slice for counting
	var banCount int
	if bans, ok := bannedIPs.([]security.BannedIP); ok {
		banCount = len(bans)
	} else if bans, ok := bannedIPs.([]map[string]interface{}); ok {
		banCount = len(bans)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"banned_ips": bannedIPs,
		"total_bans": banCount,
		"timestamp":  time.Now().Format(time.RFC3339),
		"note":       note,
	})
}

// handleHistory handles /api/v1/history endpoint
func (h *Handler) handleHistory(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if h.statsManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Stats manager not available")
		return
	}

	// Get limit from query parameter
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	history := h.statsManager.GetConnectionHistory(limit)
	
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"history":     history,
		"count":       len(history),
		"limit":       limit,
		"timestamp":   time.Now().Format(time.RFC3339),
	})
}

// handleConnections handles /api/v1/connections endpoint
func (h *Handler) handleConnections(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if h.statsManager == nil {
		writeError(w, http.StatusServiceUnavailable, "Stats manager not available")
		return
	}

	connections := h.statsManager.GetActiveConnections()
	
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"connections":  connections,
		"count":        len(connections),
		"timestamp":    time.Now().Format(time.RFC3339),
	})
}
