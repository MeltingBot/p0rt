package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/p0rt/p0rt/internal/auth"
	"github.com/p0rt/p0rt/internal/config"
	"github.com/p0rt/p0rt/internal/domain"
	"github.com/p0rt/p0rt/internal/metrics"
	"github.com/p0rt/p0rt/internal/security"
	"github.com/p0rt/p0rt/internal/stats"
)

// SecurityProvider interface for getting security data
type SecurityProvider interface {
	GetSecurityStats() security.SecurityStats
	GetBannedIPs() []security.BannedIP
	UnbanIP(ip string)
	UnbanIPFromTracker(ip string)
}

// SSHNotificationProvider interface for sending notifications to SSH clients
type SSHNotificationProvider interface {
	NotifyDomainBanned(domain string)
	NotifyDomain(domain, message string)
}

// Handler handles API requests
type Handler struct {
	reservationManager domain.ReservationManagerInterface
	statsManager       *stats.Manager
	securityProvider   SecurityProvider
	sshNotifier        SSHNotificationProvider
	keyStore           auth.KeyStoreInterface
	apiKey             string // Optional API key for authentication
}

// NewHandler creates a new API handler
func NewHandler(reservationManager domain.ReservationManagerInterface, statsManager *stats.Manager, apiKey string) *Handler {
	keyStore, _ := auth.NewKeyStoreFromConfig()
	return &Handler{
		reservationManager: reservationManager,
		statsManager:       statsManager,
		keyStore:           keyStore,
		apiKey:             apiKey,
	}
}

// NewHandlerWithSecurity creates a new API handler with security provider
func NewHandlerWithSecurity(reservationManager domain.ReservationManagerInterface, statsManager *stats.Manager, securityProvider SecurityProvider, apiKey string) *Handler {
	keyStore, _ := auth.NewKeyStoreFromConfig()
	return &Handler{
		reservationManager: reservationManager,
		statsManager:       statsManager,
		securityProvider:   securityProvider,
		keyStore:           keyStore,
		apiKey:             apiKey,
	}
}

// NewHandlerWithSSH creates a new API handler with SSH notification support
func NewHandlerWithSSH(reservationManager domain.ReservationManagerInterface, statsManager *stats.Manager, securityProvider SecurityProvider, sshNotifier SSHNotificationProvider, apiKey string) *Handler {
	keyStore, _ := auth.NewKeyStoreFromConfig()
	return &Handler{
		reservationManager: reservationManager,
		statsManager:       statsManager,
		securityProvider:   securityProvider,
		sshNotifier:        sshNotifier,
		keyStore:           keyStore,
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
	mux.HandleFunc("/api/v1/security/unban", h.handleSecurityUnban)
	mux.HandleFunc("/api/v1/abuse/reports", h.handleAbuseReports)
	mux.HandleFunc("/api/v1/abuse/reports/", h.handleAbuseReport)
	mux.HandleFunc("/api/v1/abuse/stats", h.handleAbuseStats)
	mux.HandleFunc("/api/v1/access", h.handleAccess)
	mux.HandleFunc("/api/v1/status", h.handleStatus)

	// SSH key management endpoints
	mux.HandleFunc("/api/v1/keys", h.handleKeys)
	mux.HandleFunc("/api/v1/keys/", h.handleKey)

	// Server management endpoints
	mux.HandleFunc("/api/v1/server/status", h.handleServerStatus)
	mux.HandleFunc("/api/v1/server/reload", h.handleServerReload)

	// Notification endpoints
	mux.HandleFunc("/api/v1/notifications/test", h.handleNotificationTest)
	mux.HandleFunc("/api/v1/notifications/domain", h.handleNotificationBanDomain)
	mux.HandleFunc("/api/v1/notifications/ban-domain", h.handleNotificationBanDomain)

	// Metrics endpoint for admin dashboard
	mux.HandleFunc("/api/v1/metrics/dashboard", h.handleDashboardMetrics)

	// Domain management endpoints
	mux.HandleFunc("/api/v1/domains", h.handleDomains)
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

// getConfig loads the configuration (helper for API handlers)
func (h *Handler) getConfig() (*config.Config, error) {
	return config.Load()
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

	// Parse pagination parameters
	query := r.URL.Query()
	limit := 50 // Default limit
	offset := 0

	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	if offsetStr := query.Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	var bannedIPs []security.BannedIP
	var totalCount int
	var note string

	if h.securityProvider != nil {
		// Get real ban data from the SSH server
		allBans := h.securityProvider.GetBannedIPs()
		totalCount = len(allBans)

		// Apply pagination
		start := offset
		end := offset + limit

		if start < totalCount {
			if end > totalCount {
				end = totalCount
			}
			bannedIPs = allBans[start:end]
		} else {
			bannedIPs = []security.BannedIP{}
		}

		note = "Real-time ban data from SSH server"
	} else {
		// Fallback to empty list
		bannedIPs = []security.BannedIP{}
		totalCount = 0
		note = "No security provider configured - showing placeholder data"
	}

	// Calculate pagination metadata
	hasNext := offset+limit < totalCount
	hasPrev := offset > 0

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"banned_ips": bannedIPs,
		"total_bans": totalCount,
		"count":      len(bannedIPs),
		"limit":      limit,
		"offset":     offset,
		"has_next":   hasNext,
		"has_prev":   hasPrev,
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
		"success":   true,
		"history":   history,
		"count":     len(history),
		"limit":     limit,
		"timestamp": time.Now().Format(time.RFC3339),
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
		"success":     true,
		"connections": connections,
		"count":       len(connections),
		"timestamp":   time.Now().Format(time.RFC3339),
	})
}

// handleAccess handles /api/v1/access endpoint
func (h *Handler) handleAccess(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Get current access mode
		currentMode := "restricted"
		if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
			currentMode = "open"
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":     true,
			"access_mode": currentMode,
			"open_access": currentMode == "open",
			"timestamp":   time.Now().Format(time.RFC3339),
		})

	case http.MethodPost:
		// Change access mode
		var req struct {
			Mode string `json:"mode"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if req.Mode != "open" && req.Mode != "restricted" {
			writeError(w, http.StatusBadRequest, "Mode must be 'open' or 'restricted'")
			return
		}

		// Get current mode
		oldMode := "restricted"
		if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
			oldMode = "open"
		}

		// Set new mode
		if req.Mode == "open" {
			os.Setenv("P0RT_OPEN_ACCESS", "true")
		} else {
			os.Setenv("P0RT_OPEN_ACCESS", "false")
		}

		// Update stats manager if available
		if h.statsManager != nil {
			h.statsManager.SetAccessMode(req.Mode)
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":     true,
			"access_mode": req.Mode,
			"old_mode":    oldMode,
			"changed":     oldMode != req.Mode,
			"timestamp":   time.Now().Format(time.RFC3339),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleAbuseReports handles /api/v1/abuse/reports endpoint
func (h *Handler) handleAbuseReports(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get status filter from query parameter
	status := r.URL.Query().Get("status")
	showAll := r.URL.Query().Get("all") == "true"

	if !showAll && status == "" {
		status = "pending"
	}

	// Load config to get Redis URL and create report manager
	cfg, err := h.getConfig()
	var reportManager *security.AbuseReportManager
	if err == nil && cfg.Storage.RedisURL != "" {
		reportManager = security.NewAbuseReportManagerWithRedis(cfg.Storage.RedisURL)
	} else {
		reportManager = security.NewAbuseReportManager()
	}

	reports, err := reportManager.ListReports(status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get abuse reports: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"reports":   reports,
		"count":     len(reports),
		"status":    status,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleAbuseReport handles /api/v1/abuse/reports/{id} endpoint
func (h *Handler) handleAbuseReport(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract report ID from path
	reportID := strings.TrimPrefix(r.URL.Path, "/api/v1/abuse/reports/")
	if reportID == "" {
		writeError(w, http.StatusBadRequest, "Report ID is required")
		return
	}

	// Load config to get Redis URL and create report manager
	cfg, err := h.getConfig()
	var reportManager *security.AbuseReportManager
	if err == nil && cfg.Storage.RedisURL != "" {
		reportManager = security.NewAbuseReportManagerWithRedis(cfg.Storage.RedisURL)
	} else {
		reportManager = security.NewAbuseReportManager()
	}

	switch r.Method {
	case http.MethodGet:
		// Get specific report
		report, err := reportManager.GetReport(reportID)
		if err != nil {
			writeError(w, http.StatusNotFound, fmt.Sprintf("Report not found: %v", err))
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":   true,
			"report":    report,
			"timestamp": time.Now().Format(time.RFC3339),
		})

	case http.MethodPost:
		// Process report (ban/accept)
		var req struct {
			Action string `json:"action"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if req.Action != "ban" && req.Action != "accept" {
			writeError(w, http.StatusBadRequest, "Action must be 'ban' or 'accept'")
			return
		}

		err := reportManager.ProcessReport(reportID, req.Action, "api-admin")
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to process report: %v", err))
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":   true,
			"report_id": reportID,
			"action":    req.Action,
			"timestamp": time.Now().Format(time.RFC3339),
		})

	case http.MethodDelete:
		// Archive/delete report
		err := reportManager.ArchiveReport(reportID, "api-admin")
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to archive report: %v", err))
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":   true,
			"report_id": reportID,
			"action":    "archived",
			"message":   "Report archived and cleanup performed",
			"timestamp": time.Now().Format(time.RFC3339),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleDashboardMetrics returns Prometheus metrics formatted for the admin dashboard
func (h *Handler) handleDashboardMetrics(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Only allow GET method
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Collect metrics from Prometheus
	ctx := context.Background()
	dashboardMetrics, err := metrics.CollectDashboardMetrics(ctx)
	if err != nil {
		log.Printf("Error collecting dashboard metrics: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to collect metrics")
		return
	}

	// Return metrics as JSON
	writeJSON(w, http.StatusOK, dashboardMetrics)
}

// handleAbuseStats handles /api/v1/abuse/stats endpoint
func (h *Handler) handleAbuseStats(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Load config to get Redis URL and create report manager
	cfg, err := h.getConfig()
	var reportManager *security.AbuseReportManager
	if err == nil && cfg.Storage.RedisURL != "" {
		reportManager = security.NewAbuseReportManagerWithRedis(cfg.Storage.RedisURL)
	} else {
		reportManager = security.NewAbuseReportManager()
	}

	stats := reportManager.GetStats()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"stats":     stats,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleSecurityUnban handles /api/v1/security/unban endpoint
func (h *Handler) handleSecurityUnban(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body
	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.IP == "" {
		writeError(w, http.StatusBadRequest, "IP address is required")
		return
	}

	// Unban the IP using the security provider
	if h.securityProvider != nil {
		h.securityProvider.UnbanIP(req.IP)
		h.securityProvider.UnbanIPFromTracker(req.IP)
		log.Printf("🔓 API: Successfully unbanned IP %s", req.IP)
	} else {
		writeError(w, http.StatusServiceUnavailable, "Security provider not available")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   fmt.Sprintf("IP %s has been unbanned", req.IP),
		"ip":        req.IP,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// DomainInfo represents information about a domain and its usage
type DomainInfo struct {
	Domain            string     `json:"domain"`
	SSHKeyHash        string     `json:"ssh_key_hash"`
	SSHKeyFingerprint string     `json:"ssh_key_fingerprint,omitempty"`
	FirstSeen         time.Time  `json:"first_seen"`
	LastSeen          time.Time  `json:"last_seen"`
	LastConnectionIP  string     `json:"last_connection_ip"`
	LastActivity      *time.Time `json:"last_activity,omitempty"`
	UseCount          int        `json:"use_count"`
	IsActive          bool       `json:"is_active"`
	BytesTransferred  int64      `json:"bytes_transferred"`
	RequestCount      int64      `json:"request_count"`
}

// DomainsResponse represents the paginated response for domains
type DomainsResponse struct {
	Domains    []DomainInfo `json:"domains"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PerPage    int          `json:"per_page"`
	TotalPages int          `json:"total_pages"`
	HasNext    bool         `json:"has_next"`
	HasPrev    bool         `json:"has_prev"`
}

// handleDomains returns a paginated list of all domains with their SSH keys and usage information
func (h *Handler) handleDomains(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse pagination parameters
	page := 1
	perPage := 50 // Default per page

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if perPageStr := r.URL.Query().Get("per_page"); perPageStr != "" {
		if pp, err := strconv.Atoi(perPageStr); err == nil && pp > 0 && pp <= 500 {
			perPage = pp
		}
	}

	// Get domain information from connection history
	allDomains := []DomainInfo{}

	if h.statsManager != nil {
		// Get connection history to build domain list
		connectionHistory := h.statsManager.GetConnectionHistory(1000) // Get more records to have complete domain list

		// Build domain info from connection history
		domainMap := make(map[string]*DomainInfo)

		for _, record := range connectionHistory {
			if existingDomain, exists := domainMap[record.Domain]; exists {
				// Update existing domain info with latest connection data
				existingDomain.UseCount++
				if record.LastActivity.After(existingDomain.LastSeen) {
					existingDomain.LastSeen = record.LastActivity
					existingDomain.LastConnectionIP = record.ClientIP
					existingDomain.SSHKeyFingerprint = record.Fingerprint
					if record.DisconnectedAt == nil {
						existingDomain.LastActivity = &record.LastActivity
					}
				}
				existingDomain.BytesTransferred += record.BytesIn + record.BytesOut
				existingDomain.RequestCount += record.RequestCount
			} else {
				// Create new domain info
				lastActivity := record.LastActivity
				domainInfo := &DomainInfo{
					Domain:            record.Domain,
					SSHKeyFingerprint: record.Fingerprint,
					FirstSeen:         record.ConnectedAt,
					LastSeen:          record.LastActivity,
					LastConnectionIP:  record.ClientIP,
					UseCount:          1,
					IsActive:          false, // Will be determined later
					BytesTransferred:  record.BytesIn + record.BytesOut,
					RequestCount:      record.RequestCount,
				}
				if record.DisconnectedAt == nil {
					domainInfo.LastActivity = &lastActivity
				}
				domainMap[record.Domain] = domainInfo
			}
		}

		// Second pass: determine IsActive status based on ONLY currently active connections
		for _, record := range connectionHistory {
			if domainInfo, exists := domainMap[record.Domain]; exists {
				// A domain is active ONLY if there's at least one record that is:
				// 1. Not disconnected (DisconnectedAt == nil)
				// 2. Marked as active (Active == true)
				if record.DisconnectedAt == nil && record.Active {
					domainInfo.IsActive = true
				}
			}
		}

		// Convert map to slice
		for _, domainInfo := range domainMap {
			allDomains = append(allDomains, *domainInfo)
		}
	}

	// Calculate pagination
	total := len(allDomains)
	totalPages := (total + perPage - 1) / perPage

	// Apply pagination
	start := (page - 1) * perPage
	end := start + perPage
	if end > total {
		end = total
	}

	paginatedDomains := []DomainInfo{}
	if start < total {
		paginatedDomains = allDomains[start:end]
	}

	response := DomainsResponse{
		Domains:    paginatedDomains,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}

	writeJSON(w, http.StatusOK, response)
}
