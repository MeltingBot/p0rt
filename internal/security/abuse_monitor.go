package security

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/p0rt/p0rt/internal/web"
)

type AbuseMonitor struct {
	// Limites par clé SSH
	connectionLimits map[string]*ConnectionLimit
	limitMutex       sync.RWMutex

	// Patterns suspects
	// Note: HTTP content analysis patterns removed for privacy
	// Only connection-level monitoring remains

	// Alertes
	alertCallback func(domain, reason, details string)

	// Abuse report manager
	reportManager *AbuseReportManager

	// Abuse report form handler
	abuseReportHandler *web.AbuseReportHandler
}

type ConnectionLimit struct {
	Connections  int
	LastReset    time.Time
	Blocked      bool
	BlockedUntil time.Time
}

func NewAbuseMonitor() *AbuseMonitor {
	monitor := &AbuseMonitor{
		connectionLimits:   make(map[string]*ConnectionLimit),
		reportManager:      NewAbuseReportManager(),
		abuseReportHandler: web.NewAbuseReportHandler(),
		// Note: Content analysis removed for privacy - only connection monitoring
	}

	return monitor
}

// CheckDomain - domain filtering disabled for privacy
func (am *AbuseMonitor) CheckDomain(domain string) (bool, string) {
	// All domains allowed - no content filtering for privacy
	return true, ""
}

// CheckConnectionRate limite les connexions par clé SSH
func (am *AbuseMonitor) CheckConnectionRate(sshKeyHash string) bool {
	am.limitMutex.Lock()
	defer am.limitMutex.Unlock()

	now := time.Now()
	limit, exists := am.connectionLimits[sshKeyHash]

	if !exists {
		am.connectionLimits[sshKeyHash] = &ConnectionLimit{
			Connections: 1,
			LastReset:   now,
		}
		return true
	}

	// Vérifier si toujours bloqué
	if limit.Blocked && now.Before(limit.BlockedUntil) {
		return false
	}

	// Reset hourly
	if now.Sub(limit.LastReset) > time.Hour {
		limit.Connections = 1
		limit.LastReset = now
		limit.Blocked = false
		return true
	}

	// Limite: 100 connexions par heure par clé SSH
	limit.Connections++
	if limit.Connections > 100 {
		limit.Blocked = true
		limit.BlockedUntil = now.Add(24 * time.Hour) // Bloquer 24h
		log.Printf("SSH key %s blocked for excessive connections: %d/hour", sshKeyHash[:8], limit.Connections)
		return false
	}

	return true
}

// AnalyzeHTTPRequest - HTTP content analysis disabled for privacy
func (am *AbuseMonitor) AnalyzeHTTPRequest(domain, path, userAgent, referer string) (bool, string) {
	// All HTTP requests allowed - no content inspection for privacy
	return true, ""
}

// ReportAbuse permet de signaler un abus
func (am *AbuseMonitor) ReportAbuse(domain, reporterIP, reason string) {
	details := fmt.Sprintf("Abuse report from %s", reporterIP)

	// Submit to report manager
	report, err := am.reportManager.SubmitReport(domain, reporterIP, reason, details)
	if err != nil {
		log.Printf("Failed to submit abuse report: %v", err)
		return
	}

	log.Printf("Abuse reported for domain %s by %s: %s (ID: %s)", domain, reporterIP, reason, report.ID)

	if am.alertCallback != nil {
		am.alertCallback(domain, "abuse_report", fmt.Sprintf("reported by %s: %s (ID: %s)", reporterIP, reason, report.ID))
	}
}

// GetReportManager returns the abuse report manager
func (am *AbuseMonitor) GetReportManager() *AbuseReportManager {
	return am.reportManager
}

// SetAlertCallback définit le callback pour les alertes
func (am *AbuseMonitor) SetAlertCallback(callback func(domain, reason, details string)) {
	am.alertCallback = callback
}

// IsKnownMaliciousIP vérifie si une IP est dans une liste noire connue
func (am *AbuseMonitor) IsKnownMaliciousIP(ip string) bool {
	// IPs des exemples que tu as montrés - patterns de scan courants
	knownBadIPs := []string{
		"165.232.95.247", // DigitalOcean - scan répété
		"193.32.162.145", // Pattern de scan
		"118.193.43.244", // Pattern de scan
		"193.233.48.138", // Pattern de scan
		"103.183.157.25", // Tentatives multiples
		"182.93.7.194",   // Pattern de scan
		"78.128.112.74",  // Tentatives sans auth
		"5.228.183.178",  // Pattern de scan
		"195.158.16.5",   // Pattern de scan
	}

	for _, badIP := range knownBadIPs {
		if ip == badIP {
			return true
		}
	}

	// Vérifier contre les ranges suspects (peut être étendu)
	suspiciousRanges := []string{
		"165.232.", // DigitalOcean ranges souvent utilisés pour du scan
		"103.183.", // Range d'IP avec beaucoup de scan
		"193.32.",  // Range suspect
	}

	for _, suspicious := range suspiciousRanges {
		if strings.HasPrefix(ip, suspicious) {
			return true
		}
	}

	return false
}

// loadBlockedDomains - disabled for privacy
func (am *AbuseMonitor) loadBlockedDomains() {
	// Domain blocking disabled for privacy
}

// GetConnectionStats retourne les statistiques de connexion
func (am *AbuseMonitor) GetConnectionStats(sshKeyHash string) (int, bool) {
	am.limitMutex.RLock()
	defer am.limitMutex.RUnlock()

	if limit, exists := am.connectionLimits[sshKeyHash]; exists {
		return limit.Connections, limit.Blocked
	}
	return 0, false
}

// CreateAbuseReportHandler crée un endpoint pour signaler des abus
func (am *AbuseMonitor) CreateAbuseReportHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Servir le formulaire de signalement
			am.serveReportForm(w, r)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		domain := r.FormValue("domain")
		reason := r.FormValue("reason")
		details := r.FormValue("details")
		contact := r.FormValue("contact")
		hcaptchaResponse := r.FormValue("h-captcha-response")

		// Validation avec messages d'erreur JSON détaillés
		if domain == "" || reason == "" {
			am.writeErrorJSON(w, "Please fill in both domain and abuse type")
			return
		}

		// Verify hCaptcha
		if hcaptchaResponse == "" {
			am.writeErrorJSON(w, "Please complete the captcha verification")
			return
		}

		if !am.verifyHCaptcha(hcaptchaResponse) {
			am.writeErrorJSON(w, "Captcha verification failed, please try again")
			return
		}

		// Auto-complete domain if needed (for backward compatibility)
		if !strings.Contains(domain, ".") {
			domain = domain + ".p0rt.xyz"
		}

		// Validate domain format
		if !strings.HasSuffix(domain, ".p0rt.xyz") {
			am.writeErrorJSON(w, "Domain must end with .p0rt.xyz")
			return
		}

		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		fullReason := reason
		if details != "" {
			fullReason += " - " + details
		}
		if contact != "" {
			fullReason += " (Contact: " + contact + ")"
		}

		am.ReportAbuse(domain, clientIP, fullReason)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"reported","message":"Thank you for reporting. We will investigate."}`)
	}
}

func (am *AbuseMonitor) serveReportForm(w http.ResponseWriter, r *http.Request) {
	// Use the embedded abuse report handler
	if am.abuseReportHandler != nil {
		am.abuseReportHandler.ServeAbuseReportForm(w, r)
	} else {
		// Fallback to simple error response
		http.Error(w, "Abuse report form not available", http.StatusInternalServerError)
	}
}

// verifyHCaptcha verifies the hCaptcha response with hCaptcha service
func (am *AbuseMonitor) verifyHCaptcha(response string) bool {
	// Get hCaptcha secret key from environment
	secretKey := os.Getenv("HCAPTCHA_SECRET_KEY")
	if secretKey == "" {
		// For testing/development, use test secret key
		secretKey = "0x0000000000000000000000000000000000000000"
	}

	// Prepare verification request
	data := url.Values{}
	data.Set("secret", secretKey)
	data.Set("response", response)

	// Make request to hCaptcha verification endpoint
	resp, err := http.PostForm("https://hcaptcha.com/siteverify", data)
	if err != nil {
		log.Printf("hCaptcha verification request failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	// Parse response
	var result struct {
		Success bool `json:"success"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("hCaptcha verification response decode failed: %v", err)
		return false
	}

	return result.Success
}

// writeErrorJSON writes a JSON error response
func (am *AbuseMonitor) writeErrorJSON(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `{"status":"error","message":"%s"}`, message)
}

// GetBannedIPCount returns the number of currently banned IP addresses
func (am *AbuseMonitor) GetBannedIPCount() int {
	if am.reportManager == nil {
		return 0
	}
	
	// Get stats from the abuse report manager's underlying systems
	stats := am.reportManager.GetStats()
	if bannedIPs, ok := stats["banned_ips"].(int); ok {
		return bannedIPs
	}
	
	return 0
}

// GetBannedDomainCount returns the number of currently banned domains
func (am *AbuseMonitor) GetBannedDomainCount() int {
	if am.reportManager == nil {
		return 0
	}
	
	// Get stats from the abuse report manager
	stats := am.reportManager.GetStats()
	if bannedReports, ok := stats["banned_reports"].(int); ok {
		return bannedReports
	}
	
	return 0
}
