package security

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type AbuseMonitor struct {
	// Limites par clé SSH
	connectionLimits map[string]*ConnectionLimit
	limitMutex       sync.RWMutex

	// Patterns suspects
	suspiciousPatterns []*regexp.Regexp
	blockedDomains     map[string]bool
	blockedKeywords    []string

	// Alertes
	alertCallback func(domain, reason, details string)
}

type ConnectionLimit struct {
	Connections int
	LastReset   time.Time
	Blocked     bool
	BlockedUntil time.Time
}

func NewAbuseMonitor() *AbuseMonitor {
	monitor := &AbuseMonitor{
		connectionLimits: make(map[string]*ConnectionLimit),
		blockedDomains:   make(map[string]bool),
		suspiciousPatterns: []*regexp.Regexp{
			// Patterns de phishing
			regexp.MustCompile(`(?i)(login|signin|account|bank|paypal|amazon|google|microsoft|apple)`),
			regexp.MustCompile(`(?i)(verify|suspend|update|confirm|security)`),
			regexp.MustCompile(`(?i)(password|credit.*card|social.*security)`),
			
			// Patterns de spam
			regexp.MustCompile(`(?i)(casino|lottery|winner|prize|claim|free.*money)`),
			regexp.MustCompile(`(?i)(viagra|pharmacy|crypto|investment)`),
			
			// Patterns de scam
			regexp.MustCompile(`(?i)(urgent|limited.*time|act.*now|congratulations)`),
			regexp.MustCompile(`(?i)(nigerian|prince|inheritance|wire.*transfer)`),
		},
		blockedKeywords: []string{
			"phishing", "malware", "virus", "trojan", "ransomware",
			"spam", "scam", "fraud", "fake", "counterfeit",
		},
	}

	// Charger les domaines bloqués depuis des listes publiques
	monitor.loadBlockedDomains()

	return monitor
}

// CheckDomain vérifie si un domaine généré est suspect
func (am *AbuseMonitor) CheckDomain(domain string) (bool, string) {
	am.limitMutex.RLock()
	defer am.limitMutex.RUnlock()

	// Vérifier contre les mots-clés bloqués
	domainLower := strings.ToLower(domain)
	for _, keyword := range am.blockedKeywords {
		if strings.Contains(domainLower, keyword) {
			return false, fmt.Sprintf("domain contains blocked keyword: %s", keyword)
		}
	}

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

// AnalyzeHTTPRequest analyse une requête HTTP pour détecter des patterns suspects
func (am *AbuseMonitor) AnalyzeHTTPRequest(domain, path, userAgent, referer string) (bool, string) {
	content := strings.ToLower(path + " " + userAgent + " " + referer)

	// Vérifier contre les patterns suspects
	for _, pattern := range am.suspiciousPatterns {
		if pattern.MatchString(content) {
			reason := fmt.Sprintf("suspicious pattern detected: %s", pattern.String())
			if am.alertCallback != nil {
				am.alertCallback(domain, "suspicious_content", reason)
			}
			return false, reason
		}
	}

	return true, ""
}

// ReportAbuse permet de signaler un abus
func (am *AbuseMonitor) ReportAbuse(domain, reporterIP, reason string) {
	log.Printf("Abuse reported for domain %s by %s: %s", domain, reporterIP, reason)
	
	if am.alertCallback != nil {
		am.alertCallback(domain, "abuse_report", fmt.Sprintf("reported by %s: %s", reporterIP, reason))
	}
}

// SetAlertCallback définit le callback pour les alertes
func (am *AbuseMonitor) SetAlertCallback(callback func(domain, reason, details string)) {
	am.alertCallback = callback
}

// loadBlockedDomains charge une liste de domaines suspects (peut être étendu)
func (am *AbuseMonitor) loadBlockedDomains() {
	// Liste basique de domaines suspects
	suspiciousDomains := []string{
		"phishing.example",
		"malware.example", 
		"spam.example",
	}

	for _, domain := range suspiciousDomains {
		am.blockedDomains[domain] = true
	}
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
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		domain := r.FormValue("domain")
		reason := r.FormValue("reason")
		
		if domain == "" || reason == "" {
			http.Error(w, "Missing domain or reason", http.StatusBadRequest)
			return
		}

		// Valider le domaine
		if !strings.HasSuffix(domain, ".p0rt.xyz") {
			http.Error(w, "Invalid domain", http.StatusBadRequest)
			return
		}

		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		am.ReportAbuse(domain, clientIP, reason)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"reported","message":"Thank you for reporting. We will investigate."}`)
	}
}