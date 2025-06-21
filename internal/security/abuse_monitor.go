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
}

type ConnectionLimit struct {
	Connections  int
	LastReset    time.Time
	Blocked      bool
	BlockedUntil time.Time
}

func NewAbuseMonitor() *AbuseMonitor {
	monitor := &AbuseMonitor{
		connectionLimits: make(map[string]*ConnectionLimit),
		reportManager:    NewAbuseReportManager(),
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

		// Debug logs
		log.Printf("Abuse report submission: domain=%s, reason=%s, hcaptcha_present=%v", domain, reason, hcaptchaResponse != "")

		if domain == "" || reason == "" {
			log.Printf("Abuse report error: Missing domain or reason (domain=%s, reason=%s)", domain, reason)
			http.Error(w, "Missing domain or reason", http.StatusBadRequest)
			return
		}

		// Verify hCaptcha
		if hcaptchaResponse == "" {
			log.Printf("Abuse report error: Captcha verification required")
			http.Error(w, "Captcha verification required", http.StatusBadRequest)
			return
		}

		if !am.verifyHCaptcha(hcaptchaResponse) {
			log.Printf("Abuse report error: Captcha verification failed")
			http.Error(w, "Captcha verification failed", http.StatusBadRequest)
			return
		}

		// Valider le domaine
		if !strings.HasSuffix(domain, ".p0rt.xyz") {
			log.Printf("Abuse report error: Invalid domain format (domain=%s)", domain)
			http.Error(w, "Invalid domain", http.StatusBadRequest)
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
	siteKey := os.Getenv("HCAPTCHA_SITE_KEY")
	if siteKey == "" {
		// Use test site key for development
		siteKey = "10000000-ffff-ffff-ffff-000000000001"
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Abuse - P0rt Security</title>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 2rem;
            background: #0a0a0a;
            color: #fafafa;
            line-height: 1.6;
        }
        h1 {
            color: #ef4444;
            text-align: center;
            margin-bottom: 2rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #60a5fa;
            font-weight: bold;
        }
        input, textarea, select {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #333;
            border-radius: 4px;
            background: #1a1a1a;
            color: #fafafa;
            font-size: 1rem;
        }
        textarea {
            height: 120px;
            resize: vertical;
        }
        button {
            background: #ef4444;
            color: white;
            padding: 0.75rem 2rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
            width: 100%;
        }
        button:hover {
            background: #dc2626;
        }
        .info {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 2rem;
            color: #888;
        }
        .back-link {
            text-align: center;
            margin-top: 2rem;
        }
        .back-link a {
            color: #60a5fa;
            text-decoration: none;
        }
        .back-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>🛡️ Report Abuse</h1>
    
    <div class="info">
        <strong>Help us keep P0rt safe!</strong><br>
        Report tunnels being used for phishing, spam, scams, or other malicious activities.
        All reports are reviewed by our security team.
    </div>
    
    <form method="POST" action="/report-abuse">
        <div class="form-group">
            <label for="domain">Suspicious Domain *</label>
            <input type="text" id="domain" name="domain" placeholder="example-domain.p0rt.xyz" required>
        </div>
        
        <div class="form-group">
            <label for="reason">Type of Abuse *</label>
            <select id="reason" name="reason" required>
                <option value="">Select abuse type...</option>
                <option value="phishing">Phishing (fake login pages, account theft)</option>
                <option value="spam">Spam (unwanted promotional content)</option>
                <option value="scam">Scam (fraudulent schemes, fake offers)</option>
                <option value="malware">Malware distribution</option>
                <option value="copyright">Copyright infringement</option>
                <option value="harassment">Harassment or threatening content</option>
                <option value="other">Other malicious activity</option>
            </select>
        </div>
        
        <div class="form-group">
            <label for="details">Additional Details</label>
            <textarea id="details" name="details" placeholder="Describe what you observed (URLs, screenshots, etc.)"></textarea>
        </div>
        
        <div class="form-group">
            <label for="contact">Your Email (optional)</label>
            <input type="email" id="contact" name="contact" placeholder="your-email@example.com">
            <small style="color: #888;">Only used if we need clarification about your report</small>
        </div>
        
        <div class="form-group">
            <div class="h-captcha" data-sitekey="%s"></div>
        </div>
        
        <button type="submit">Submit Report</button>
    </form>
    
    <div class="back-link">
        <a href="/">← Back to P0rt</a>
    </div>
    
    <script>
        document.querySelector('form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const submitButton = document.querySelector('button[type="submit"]');
            
            // Get hCaptcha response
            const hcaptchaResponse = hcaptcha.getResponse();
            if (!hcaptchaResponse) {
                alert('Please complete the captcha verification.');
                return;
            }
            
            const formData = new FormData(this);
            formData.append('h-captcha-response', hcaptchaResponse);
            
            submitButton.textContent = 'Submitting...';
            submitButton.disabled = true;
            
            fetch('/report-abuse', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'reported') {
                    document.body.innerHTML = '<div style="text-align: center; padding: 4rem;"><h1 style="color: #10b981;">✓ Report Submitted</h1><p>Thank you for helping keep P0rt safe. Our security team will investigate this report.</p><p><a href="/" style="color: #60a5fa;">Back to P0rt</a></p></div>';
                } else {
                    throw new Error('Report failed');
                }
            })
            .catch(error => {
                submitButton.textContent = 'Submit Report';
                submitButton.disabled = false;
                hcaptcha.reset();
                alert('Failed to submit report. Please try again.');
            });
        });
    </script>
</body>
</html>`

	// Replace placeholder with actual site key
	finalHTML := strings.ReplaceAll(html, "%s", siteKey)
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(finalHTML))
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
