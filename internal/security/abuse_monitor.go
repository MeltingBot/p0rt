package security

import (
	"fmt"
	"log"
	"net/http"
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
	log.Printf("Abuse reported for domain %s by %s: %s", domain, reporterIP, reason)
	
	if am.alertCallback != nil {
		am.alertCallback(domain, "abuse_report", fmt.Sprintf("reported by %s: %s", reporterIP, reason))
	}
}

// SetAlertCallback définit le callback pour les alertes
func (am *AbuseMonitor) SetAlertCallback(callback func(domain, reason, details string)) {
	am.alertCallback = callback
}

// IsKnownMaliciousIP vérifie si une IP est dans une liste noire connue
func (am *AbuseMonitor) IsKnownMaliciousIP(ip string) bool {
	// IPs des exemples que tu as montrés - patterns de scan courants
	knownBadIPs := []string{
		"165.232.95.247",  // DigitalOcean - scan répété
		"193.32.162.145",  // Pattern de scan
		"118.193.43.244",  // Pattern de scan
		"193.233.48.138",  // Pattern de scan
		"103.183.157.25",  // Tentatives multiples
		"182.93.7.194",    // Pattern de scan
		"78.128.112.74",   // Tentatives sans auth
		"5.228.183.178",   // Pattern de scan
		"195.158.16.5",    // Pattern de scan
	}
	
	for _, badIP := range knownBadIPs {
		if ip == badIP {
			return true
		}
	}
	
	// Vérifier contre les ranges suspects (peut être étendu)
	suspiciousRanges := []string{
		"165.232.",    // DigitalOcean ranges souvent utilisés pour du scan
		"103.183.",    // Range d'IP avec beaucoup de scan
		"193.32.",     // Range suspect
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
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Abuse - P0rt Security</title>
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
        
        <button type="submit">Submit Report</button>
    </form>
    
    <div class="back-link">
        <a href="/">← Back to P0rt</a>
    </div>
    
    <script>
        document.querySelector('form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const submitButton = document.querySelector('button[type="submit"]');
            
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
                alert('Failed to submit report. Please try again.');
            });
        });
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}