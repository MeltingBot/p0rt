package metrics

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
)

// BasicAuthMiddleware provides HTTP Basic Authentication for metrics endpoint
func BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get credentials from environment variables
		username := os.Getenv("P0RT_METRICS_USERNAME")
		password := os.Getenv("P0RT_METRICS_PASSWORD")

		// If no credentials configured, deny access
		if username == "" || password == "" {
			http.Error(w, "Metrics endpoint not configured", http.StatusServiceUnavailable)
			return
		}

		// Parse Authorization header
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			w.Header().Set("WWW-Authenticate", `Basic realm="P0rt Metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Decode base64 credentials
		payload, err := base64.StdEncoding.DecodeString(auth[6:])
		if err != nil {
			http.Error(w, "Invalid credentials format", http.StatusBadRequest)
			return
		}

		// Split username:password
		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 {
			http.Error(w, "Invalid credentials format", http.StatusBadRequest)
			return
		}

		providedUsername := pair[0]
		providedPassword := pair[1]

		// Use constant-time comparison to prevent timing attacks
		usernameMatch := subtle.ConstantTimeCompare([]byte(providedUsername), []byte(username)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(providedPassword), []byte(password)) == 1

		if !usernameMatch || !passwordMatch {
			w.Header().Set("WWW-Authenticate", `Basic realm="P0rt Metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Authentication successful
		next.ServeHTTP(w, r)
	})
}

// IsMetricsEnabled checks if metrics endpoint should be enabled
func IsMetricsEnabled() bool {
	username := os.Getenv("P0RT_METRICS_USERNAME")
	password := os.Getenv("P0RT_METRICS_PASSWORD")
	return username != "" && password != ""
}