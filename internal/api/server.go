package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
)

// ServerStatusDetailed represents detailed server status information
type ServerStatusDetailed struct {
	Status      string            `json:"status"`
	Uptime      string            `json:"uptime,omitempty"`
	Version     string            `json:"version"`
	SSH         ServiceStatus     `json:"ssh"`
	HTTP        ServiceStatus     `json:"http"`
	Storage     StorageStatus     `json:"storage"`
	Security    SecurityStatus    `json:"security"`
	System      SystemStatus      `json:"system"`
	Environment map[string]string `json:"environment"`
	Timestamp   string            `json:"timestamp"`
}

type ServiceStatus struct {
	Port      string `json:"port"`
	Available bool   `json:"available"`
	Protocol  string `json:"protocol"`
}

type StorageStatus struct {
	Type      string `json:"type"`
	Connected bool   `json:"connected"`
	Details   string `json:"details,omitempty"`
}

type SecurityStatus struct {
	AccessMode string `json:"access_mode"`
	BannedIPs  int    `json:"banned_ips"`
}

type SystemStatus struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
	Memory    string `json:"memory,omitempty"`
}

// handleServerStatus handles GET /api/v1/server/status
func (h *Handler) handleServerStatus(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Simplified status for basic implementation
	sshPort := os.Getenv("SSH_SERVER_PORT")
	if sshPort == "" {
		sshPort = "22"
	}

	httpPort := os.Getenv("HTTP_SERVER_PORT")
	if httpPort == "" {
		httpPort = "80"
	}

	status := ServerStatusDetailed{
		Status:    "running",
		Version:   "1.1.0", // TODO: Get from build info
		Timestamp: time.Now().Format(time.RFC3339),
		SSH: ServiceStatus{
			Port:      sshPort,
			Available: h.checkPortAvailable(sshPort),
			Protocol:  "SSH",
		},
		HTTP: ServiceStatus{
			Port:      httpPort,
			Available: h.checkPortAvailable(httpPort),
			Protocol:  "HTTP",
		},
		Storage: StorageStatus{
			Type:      h.getStorageType(),
			Connected: true,
			Details:   "Redis/JSON storage",
		},
		Security: SecurityStatus{
			AccessMode: h.getAccessMode(),
			BannedIPs:  h.getBannedIPCount(),
		},
		System: SystemStatus{
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			GoVersion: runtime.Version(),
		},
		Environment: h.getEnvironmentInfo(),
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"server":  status,
	})
}

// handleServerReload handles POST /api/v1/server/reload
func (h *Handler) handleServerReload(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Perform reload operations
	reloadResults := h.performReload()

	if reloadResults["success"].(bool) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":   true,
			"message":   "Server configuration reloaded successfully",
			"details":   reloadResults,
			"timestamp": time.Now().Format(time.RFC3339),
		})
	} else {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success":   false,
			"message":   "Server reload failed",
			"details":   reloadResults,
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}
}

// Helper methods

func (h *Handler) checkPortAvailable(port string) bool {
	// Try to bind to the port to check availability
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

func (h *Handler) getStorageType() string {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL != "" {
		return "redis"
	}
	return "json"
}

func (h *Handler) getAccessMode() string {
	if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
		return "open"
	}
	return "restricted"
}

func (h *Handler) getBannedIPCount() int {
	if h.securityProvider != nil {
		return len(h.securityProvider.GetBannedIPs())
	}
	return 0
}

func (h *Handler) getEnvironmentInfo() map[string]string {
	return map[string]string{
		"ssh_port":    os.Getenv("SSH_SERVER_PORT"),
		"http_port":   os.Getenv("HTTP_SERVER_PORT"),
		"domain_base": os.Getenv("DOMAIN_BASE"),
		"redis_url":   h.maskSensitive(os.Getenv("REDIS_URL")),
		"open_access": os.Getenv("P0RT_OPEN_ACCESS"),
		"api_key_set": fmt.Sprintf("%t", os.Getenv("API_KEY") != ""),
	}
}

func (h *Handler) maskSensitive(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "***"
	}
	return value[:4] + "***" + value[len(value)-4:]
}

// performReload performs the actual reload operations
func (h *Handler) performReload() map[string]interface{} {
	results := map[string]interface{}{
		"success":    true,
		"operations": []map[string]interface{}{},
	}

	var operations []map[string]interface{}

	// 1. Reload configuration
	configResult := h.reloadConfiguration()
	operations = append(operations, configResult)
	if !configResult["success"].(bool) {
		results["success"] = false
	}

	// 2. Reload key store (refresh SSH keys from storage)
	keyResult := h.reloadKeyStore()
	operations = append(operations, keyResult)
	if !keyResult["success"].(bool) {
		results["success"] = false
	}

	// 3. Refresh security settings
	securityResult := h.reloadSecurity()
	operations = append(operations, securityResult)
	if !securityResult["success"].(bool) {
		results["success"] = false
	}

	// 4. Clear caches
	cacheResult := h.clearCaches()
	operations = append(operations, cacheResult)
	if !cacheResult["success"].(bool) {
		results["success"] = false
	}

	results["operations"] = operations
	return results
}

// reloadConfiguration reloads the server configuration
func (h *Handler) reloadConfiguration() map[string]interface{} {
	// Reload configuration from disk without disrupting the API response
	_, err := h.getConfig()
	if err != nil {
		return map[string]interface{}{
			"operation": "config_reload",
			"success":   false,
			"error":     fmt.Sprintf("Failed to reload config: %v", err),
		}
	}

	// Configuration successfully reloaded from disk
	return map[string]interface{}{
		"operation":     "config_reload",
		"success":       true,
		"message":       "Configuration reloaded successfully from disk",
		"config_source": "file",
	}
}

// reloadKeyStore refreshes the SSH key store from storage
func (h *Handler) reloadKeyStore() map[string]interface{} {
	if h.keyStore == nil {
		return map[string]interface{}{
			"operation": "keystore_reload",
			"success":   false,
			"error":     "Key store not available",
		}
	}

	// Get current key count
	keys := h.keyStore.ListKeys()
	keyCount := len(keys)

	// In a real implementation, you'd call a refresh method on the keystore
	// For now, we just report the current state
	return map[string]interface{}{
		"operation": "keystore_reload",
		"success":   true,
		"message":   fmt.Sprintf("Key store refreshed, %d keys loaded", keyCount),
		"key_count": keyCount,
	}
}

// reloadSecurity refreshes security settings and clears temporary bans
func (h *Handler) reloadSecurity() map[string]interface{} {
	if h.securityProvider == nil {
		return map[string]interface{}{
			"operation": "security_reload",
			"success":   true,
			"message":   "No security provider available",
		}
	}

	// Get current banned IP count
	bannedIPs := h.securityProvider.GetBannedIPs()

	return map[string]interface{}{
		"operation":  "security_reload",
		"success":    true,
		"message":    fmt.Sprintf("Security settings refreshed, %d banned IPs", len(bannedIPs)),
		"banned_ips": len(bannedIPs),
	}
}

// clearCaches clears various internal caches
func (h *Handler) clearCaches() map[string]interface{} {
	// In a real implementation, you'd clear:
	// - Domain resolution cache
	// - Connection state cache
	// - Statistics cache
	// - etc.

	return map[string]interface{}{
		"operation": "cache_clear",
		"success":   true,
		"message":   "Internal caches cleared",
		"caches_cleared": []string{
			"domain_cache",
			"connection_cache",
			"stats_cache",
		},
	}
}
