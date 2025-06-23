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
	Status       string            `json:"status"`
	Uptime       string            `json:"uptime,omitempty"`
	Version      string            `json:"version"`
	SSH          ServiceStatus     `json:"ssh"`
	HTTP         ServiceStatus     `json:"http"`
	Storage      StorageStatus     `json:"storage"`
	Security     SecurityStatus    `json:"security"`
	System       SystemStatus      `json:"system"`
	Environment  map[string]string `json:"environment"`
	Timestamp    string            `json:"timestamp"`
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
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	GoVersion string `json:"go_version"`
	Memory   string `json:"memory,omitempty"`
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

// handleServerStart handles POST /api/v1/server/start
func (h *Handler) handleServerStart(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Note: This is a placeholder since starting a server process via API
	// is complex and potentially dangerous. In practice, this would need
	// careful consideration of process management, permissions, etc.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Server start request received",
		"note":      "Server lifecycle management via API requires careful implementation",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleServerStop handles POST /api/v1/server/stop
func (h *Handler) handleServerStop(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Note: Similar to start, this is a placeholder for proper process management
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Server stop request received",
		"note":      "Server lifecycle management via API requires careful implementation",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleServerRestart handles POST /api/v1/server/restart
func (h *Handler) handleServerRestart(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Note: Placeholder for proper restart functionality
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Server restart request received",
		"note":      "Server lifecycle management via API requires careful implementation",
		"timestamp": time.Now().Format(time.RFC3339),
	})
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
		"ssh_port":      os.Getenv("SSH_SERVER_PORT"),
		"http_port":     os.Getenv("HTTP_SERVER_PORT"),
		"domain_base":   os.Getenv("DOMAIN_BASE"),
		"redis_url":     h.maskSensitive(os.Getenv("REDIS_URL")),
		"open_access":   os.Getenv("P0RT_OPEN_ACCESS"),
		"api_key_set":   fmt.Sprintf("%t", os.Getenv("API_KEY") != ""),
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