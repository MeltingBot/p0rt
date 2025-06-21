package stats

import (
	"fmt"
	"sync"
	"time"
)

// Manager handles statistics collection and reporting
type Manager struct {
	mu                   sync.RWMutex
	startTime            time.Time
	activeTunnels        int
	totalTunnels         int64
	totalConnections     int64
	bytesTransferred     int64
	httpRequests         int64
	websocketConnections int64
	tunnelDomains        map[string]*TunnelStats
	accessMode           string // "open" or "restricted"
	connectionHistory    *ConnectionHistory
}

// TunnelStats represents statistics for a specific tunnel/domain
type TunnelStats struct {
	Domain            string    `json:"domain"`
	CreatedAt         time.Time `json:"created_at"`
	LastActivity      time.Time `json:"last_activity"`
	TotalRequests     int64     `json:"total_requests"`
	BytesIn           int64     `json:"bytes_in"`
	BytesOut          int64     `json:"bytes_out"`
	WebSocketUpgrades int64     `json:"websocket_upgrades"`
	ActiveConnections int       `json:"active_connections"`
}

// GlobalStats represents overall system statistics
type GlobalStats struct {
	Uptime               string          `json:"uptime"`
	ActiveTunnels        int             `json:"active_tunnels"`
	TotalTunnels         int64           `json:"total_tunnels"`
	TotalConnections     int64           `json:"total_connections"`
	BytesTransferred     int64           `json:"bytes_transferred"`
	HTTPRequests         int64           `json:"http_requests"`
	WebSocketConnections int64           `json:"websocket_connections"`
	TopDomains           []*TunnelStats  `json:"top_domains"`
	RecentActivity       []ActivityEntry `json:"recent_activity"`
	AccessMode           string          `json:"access_mode"` // "open" or "restricted"
}

// ActivityEntry represents a recent activity log entry
type ActivityEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Domain    string    `json:"domain"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
}

// NewManager creates a new statistics manager
func NewManager() *Manager {
	return &Manager{
		startTime:         time.Now(),
		tunnelDomains:     make(map[string]*TunnelStats),
		accessMode:        "restricted", // Default, will be updated by server
		connectionHistory: NewConnectionHistory("./data/stats"),
	}
}

// SetAccessMode sets the access mode (open or restricted)
func (m *Manager) SetAccessMode(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessMode = mode
}

// TunnelConnected records a new tunnel connection
func (m *Manager) TunnelConnected(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.activeTunnels++
	m.totalTunnels++

	if _, exists := m.tunnelDomains[domain]; !exists {
		m.tunnelDomains[domain] = &TunnelStats{
			Domain:    domain,
			CreatedAt: time.Now(),
		}
	}
	m.tunnelDomains[domain].LastActivity = time.Now()
}

// TunnelConnectedWithDetails records a new tunnel connection with client details
func (m *Manager) TunnelConnectedWithDetails(domain, clientIP, fingerprint string) {
	m.TunnelConnected(domain)
	m.connectionHistory.RecordConnection(domain, clientIP, fingerprint)
}

// TunnelDisconnected records a tunnel disconnection
func (m *Manager) TunnelDisconnected(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.activeTunnels--
	if m.activeTunnels < 0 {
		m.activeTunnels = 0
	}

	if stats, exists := m.tunnelDomains[domain]; exists {
		stats.ActiveConnections = 0
	}
	
	m.connectionHistory.RecordDisconnection(domain)
}

// HTTPRequest records an HTTP request
func (m *Manager) HTTPRequest(domain string, bytesIn, bytesOut int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.httpRequests++
	m.totalConnections++
	m.bytesTransferred += bytesIn + bytesOut

	if stats, exists := m.tunnelDomains[domain]; exists {
		stats.TotalRequests++
		stats.BytesIn += bytesIn
		stats.BytesOut += bytesOut
		stats.LastActivity = time.Now()
	}
	
	// Update connection history bandwidth
	m.connectionHistory.UpdateTraffic(domain, bytesIn, bytesOut)
}

// WebSocketUpgrade records a WebSocket upgrade
func (m *Manager) WebSocketUpgrade(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.websocketConnections++

	if stats, exists := m.tunnelDomains[domain]; exists {
		stats.WebSocketUpgrades++
		stats.LastActivity = time.Now()
	}
}

// ConnectionActive increments active connections for a domain
func (m *Manager) ConnectionActive(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if stats, exists := m.tunnelDomains[domain]; exists {
		stats.ActiveConnections++
	}
}

// ConnectionClosed decrements active connections for a domain
func (m *Manager) ConnectionClosed(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if stats, exists := m.tunnelDomains[domain]; exists {
		stats.ActiveConnections--
		if stats.ActiveConnections < 0 {
			stats.ActiveConnections = 0
		}
	}
}

// GetGlobalStats returns overall system statistics
func (m *Manager) GetGlobalStats() *GlobalStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	uptime := time.Since(m.startTime)

	// Get top 10 domains by request count
	topDomains := make([]*TunnelStats, 0, 10)
	for _, stats := range m.tunnelDomains {
		topDomains = append(topDomains, stats)
	}

	// Sort by total requests (simple sorting for top domains)
	for i := 0; i < len(topDomains)-1; i++ {
		for j := i + 1; j < len(topDomains); j++ {
			if topDomains[j].TotalRequests > topDomains[i].TotalRequests {
				topDomains[i], topDomains[j] = topDomains[j], topDomains[i]
			}
		}
	}

	// Limit to top 10
	if len(topDomains) > 10 {
		topDomains = topDomains[:10]
	}

	return &GlobalStats{
		Uptime:               formatDuration(uptime),
		ActiveTunnels:        m.activeTunnels,
		TotalTunnels:         m.totalTunnels,
		TotalConnections:     m.totalConnections,
		BytesTransferred:     m.bytesTransferred,
		HTTPRequests:         m.httpRequests,
		WebSocketConnections: m.websocketConnections,
		TopDomains:           topDomains,
		AccessMode:           m.accessMode,
	}
}

// GetTunnelStats returns statistics for a specific tunnel
func (m *Manager) GetTunnelStats(domain string) *TunnelStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if stats, exists := m.tunnelDomains[domain]; exists {
		// Return a copy to avoid data races
		return &TunnelStats{
			Domain:            stats.Domain,
			CreatedAt:         stats.CreatedAt,
			LastActivity:      stats.LastActivity,
			TotalRequests:     stats.TotalRequests,
			BytesIn:           stats.BytesIn,
			BytesOut:          stats.BytesOut,
			WebSocketUpgrades: stats.WebSocketUpgrades,
			ActiveConnections: stats.ActiveConnections,
		}
	}
	return nil
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	} else {
		return fmt.Sprintf("%ds", seconds)
	}
}

// formatBytes formats bytes into human-readable format
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GetConnectionHistory returns connection history
func (m *Manager) GetConnectionHistory(limit int) []*ConnectionRecord {
	return m.connectionHistory.GetHistory(limit)
}

// GetActiveConnections returns currently active connections
func (m *Manager) GetActiveConnections() []*ConnectionRecord {
	return m.connectionHistory.GetActiveConnections()
}

// GetConnectionStats returns aggregated connection statistics
func (m *Manager) GetConnectionStats() map[string]interface{} {
	return m.connectionHistory.GetConnectionStats()
}

// CleanupStaleConnections manually triggers cleanup of stale connections
func (m *Manager) CleanupStaleConnections(timeout time.Duration) {
	m.connectionHistory.CleanupStaleConnections(timeout)
}
