package stats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ConnectionRecord represents a single SSH connection
type ConnectionRecord struct {
	ID           string    `json:"id"`
	Domain       string    `json:"domain"`       // Full domain (e.g., "abc.p0rt.xyz")
	Trigram      string    `json:"trigram"`      // First 3 chars of subdomain
	ClientIP     string    `json:"client_ip"`    // SSH client IP
	Fingerprint  string    `json:"fingerprint"`  // SSH key fingerprint
	ConnectedAt  time.Time `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	Duration     string    `json:"duration,omitempty"`
	BytesIn      int64     `json:"bytes_in"`
	BytesOut     int64     `json:"bytes_out"`
	RequestCount int64     `json:"request_count"`
	Active       bool      `json:"active"`
}

// ConnectionHistory manages historical connection data
type ConnectionHistory struct {
	mu          sync.RWMutex
	connections map[string]*ConnectionRecord // domain -> record
	history     []*ConnectionRecord          // all records (including disconnected)
	dataDir     string
	maxHistory  int
}

// NewConnectionHistory creates a new connection history manager
func NewConnectionHistory(dataDir string) *ConnectionHistory {
	if dataDir == "" {
		dataDir = "./data"
	}
	
	ch := &ConnectionHistory{
		connections: make(map[string]*ConnectionRecord),
		history:     make([]*ConnectionRecord, 0),
		dataDir:     dataDir,
		maxHistory:  10000, // Keep last 10k connections
	}
	
	// Create data directory
	os.MkdirAll(dataDir, 0755)
	
	// Load existing history
	ch.loadHistory()
	
	// Start periodic save
	go ch.periodicSave()
	
	return ch
}

// RecordConnection records a new SSH connection
func (ch *ConnectionHistory) RecordConnection(domain, clientIP, fingerprint string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	
	// Extract trigram (first 3 chars of subdomain)
	trigram := extractTrigram(domain)
	
	record := &ConnectionRecord{
		ID:           fmt.Sprintf("%s-%d", domain, time.Now().UnixNano()),
		Domain:       domain,
		Trigram:      trigram,
		ClientIP:     clientIP,
		Fingerprint:  fingerprint,
		ConnectedAt:  time.Now(),
		Active:       true,
	}
	
	ch.connections[domain] = record
	ch.history = append(ch.history, record)
	
	// Trim history if too large
	if len(ch.history) > ch.maxHistory {
		ch.history = ch.history[len(ch.history)-ch.maxHistory:]
	}
}

// RecordDisconnection marks a connection as disconnected
func (ch *ConnectionHistory) RecordDisconnection(domain string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	
	if record, exists := ch.connections[domain]; exists {
		now := time.Now()
		record.DisconnectedAt = &now
		record.Duration = now.Sub(record.ConnectedAt).String()
		record.Active = false
		delete(ch.connections, domain)
	}
}

// UpdateTraffic updates traffic statistics for a connection
func (ch *ConnectionHistory) UpdateTraffic(domain string, bytesIn, bytesOut int64) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	
	if record, exists := ch.connections[domain]; exists {
		record.BytesIn += bytesIn
		record.BytesOut += bytesOut
		record.RequestCount++
	}
}

// GetActiveConnections returns all active connections
func (ch *ConnectionHistory) GetActiveConnections() []*ConnectionRecord {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	
	active := make([]*ConnectionRecord, 0, len(ch.connections))
	for _, record := range ch.connections {
		active = append(active, record)
	}
	
	return active
}

// GetHistory returns connection history (last N records)
func (ch *ConnectionHistory) GetHistory(limit int) []*ConnectionRecord {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	
	if limit <= 0 || limit > len(ch.history) {
		limit = len(ch.history)
	}
	
	// Return from newest to oldest
	start := len(ch.history) - limit
	if start < 0 {
		start = 0
	}
	
	result := make([]*ConnectionRecord, 0, limit)
	for i := len(ch.history) - 1; i >= start; i-- {
		result = append(result, ch.history[i])
	}
	
	return result
}

// GetConnectionStats returns aggregated statistics
func (ch *ConnectionHistory) GetConnectionStats() map[string]interface{} {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	
	totalBytesIn := int64(0)
	totalBytesOut := int64(0)
	totalRequests := int64(0)
	
	// Count by trigram
	trigramCounts := make(map[string]int)
	
	// Count by IP
	ipCounts := make(map[string]int)
	
	for _, record := range ch.history {
		totalBytesIn += record.BytesIn
		totalBytesOut += record.BytesOut
		totalRequests += record.RequestCount
		
		trigramCounts[record.Trigram]++
		ipCounts[record.ClientIP]++
	}
	
	// Find top trigrams
	topTrigrams := findTopN(trigramCounts, 10)
	
	// Find top IPs
	topIPs := findTopN(ipCounts, 10)
	
	return map[string]interface{}{
		"total_connections":   len(ch.history),
		"active_connections":  len(ch.connections),
		"total_bytes_in":      totalBytesIn,
		"total_bytes_out":     totalBytesOut,
		"total_requests":      totalRequests,
		"top_trigrams":        topTrigrams,
		"top_client_ips":      topIPs,
	}
}

// loadHistory loads history from disk
func (ch *ConnectionHistory) loadHistory() error {
	filePath := filepath.Join(ch.dataDir, "connection_history.json")
	
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No history yet
		}
		return err
	}
	
	return json.Unmarshal(data, &ch.history)
}

// saveHistory saves history to disk
func (ch *ConnectionHistory) saveHistory() error {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	
	filePath := filepath.Join(ch.dataDir, "connection_history.json")
	tempFile := filePath + ".tmp"
	
	data, err := json.MarshalIndent(ch.history, "", "  ")
	if err != nil {
		return err
	}
	
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return err
	}
	
	return os.Rename(tempFile, filePath)
}

// periodicSave saves history periodically
func (ch *ConnectionHistory) periodicSave() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		if err := ch.saveHistory(); err != nil {
			fmt.Printf("Error saving connection history: %v\n", err)
		}
	}
}

// extractTrigram extracts the first 3 characters of a subdomain
func extractTrigram(domain string) string {
	// Remove the base domain suffix
	if idx := len(domain) - len(".p0rt.xyz"); idx > 0 && domain[idx:] == ".p0rt.xyz" {
		subdomain := domain[:idx]
		if len(subdomain) >= 3 {
			return subdomain[:3]
		}
		return subdomain
	}
	
	// For custom domains, use first 3 chars
	if len(domain) >= 3 {
		return domain[:3]
	}
	return domain
}

// findTopN finds the top N entries from a count map
func findTopN(counts map[string]int, n int) []map[string]interface{} {
	type entry struct {
		key   string
		count int
	}
	
	entries := make([]entry, 0, len(counts))
	for k, v := range counts {
		entries = append(entries, entry{k, v})
	}
	
	// Simple selection sort for top N
	for i := 0; i < len(entries) && i < n; i++ {
		maxIdx := i
		for j := i + 1; j < len(entries); j++ {
			if entries[j].count > entries[maxIdx].count {
				maxIdx = j
			}
		}
		entries[i], entries[maxIdx] = entries[maxIdx], entries[i]
	}
	
	result := make([]map[string]interface{}, 0, n)
	for i := 0; i < len(entries) && i < n; i++ {
		result = append(result, map[string]interface{}{
			"value": entries[i].key,
			"count": entries[i].count,
		})
	}
	
	return result
}