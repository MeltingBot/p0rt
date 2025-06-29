package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ConnectionRecord represents a single SSH connection
type ConnectionRecord struct {
	ID             string     `json:"id"`
	Domain         string     `json:"domain"`      // Full domain (e.g., "abc.p0rt.xyz")
	Trigram        string     `json:"trigram"`     // First 3 chars of subdomain
	ClientIP       string     `json:"client_ip"`   // SSH client IP
	Fingerprint    string     `json:"fingerprint"` // SSH key fingerprint
	ConnectedAt    time.Time  `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	Duration       string     `json:"duration,omitempty"`
	BytesIn        int64      `json:"bytes_in"`
	BytesOut       int64      `json:"bytes_out"`
	RequestCount   int64      `json:"request_count"`
	Active         bool       `json:"active"`
	LastActivity   time.Time  `json:"last_activity"` // Track last activity time
}

// ConnectionHistory manages historical connection data
type ConnectionHistory struct {
	mu          sync.RWMutex
	connections map[string]*ConnectionRecord // domain -> record
	history     []*ConnectionRecord          // all records (including disconnected)
	dataDir     string
	maxHistory  int

	// Redis support
	redisClient *redis.Client
	useRedis    bool
	ctx         context.Context
	keyPrefix   string
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
		ctx:         context.Background(),
		keyPrefix:   "p0rt:stats:",
	}

	// Try to initialize Redis
	ch.initRedis()

	if !ch.useRedis {
		// Fallback to file storage
		os.MkdirAll(dataDir, 0755)
		ch.loadHistory()
		go ch.periodicSave()
	} else {
		// Load from Redis
		ch.loadFromRedis()
	}

	// Start periodic cleanup of stale connections (every 10 minutes)
	go ch.periodicCleanup()

	return ch
}

// initRedis initializes Redis connection if available
func (ch *ConnectionHistory) initRedis() {
	redisURL := getRedisURL()
	if redisURL == "" {
		log.Println("ConnectionHistory: No Redis URL found, using file storage")
		return
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Printf("ConnectionHistory: Invalid Redis URL: %v", err)
		return
	}

	ch.redisClient = redis.NewClient(opts)

	// Test connection
	if err := ch.redisClient.Ping(ch.ctx).Err(); err != nil {
		log.Printf("ConnectionHistory: Redis connection failed: %v", err)
		ch.redisClient.Close()
		ch.redisClient = nil
		return
	}

	ch.useRedis = true
	log.Println("ConnectionHistory: Using Redis storage")
}

// getRedisURL returns the Redis URL from environment
func getRedisURL() string {
	if url := os.Getenv("REDIS_URL"); url != "" {
		return url
	}
	if url := os.Getenv("P0RT_REDIS_URL"); url != "" {
		return url
	}

	host := os.Getenv("REDIS_HOST")
	if host == "" {
		return ""
	}

	port := os.Getenv("REDIS_PORT")
	if port == "" {
		port = "6379"
	}

	password := os.Getenv("REDIS_PASSWORD")
	db := os.Getenv("REDIS_DB")
	if db == "" {
		db = "0"
	}

	if password != "" {
		return fmt.Sprintf("redis://:%s@%s:%s/%s", password, host, port, db)
	}
	return fmt.Sprintf("redis://%s:%s/%s", host, port, db)
}

// RecordConnection records a new SSH connection
func (ch *ConnectionHistory) RecordConnection(domain, clientIP, fingerprint string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	// Extract trigram (first 3 chars of subdomain)
	trigram := extractTrigram(domain)

	now := time.Now()
	record := &ConnectionRecord{
		ID:           fmt.Sprintf("%s-%d", domain, now.UnixNano()),
		Domain:       domain,
		Trigram:      trigram,
		ClientIP:     clientIP,
		Fingerprint:  fingerprint,
		ConnectedAt:  now,
		Active:       true,
		LastActivity: now,
	}

	ch.connections[domain] = record
	ch.history = append(ch.history, record)

	// Trim history if too large
	if len(ch.history) > ch.maxHistory {
		ch.history = ch.history[len(ch.history)-ch.maxHistory:]
	}

	// Save to Redis if available
	if ch.useRedis {
		ch.saveRecordToRedis(record)
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

		// Update in Redis if available
		if ch.useRedis {
			ch.saveRecordToRedis(record)
		}
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
		record.LastActivity = time.Now() // Update last activity time

		// Update in Redis if available
		if ch.useRedis {
			ch.saveRecordToRedis(record)
		}
	}
}

// KeepAlive updates the last activity time for a connection to prevent cleanup
func (ch *ConnectionHistory) KeepAlive(domain string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if record, exists := ch.connections[domain]; exists {
		record.LastActivity = time.Now()

		// Update in Redis if available
		if ch.useRedis {
			ch.saveRecordToRedis(record)
		}
	}
}

// GetActiveConnections returns all active connections
func (ch *ConnectionHistory) GetActiveConnections() []*ConnectionRecord {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	// If using Redis, refresh from Redis first
	if ch.useRedis {
		ch.refreshActiveFromRedis()
	}

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

	// If using Redis, refresh from Redis first
	if ch.useRedis {
		ch.refreshHistoryFromRedis()
	}

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
		"total_connections":  len(ch.history),
		"active_connections": len(ch.connections),
		"total_bytes_in":     totalBytesIn,
		"total_bytes_out":    totalBytesOut,
		"total_requests":     totalRequests,
		"top_trigrams":       topTrigrams,
		"top_client_ips":     topIPs,
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

// saveRecordToRedis saves a connection record to Redis
func (ch *ConnectionHistory) saveRecordToRedis(record *ConnectionRecord) {
	if ch.redisClient == nil {
		return
	}

	data, err := json.Marshal(record)
	if err != nil {
		log.Printf("ConnectionHistory: Failed to marshal record: %v", err)
		return
	}

	// Save active connection
	if record.Active {
		activeKey := ch.keyPrefix + "active:" + record.Domain
		if err := ch.redisClient.Set(ch.ctx, activeKey, data, 0).Err(); err != nil {
			log.Printf("ConnectionHistory: Failed to save active record to Redis: %v", err)
		}
	} else {
		// Remove from active and add to history
		activeKey := ch.keyPrefix + "active:" + record.Domain
		ch.redisClient.Del(ch.ctx, activeKey)
	}

	// Always save to history
	historyKey := ch.keyPrefix + "history:" + record.ID
	if err := ch.redisClient.Set(ch.ctx, historyKey, data, 7*24*time.Hour).Err(); err != nil {
		log.Printf("ConnectionHistory: Failed to save history record to Redis: %v", err)
	}
}

// loadFromRedis loads connection history from Redis
func (ch *ConnectionHistory) loadFromRedis() {
	if ch.redisClient == nil {
		return
	}

	// Load active connections
	activePattern := ch.keyPrefix + "active:*"
	activeKeys, err := ch.redisClient.Keys(ch.ctx, activePattern).Result()
	if err != nil {
		log.Printf("ConnectionHistory: Failed to get active keys from Redis: %v", err)
		return
	}

	for _, key := range activeKeys {
		data, err := ch.redisClient.Get(ch.ctx, key).Result()
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if err := json.Unmarshal([]byte(data), &record); err != nil {
			continue
		}

		// Validate and fix dates if corrupted
		now := time.Now()
		if record.ConnectedAt.IsZero() || record.ConnectedAt.Unix() < 0 || record.ConnectedAt.After(now.Add(time.Hour)) {
			record.ConnectedAt = now.Add(-time.Hour) // Default to 1 hour ago
		}
		if record.LastActivity.IsZero() || record.LastActivity.Unix() < 0 || record.LastActivity.After(now.Add(time.Hour)) {
			record.LastActivity = record.ConnectedAt
		}

		ch.connections[record.Domain] = &record
	}

	// Load recent history
	historyPattern := ch.keyPrefix + "history:*"
	historyKeys, err := ch.redisClient.Keys(ch.ctx, historyPattern).Result()
	if err != nil {
		log.Printf("ConnectionHistory: Failed to get history keys from Redis: %v", err)
		return
	}

	for _, key := range historyKeys {
		data, err := ch.redisClient.Get(ch.ctx, key).Result()
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if err := json.Unmarshal([]byte(data), &record); err != nil {
			continue
		}

		ch.history = append(ch.history, &record)
	}

	log.Printf("ConnectionHistory: Loaded %d active connections and %d history records from Redis", len(ch.connections), len(ch.history))
}

// refreshActiveFromRedis refreshes active connections from Redis (called with lock)
func (ch *ConnectionHistory) refreshActiveFromRedis() {
	if ch.redisClient == nil {
		return
	}

	activePattern := ch.keyPrefix + "active:*"
	activeKeys, err := ch.redisClient.Keys(ch.ctx, activePattern).Result()
	if err != nil {
		return
	}

	// Clear current active connections
	ch.connections = make(map[string]*ConnectionRecord)

	for _, key := range activeKeys {
		data, err := ch.redisClient.Get(ch.ctx, key).Result()
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if err := json.Unmarshal([]byte(data), &record); err != nil {
			continue
		}

		// Validate and fix dates if corrupted
		now := time.Now()
		if record.ConnectedAt.IsZero() || record.ConnectedAt.Unix() < 0 || record.ConnectedAt.After(now.Add(time.Hour)) {
			record.ConnectedAt = now.Add(-time.Hour) // Default to 1 hour ago
		}
		if record.LastActivity.IsZero() || record.LastActivity.Unix() < 0 || record.LastActivity.After(now.Add(time.Hour)) {
			record.LastActivity = record.ConnectedAt
		}

		ch.connections[record.Domain] = &record
	}
}

// refreshHistoryFromRedis refreshes history from Redis (called with lock)
func (ch *ConnectionHistory) refreshHistoryFromRedis() {
	if ch.redisClient == nil {
		return
	}

	historyPattern := ch.keyPrefix + "history:*"
	historyKeys, err := ch.redisClient.Keys(ch.ctx, historyPattern).Result()
	if err != nil {
		return
	}

	// Clear current history
	ch.history = make([]*ConnectionRecord, 0)

	for _, key := range historyKeys {
		data, err := ch.redisClient.Get(ch.ctx, key).Result()
		if err != nil {
			continue
		}

		var record ConnectionRecord
		if err := json.Unmarshal([]byte(data), &record); err != nil {
			continue
		}

		ch.history = append(ch.history, &record)
	}
}

// CleanupStaleConnections marks connections as disconnected if they're older than the timeout
func (ch *ConnectionHistory) CleanupStaleConnections(timeout time.Duration) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	now := time.Now()
	staleConnections := make([]string, 0)

	for domain, record := range ch.connections {
		if record.DisconnectedAt == nil && now.Sub(record.LastActivity) > timeout {
			// Mark as disconnected
			record.DisconnectedAt = &now
			record.Duration = now.Sub(record.ConnectedAt).String()
			record.Active = false

			staleConnections = append(staleConnections, domain)

			log.Printf("ConnectionHistory: Marked stale connection as disconnected: %s (last activity: %v ago)",
				domain, now.Sub(record.LastActivity))
		}
	}

	// Remove from active connections map and update Redis
	for _, domain := range staleConnections {
		if record, exists := ch.connections[domain]; exists {
			// Update in Redis before removing from map
			if ch.useRedis {
				ch.saveRecordToRedis(record)
			}
			delete(ch.connections, domain)
		}
	}
}

// periodicCleanup runs periodic cleanup of stale connections
func (ch *ConnectionHistory) periodicCleanup() {
	ticker := time.NewTicker(5 * time.Minute) // Nettoyage plus fréquent
	defer ticker.Stop()

	for range ticker.C {
		// Mark connections as disconnected if they're older than 15 minutes without activity
		ch.CleanupStaleConnections(15 * time.Minute) // Timeout réduit
	}
}
