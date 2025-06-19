package security

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// EventType represents different types of security events
type EventType string

const (
	EventAuthFailure     EventType = "auth_failure"
	EventBruteForce      EventType = "brute_force"
	EventPortScanning    EventType = "port_scanning"
	EventAbuseReport     EventType = "abuse_report"
	EventSuspiciousConn  EventType = "suspicious_connection"
	EventRateLimitHit    EventType = "rate_limit_hit"
)

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Type      EventType         `json:"type"`
	IP        string            `json:"ip"`
	Details   map[string]string `json:"details"`
	Severity  int               `json:"severity"` // 1-10 scale
}

// BannedIP represents a banned IP address
type BannedIP struct {
	IP        string    `json:"ip"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
	EventCount int      `json:"event_count"`
	Country   string    `json:"country,omitempty"`
}

// SecurityStats represents overall security statistics
type SecurityStats struct {
	AuthenticationFailures int                    `json:"authentication_failures"`
	BlockedIPsCount       int                    `json:"blocked_ips_count"`
	ScanningAttempts      int                    `json:"scanning_attempts"`
	AbuseReports          int                    `json:"abuse_reports"`
	Last24hFailures       int                    `json:"last_24h_failures"`
	GeographicBlocks      map[string]int         `json:"geographic_blocks"`
	BanReasons           map[string]int         `json:"ban_reasons"`
	TotalEvents          int                    `json:"total_events"`
	EventsByType         map[EventType]int      `json:"events_by_type"`
	TopOffenders         []string               `json:"top_offenders"`
}

// SecurityTracker manages security events and bans
type SecurityTracker struct {
	mu            sync.RWMutex
	events        []SecurityEvent
	bannedIPs     map[string]*BannedIP
	ipEventCounts map[string]int
	dataDir       string
	
	// Configuration
	maxEvents        int
	banThreshold     int
	banDuration      time.Duration
	bruteForceWindow time.Duration
	bruteForceLimit  int
}

// NewSecurityTracker creates a new security tracker
func NewSecurityTracker(dataDir string) *SecurityTracker {
	tracker := &SecurityTracker{
		events:        make([]SecurityEvent, 0),
		bannedIPs:     make(map[string]*BannedIP),
		ipEventCounts: make(map[string]int),
		dataDir:       dataDir,
		
		// Default configuration
		maxEvents:        10000,
		banThreshold:     5,
		banDuration:      24 * time.Hour,
		bruteForceWindow: 5 * time.Minute,
		bruteForceLimit:  3,
	}
	
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Printf("Warning: Failed to create security data directory: %v", err)
	}
	
	// Load existing data
	tracker.load()
	
	// Start cleanup routine
	go tracker.cleanupRoutine()
	
	return tracker
}

// RecordEvent records a security event
func (st *SecurityTracker) RecordEvent(eventType EventType, ip string, details map[string]string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	// Skip recording events for private/local IPs
	if st.isPrivateIP(ip) {
		return
	}
	
	event := SecurityEvent{
		ID:        fmt.Sprintf("%d-%s", time.Now().UnixNano(), ip),
		Timestamp: time.Now(),
		Type:      eventType,
		IP:        ip,
		Details:   details,
		Severity:  st.calculateSeverity(eventType, ip),
	}
	
	// Add to events list
	st.events = append(st.events, event)
	st.ipEventCounts[ip]++
	
	// Trim events if we exceed max
	if len(st.events) > st.maxEvents {
		st.events = st.events[len(st.events)-st.maxEvents:]
	}
	
	// Check if IP should be banned
	st.checkForBan(ip, eventType)
	
	// Save to disk
	go st.save()
	
	log.Printf("Security event recorded: %s from %s (severity: %d)", eventType, ip, event.Severity)
}

// IsBanned checks if an IP is currently banned
func (st *SecurityTracker) IsBanned(ip string) bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	// Never consider private IPs as banned
	if st.isPrivateIP(ip) {
		return false
	}
	
	bannedIP, exists := st.bannedIPs[ip]
	if !exists {
		return false
	}
	
	// Check if ban has expired
	if time.Now().After(bannedIP.ExpiresAt) {
		// Remove expired ban
		delete(st.bannedIPs, ip)
		go st.save()
		return false
	}
	
	return true
}

// BanIP manually bans an IP address
func (st *SecurityTracker) BanIP(ip, reason string, duration time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	// Don't ban private IPs
	if st.isPrivateIP(ip) {
		log.Printf("Skipped banning private IP: %s", ip)
		return
	}
	
	st.bannedIPs[ip] = &BannedIP{
		IP:        ip,
		BannedAt:  time.Now(),
		ExpiresAt: time.Now().Add(duration),
		Reason:    reason,
		EventCount: st.ipEventCounts[ip],
		Country:   st.getCountryForIP(ip),
	}
	
	go st.save()
	log.Printf("IP %s banned: %s (expires: %v)", ip, reason, time.Now().Add(duration))
}

// UnbanIP removes a ban on an IP address
func (st *SecurityTracker) UnbanIP(ip string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	
	delete(st.bannedIPs, ip)
	go st.save()
	log.Printf("IP %s unbanned", ip)
}

// GetBannedIPs returns all currently banned IPs
func (st *SecurityTracker) GetBannedIPs() []BannedIP {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	var banned []BannedIP
	now := time.Now()
	
	for ip, banInfo := range st.bannedIPs {
		if now.Before(banInfo.ExpiresAt) {
			banned = append(banned, *banInfo)
		} else {
			// Clean up expired bans
			delete(st.bannedIPs, ip)
		}
	}
	
	// Sort by ban time (most recent first)
	sort.Slice(banned, func(i, j int) bool {
		return banned[i].BannedAt.After(banned[j].BannedAt)
	})
	
	return banned
}

// GetSecurityStats returns comprehensive security statistics
func (st *SecurityTracker) GetSecurityStats() SecurityStats {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	stats := SecurityStats{
		GeographicBlocks: make(map[string]int),
		BanReasons:      make(map[string]int),
		EventsByType:    make(map[EventType]int),
		TopOffenders:    make([]string, 0),
	}
	
	// Count events by type
	last24h := time.Now().Add(-24 * time.Hour)
	
	for _, event := range st.events {
		stats.TotalEvents++
		stats.EventsByType[event.Type]++
		
		switch event.Type {
		case EventAuthFailure:
			stats.AuthenticationFailures++
			if event.Timestamp.After(last24h) {
				stats.Last24hFailures++
			}
		case EventPortScanning:
			stats.ScanningAttempts++
		case EventAbuseReport:
			stats.AbuseReports++
		}
	}
	
	// Count banned IPs and reasons
	stats.BlockedIPsCount = len(st.bannedIPs)
	for _, banInfo := range st.bannedIPs {
		stats.BanReasons[banInfo.Reason]++
		if banInfo.Country != "" {
			stats.GeographicBlocks[banInfo.Country]++
		}
	}
	
	// Get top offenders
	type ipCount struct {
		ip    string
		count int
	}
	var ipCounts []ipCount
	for ip, count := range st.ipEventCounts {
		ipCounts = append(ipCounts, ipCount{ip, count})
	}
	sort.Slice(ipCounts, func(i, j int) bool {
		return ipCounts[i].count > ipCounts[j].count
	})
	
	// Take top 5 offenders
	for i, ic := range ipCounts {
		if i >= 5 {
			break
		}
		stats.TopOffenders = append(stats.TopOffenders, fmt.Sprintf("%s (%d events)", ic.ip, ic.count))
	}
	
	return stats
}

// checkForBan checks if an IP should be automatically banned
func (st *SecurityTracker) checkForBan(ip string, eventType EventType) {
	// Skip banning for localhost/private IPs
	if st.isPrivateIP(ip) {
		return
	}
	
	eventCount := st.ipEventCounts[ip]
	
	// Ban based on total event count threshold
	if eventCount >= st.banThreshold {
		reason := "repeated_violations"
		if eventType == EventAuthFailure {
			reason = "brute_force"
		} else if eventType == EventPortScanning {
			reason = "scanning"
		}
		
		st.bannedIPs[ip] = &BannedIP{
			IP:        ip,
			BannedAt:  time.Now(),
			ExpiresAt: time.Now().Add(st.banDuration),
			Reason:    reason,
			EventCount: eventCount,
			Country:   st.getCountryForIP(ip),
		}
		
		log.Printf("Auto-banned IP %s for %s (event count: %d)", ip, reason, eventCount)
		return
	}
	
	// Check for brute force (rapid auth failures)
	if eventType == EventAuthFailure {
		recentFailures := 0
		cutoff := time.Now().Add(-st.bruteForceWindow)
		
		for _, event := range st.events {
			if event.IP == ip && event.Type == EventAuthFailure && event.Timestamp.After(cutoff) {
				recentFailures++
			}
		}
		
		if recentFailures >= st.bruteForceLimit {
			st.bannedIPs[ip] = &BannedIP{
				IP:        ip,
				BannedAt:  time.Now(),
				ExpiresAt: time.Now().Add(st.banDuration),
				Reason:    "brute_force",
				EventCount: eventCount,
				Country:   st.getCountryForIP(ip),
			}
			
			log.Printf("Auto-banned IP %s for brute force (%d failures in %v)", ip, recentFailures, st.bruteForceWindow)
		}
	}
}

// calculateSeverity calculates event severity based on type and history
func (st *SecurityTracker) calculateSeverity(eventType EventType, ip string) int {
	base := map[EventType]int{
		EventAuthFailure:     3,
		EventBruteForce:      8,
		EventPortScanning:    6,
		EventAbuseReport:     9,
		EventSuspiciousConn:  4,
		EventRateLimitHit:    2,
	}
	
	severity := base[eventType]
	
	// Increase severity for repeat offenders
	if count := st.ipEventCounts[ip]; count > 0 {
		severity += min(count, 3)
	}
	
	return min(severity, 10)
}

// isPrivateIP checks if an IP is private/local
func (st *SecurityTracker) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	return parsedIP.IsLoopback() || parsedIP.IsPrivate()
}

// getCountryForIP returns country code for IP (placeholder implementation)
func (st *SecurityTracker) getCountryForIP(ip string) string {
	// This would use a GeoIP database in production
	// For now, return placeholder
	return ""
}

// cleanupRoutine periodically cleans up expired bans and old events
func (st *SecurityTracker) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		st.mu.Lock()
		
		// Remove expired bans
		now := time.Now()
		for ip, banInfo := range st.bannedIPs {
			if now.After(banInfo.ExpiresAt) {
				delete(st.bannedIPs, ip)
			}
		}
		
		// Trim old events (keep only last 30 days)
		cutoff := time.Now().Add(-30 * 24 * time.Hour)
		filtered := make([]SecurityEvent, 0)
		for _, event := range st.events {
			if event.Timestamp.After(cutoff) {
				filtered = append(filtered, event)
			}
		}
		st.events = filtered
		
		st.mu.Unlock()
		
		// Save cleaned data
		st.save()
	}
}

// save persists security data to disk
func (st *SecurityTracker) save() {
	st.mu.RLock()
	defer st.mu.RUnlock()
	
	// Save events
	eventsFile := filepath.Join(st.dataDir, "security_events.json")
	if data, err := json.MarshalIndent(st.events, "", "  "); err == nil {
		os.WriteFile(eventsFile, data, 0644)
	}
	
	// Save bans
	bansFile := filepath.Join(st.dataDir, "banned_ips.json")
	if data, err := json.MarshalIndent(st.bannedIPs, "", "  "); err == nil {
		os.WriteFile(bansFile, data, 0644)
	}
	
	// Save IP counts
	countsFile := filepath.Join(st.dataDir, "ip_counts.json")
	if data, err := json.MarshalIndent(st.ipEventCounts, "", "  "); err == nil {
		os.WriteFile(countsFile, data, 0644)
	}
}

// load restores security data from disk
func (st *SecurityTracker) load() {
	// Load events
	eventsFile := filepath.Join(st.dataDir, "security_events.json")
	if data, err := os.ReadFile(eventsFile); err == nil {
		json.Unmarshal(data, &st.events)
	}
	
	// Load bans
	bansFile := filepath.Join(st.dataDir, "banned_ips.json")
	if data, err := os.ReadFile(bansFile); err == nil {
		json.Unmarshal(data, &st.bannedIPs)
	}
	
	// Load IP counts
	countsFile := filepath.Join(st.dataDir, "ip_counts.json")
	if data, err := os.ReadFile(countsFile); err == nil {
		json.Unmarshal(data, &st.ipEventCounts)
	}
	
	log.Printf("Security tracker loaded: %d events, %d banned IPs", len(st.events), len(st.bannedIPs))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}