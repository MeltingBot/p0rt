package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
)

// Ensure RedisSecurityTracker implements SecurityTrackerInterface
var _ SecurityTrackerInterface = (*RedisSecurityTracker)(nil)

// RedisSecurityTracker manages security events and bans using Redis
type RedisSecurityTracker struct {
	client    *redis.Client
	ctx       context.Context
	keyPrefix string

	// Configuration
	maxEvents        int
	banThreshold     int
	banDuration      time.Duration
	bruteForceWindow time.Duration
	bruteForceLimit  int
}

// NewRedisSecurityTracker creates a new Redis-based security tracker
func NewRedisSecurityTracker(redisURL, password string, db int) (*RedisSecurityTracker, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	if password != "" {
		opt.Password = password
	}
	if db != 0 {
		opt.DB = db
	}

	client := redis.NewClient(opt)

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	tracker := &RedisSecurityTracker{
		client:    client,
		ctx:       ctx,
		keyPrefix: "p0rt:security:",

		// Default configuration
		maxEvents:        10000,
		banThreshold:     5,
		banDuration:      24 * time.Hour,
		bruteForceWindow: 5 * time.Minute,
		bruteForceLimit:  3,
	}

	// Start cleanup routine
	go tracker.cleanupRoutine()

	log.Println("RedisSecurityTracker: Initialized with Redis storage")
	return tracker, nil
}

// RecordEvent records a security event
func (rst *RedisSecurityTracker) RecordEvent(eventType EventType, ip string, details map[string]string) {
	// Normalize IP address for consistent storage
	ip = normalizeIP(ip)

	// Skip recording events for private/local IPs
	if rst.isPrivateIP(ip) {
		return
	}

	event := SecurityEvent{
		ID:        fmt.Sprintf("%d-%s", time.Now().UnixNano(), ip),
		Timestamp: time.Now(),
		Type:      eventType,
		IP:        ip,
		Details:   details,
		Severity:  rst.calculateSeverity(eventType, ip),
	}

	// Store event in Redis
	rst.storeEvent(event)

	// Increment IP event count
	countKey := rst.keyPrefix + "count:" + ip
	newCount := rst.client.Incr(rst.ctx, countKey)
	rst.client.Expire(rst.ctx, countKey, 30*24*time.Hour) // Expire after 30 days

	log.Printf("📈 Event count for IP %s incremented to %d (event: %s)", ip, newCount.Val(), eventType)

	// Check if IP should be banned
	rst.checkForBan(ip, eventType)

	log.Printf("Security event recorded: %s from %s (severity: %d)", eventType, ip, event.Severity)
}

// storeEvent stores an event in Redis
func (rst *RedisSecurityTracker) storeEvent(event SecurityEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("RedisSecurityTracker: Failed to marshal event: %v", err)
		return
	}

	// Store event with timestamp as score for easy retrieval
	eventKey := rst.keyPrefix + "events"
	score := float64(event.Timestamp.Unix())

	rst.client.ZAdd(rst.ctx, eventKey, redis.Z{
		Score:  score,
		Member: data,
	})

	// Trim old events to keep only maxEvents
	rst.client.ZRemRangeByRank(rst.ctx, eventKey, 0, -int64(rst.maxEvents)-1)

	// Also store by IP for quick lookup
	ipEventKey := rst.keyPrefix + "events:ip:" + event.IP
	rst.client.ZAdd(rst.ctx, ipEventKey, redis.Z{
		Score:  score,
		Member: data,
	})
	rst.client.Expire(rst.ctx, ipEventKey, 30*24*time.Hour)
}

// IsBanned checks if an IP is currently banned
func (rst *RedisSecurityTracker) IsBanned(ip string) bool {
	// Normalize IP address for consistent lookup
	ip = normalizeIP(ip)

	// Never consider private IPs as banned
	if rst.isPrivateIP(ip) {
		return false
	}

	banKey := rst.keyPrefix + "ban:" + ip
	data, err := rst.client.Get(rst.ctx, banKey).Result()
	if err == redis.Nil {
		return false
	}
	if err != nil {
		return false
	}

	var bannedIP BannedIP
	if err := json.Unmarshal([]byte(data), &bannedIP); err != nil {
		return false
	}

	// Check if ban has expired
	if time.Now().After(bannedIP.ExpiresAt) {
		// Remove expired ban
		rst.client.Del(rst.ctx, banKey)
		return false
	}

	return true
}

// BanIP manually bans an IP address
func (rst *RedisSecurityTracker) BanIP(ip, reason string, duration time.Duration) {
	// Normalize IP address for consistent storage
	ip = normalizeIP(ip)

	// Don't ban private IPs
	if rst.isPrivateIP(ip) {
		log.Printf("Skipped banning private IP: %s", ip)
		return
	}

	eventCount := rst.getEventCount(ip)
	bannedIP := &BannedIP{
		IP:         ip,
		BannedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(duration),
		Reason:     reason,
		EventCount: eventCount,
		Country:    rst.getCountryForIP(ip),
	}

	data, err := json.Marshal(bannedIP)
	if err != nil {
		log.Printf("RedisSecurityTracker: Failed to marshal banned IP: %v", err)
		return
	}

	banKey := rst.keyPrefix + "ban:" + ip
	rst.client.Set(rst.ctx, banKey, data, duration)

	log.Printf("IP %s banned: %s (expires: %v)", ip, reason, time.Now().Add(duration))
}

// UnbanIP removes a ban on an IP address
func (rst *RedisSecurityTracker) UnbanIP(ip string) {
	// Normalize the IP to ensure consistent format
	normalizedIP := normalizeIP(ip)

	// Also try with brackets in case some keys were stored that way
	bracketedIP := "[" + normalizedIP + "]"

	// Remove all keys related to this IP (try both formats)
	keysToDelete := []string{
		// Normalized IP format
		rst.keyPrefix + "ban:" + normalizedIP,
		rst.keyPrefix + "events:ip:" + normalizedIP,
		rst.keyPrefix + "auth_failures:" + normalizedIP,
		rst.keyPrefix + "count:" + normalizedIP,

		// Bracketed IP format (legacy cleanup)
		rst.keyPrefix + "ban:" + bracketedIP,
		rst.keyPrefix + "events:ip:" + bracketedIP,
		rst.keyPrefix + "auth_failures:" + bracketedIP,
		rst.keyPrefix + "count:" + bracketedIP,
	}

	deletedCount := 0
	for _, key := range keysToDelete {
		result := rst.client.Del(rst.ctx, key)
		if result.Val() > 0 {
			deletedCount++
			log.Printf("🗑️ Deleted Redis key: %s", key)
		}
	}

	log.Printf("IP %s unbanned and all related Redis keys cleared (deleted %d keys, normalized: %s)", ip, deletedCount, normalizedIP)
}

// GetBannedIPs returns all currently banned IPs
func (rst *RedisSecurityTracker) GetBannedIPs() []BannedIP {
	pattern := rst.keyPrefix + "ban:*"
	keys, err := rst.client.Keys(rst.ctx, pattern).Result()
	if err != nil {
		return []BannedIP{}
	}

	var banned []BannedIP
	now := time.Now()

	for _, key := range keys {
		data, err := rst.client.Get(rst.ctx, key).Result()
		if err != nil {
			continue
		}

		var bannedIP BannedIP
		if err := json.Unmarshal([]byte(data), &bannedIP); err != nil {
			continue
		}

		if now.Before(bannedIP.ExpiresAt) {
			banned = append(banned, bannedIP)
		} else {
			// Clean up expired ban
			rst.client.Del(rst.ctx, key)
		}
	}

	// Sort by ban time (most recent first)
	sort.Slice(banned, func(i, j int) bool {
		return banned[i].BannedAt.After(banned[j].BannedAt)
	})

	return banned
}

// GetSecurityStats returns comprehensive security statistics
func (rst *RedisSecurityTracker) GetSecurityStats() SecurityStats {
	stats := SecurityStats{
		GeographicBlocks: make(map[string]int),
		BanReasons:       make(map[string]int),
		EventsByType:     make(map[EventType]int),
		TopOffenders:     make([]string, 0),
	}

	// Get all events from last 30 days
	eventKey := rst.keyPrefix + "events"
	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour).Unix()
	events, err := rst.client.ZRangeByScore(rst.ctx, eventKey, &redis.ZRangeBy{
		Min: fmt.Sprintf("%d", thirtyDaysAgo),
		Max: "+inf",
	}).Result()

	if err == nil {
		last24h := time.Now().Add(-24 * time.Hour)

		for _, eventData := range events {
			var event SecurityEvent
			if err := json.Unmarshal([]byte(eventData), &event); err != nil {
				continue
			}

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
	}

	// Count banned IPs and reasons
	banPattern := rst.keyPrefix + "ban:*"
	banKeys, err := rst.client.Keys(rst.ctx, banPattern).Result()
	if err == nil {
		stats.BlockedIPsCount = len(banKeys)
		for _, key := range banKeys {
			data, err := rst.client.Get(rst.ctx, key).Result()
			if err != nil {
				continue
			}

			var bannedIP BannedIP
			if err := json.Unmarshal([]byte(data), &bannedIP); err != nil {
				continue
			}

			stats.BanReasons[bannedIP.Reason]++
			if bannedIP.Country != "" {
				stats.GeographicBlocks[bannedIP.Country]++
			}
		}
	}

	// Get top offenders from IP counts
	countPattern := rst.keyPrefix + "count:*"
	countKeys, err := rst.client.Keys(rst.ctx, countPattern).Result()
	if err == nil {
		type ipCount struct {
			ip    string
			count int64
		}
		var ipCounts []ipCount

		for _, key := range countKeys {
			count, err := rst.client.Get(rst.ctx, key).Int64()
			if err != nil {
				continue
			}
			ip := key[len(rst.keyPrefix+"count:"):]
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
	}

	return stats
}

// getEventCount gets the event count for an IP
func (rst *RedisSecurityTracker) getEventCount(ip string) int {
	countKey := rst.keyPrefix + "count:" + ip
	count, err := rst.client.Get(rst.ctx, countKey).Int()
	if err != nil {
		return 0
	}
	return count
}

// checkForBan checks if an IP should be automatically banned
func (rst *RedisSecurityTracker) checkForBan(ip string, eventType EventType) {
	// Skip banning for localhost/private IPs
	if rst.isPrivateIP(ip) {
		return
	}

	eventCount := rst.getEventCount(ip)
	log.Printf("🔍 Security check for IP %s: event count = %d, threshold = %d, event type = %s", ip, eventCount, rst.banThreshold, eventType)

	// Ban based on total event count threshold
	if eventCount >= rst.banThreshold {
		reason := "repeated_violations"
		if eventType == EventAuthFailure {
			reason = "brute_force"
		} else if eventType == EventPortScanning {
			reason = "scanning"
		}

		log.Printf("🚨 About to auto-ban IP %s for %s (event count: %d >= threshold: %d)", ip, reason, eventCount, rst.banThreshold)
		rst.BanIP(ip, reason, rst.banDuration)
		log.Printf("Auto-banned IP %s for %s (event count: %d)", ip, reason, eventCount)
		return
	}

	// Check for brute force (rapid auth failures)
	if eventType == EventAuthFailure {
		cutoff := time.Now().Add(-rst.bruteForceWindow).Unix()
		ipEventKey := rst.keyPrefix + "events:ip:" + ip

		// Count recent auth failures
		recentEvents, err := rst.client.ZRangeByScore(rst.ctx, ipEventKey, &redis.ZRangeBy{
			Min: fmt.Sprintf("%d", cutoff),
			Max: "+inf",
		}).Result()

		if err == nil {
			recentFailures := 0
			for _, eventData := range recentEvents {
				var event SecurityEvent
				if err := json.Unmarshal([]byte(eventData), &event); err != nil {
					continue
				}
				if event.Type == EventAuthFailure {
					recentFailures++
				}
			}

			if recentFailures >= rst.bruteForceLimit {
				rst.BanIP(ip, "brute_force", rst.banDuration)
				log.Printf("Auto-banned IP %s for brute force (%d failures in %v)", ip, recentFailures, rst.bruteForceWindow)
			}
		}
	}
}

// calculateSeverity calculates event severity based on type and history
func (rst *RedisSecurityTracker) calculateSeverity(eventType EventType, ip string) int {
	base := map[EventType]int{
		EventAuthFailure:    3,
		EventBruteForce:     8,
		EventPortScanning:   6,
		EventAbuseReport:    9,
		EventSuspiciousConn: 4,
		EventRateLimitHit:   2,
	}

	severity := base[eventType]

	// Increase severity for repeat offenders
	if count := rst.getEventCount(ip); count > 0 {
		severity += min(count, 3)
	}

	return min(severity, 10)
}

// isPrivateIP checks if an IP is private/local
func (rst *RedisSecurityTracker) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return parsedIP.IsLoopback() || parsedIP.IsPrivate()
}

// normalizeIP removes brackets from IPv6 addresses for consistent storage
func normalizeIP(ip string) string {
	// Remove brackets from IPv6 addresses: [2001:db8::1] -> 2001:db8::1
	if len(ip) > 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
		return ip[1 : len(ip)-1]
	}
	return ip
}

// getCountryForIP returns country code for IP (placeholder implementation)
func (rst *RedisSecurityTracker) getCountryForIP(ip string) string {
	// This would use a GeoIP database in production
	// For now, return placeholder
	return ""
}

// cleanupRoutine periodically cleans up expired bans and old events
func (rst *RedisSecurityTracker) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		// Clean up expired bans (Redis TTL handles this automatically)

		// Clean up old events (keep only last 30 days)
		cutoff := time.Now().Add(-30 * 24 * time.Hour).Unix()
		eventKey := rst.keyPrefix + "events"
		rst.client.ZRemRangeByScore(rst.ctx, eventKey, "-inf", fmt.Sprintf("%d", cutoff))

		// Clean up old IP event collections
		ipEventPattern := rst.keyPrefix + "events:ip:*"
		ipEventKeys, err := rst.client.Keys(rst.ctx, ipEventPattern).Result()
		if err == nil {
			for _, key := range ipEventKeys {
				rst.client.ZRemRangeByScore(rst.ctx, key, "-inf", fmt.Sprintf("%d", cutoff))
			}
		}
	}
}

// Close closes the Redis connection
func (rst *RedisSecurityTracker) Close() error {
	return rst.client.Close()
}
