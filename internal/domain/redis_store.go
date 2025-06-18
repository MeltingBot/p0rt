package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore handles persistent storage using Redis
type RedisStore struct {
	client *redis.Client
	prefix string
	ctx    context.Context
}

// NewRedisStore creates a new Redis-based domain store
func NewRedisStore(redisURL, password string, db int) (*RedisStore, error) {
	// Parse Redis URL or use default localhost
	var client *redis.Client

	if redisURL == "" {
		// Default local Redis
		client = redis.NewClient(&redis.Options{
			Addr:     "localhost:6379",
			Password: password,
			DB:       db,
		})
	} else {
		// Parse Redis URL
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
		}
		if password != "" {
			opt.Password = password
		}
		client = redis.NewClient(opt)
	}

	store := &RedisStore{
		client: client,
		prefix: "p0rt:domain:",
		ctx:    context.Background(),
	}

	// Test connection
	if err := store.ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return store, nil
}

// ping tests the Redis connection
func (rs *RedisStore) ping() error {
	return rs.client.Ping(rs.ctx).Err()
}

// GetDomain returns the domain for a given SSH key hash
func (rs *RedisStore) GetDomain(sshKeyHash string) (string, bool) {
	key := rs.prefix + sshKeyHash

	result, err := rs.client.HGetAll(rs.ctx, key).Result()
	if err != nil || len(result) == 0 {
		return "", false
	}

	domain, exists := result["domain"]
	if !exists {
		return "", false
	}

	// Update last seen
	rs.client.HSet(rs.ctx, key, "last_seen", time.Now().Unix())
	rs.client.HIncrBy(rs.ctx, key, "use_count", 1)

	return domain, true
}

// SetDomain stores a domain assignment
func (rs *RedisStore) SetDomain(sshKeyHash, domain string) error {
	key := rs.prefix + sshKeyHash
	now := time.Now().Unix()

	// Check if record exists
	exists, err := rs.client.Exists(rs.ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check key existence: %w", err)
	}

	if exists == 0 {
		// New record
		record := map[string]interface{}{
			"domain":       domain,
			"ssh_key_hash": sshKeyHash,
			"first_seen":   now,
			"last_seen":    now,
			"use_count":    1,
		}

		err = rs.client.HMSet(rs.ctx, key, record).Err()
		if err != nil {
			return fmt.Errorf("failed to create domain record: %w", err)
		}

		// Set expiration (optional - 1 year)
		rs.client.Expire(rs.ctx, key, 365*24*time.Hour)
	} else {
		// Update existing record
		rs.client.HSet(rs.ctx, key, "last_seen", now)
		rs.client.HIncrBy(rs.ctx, key, "use_count", 1)
	}

	// Also maintain reverse index for collision detection
	reverseKey := rs.prefix + "reverse:" + domain
	rs.client.Set(rs.ctx, reverseKey, sshKeyHash, 365*24*time.Hour)

	return nil
}

// IsDomainTaken checks if a domain is already assigned to another key
func (rs *RedisStore) IsDomainTaken(domain string) (bool, string) {
	reverseKey := rs.prefix + "reverse:" + domain

	keyHash, err := rs.client.Get(rs.ctx, reverseKey).Result()
	if err == redis.Nil {
		return false, ""
	}
	if err != nil {
		return false, ""
	}

	return true, keyHash
}

// GetStats returns statistics about domain usage
func (rs *RedisStore) GetStats() map[string]interface{} {
	// Count total domains
	pattern := rs.prefix + "*"
	keys, err := rs.client.Keys(rs.ctx, pattern).Result()
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	// Filter out reverse keys
	totalDomains := 0
	activeLast24h := 0
	activeLast7d := 0

	now := time.Now().Unix()
	day24Ago := now - 24*3600
	week7Ago := now - 7*24*3600

	for _, key := range keys {
		if !containsString(key, ":reverse:") {
			totalDomains++

			// Get last_seen
			lastSeenStr, err := rs.client.HGet(rs.ctx, key, "last_seen").Result()
			if err == nil {
				if lastSeen, err := strconv.ParseInt(lastSeenStr, 10, 64); err == nil {
					if lastSeen > day24Ago {
						activeLast24h++
					}
					if lastSeen > week7Ago {
						activeLast7d++
					}
				}
			}
		}
	}

	return map[string]interface{}{
		"total_domains":    totalDomains,
		"active_last_24h":  activeLast24h,
		"active_last_7d":   activeLast7d,
		"storage_type":     "redis",
		"redis_connection": rs.client.Options().Addr,
	}
}

// Cleanup removes domains that haven't been used in a specified duration
func (rs *RedisStore) Cleanup(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge).Unix()
	pattern := rs.prefix + "*"

	keys, err := rs.client.Keys(rs.ctx, pattern).Result()
	if err != nil {
		return 0
	}

	removed := 0
	for _, key := range keys {
		// Skip reverse keys
		if containsString(key, ":reverse:") {
			continue
		}

		lastSeenStr, err := rs.client.HGet(rs.ctx, key, "last_seen").Result()
		if err != nil {
			continue
		}

		lastSeen, err := strconv.ParseInt(lastSeenStr, 10, 64)
		if err != nil {
			continue
		}

		if lastSeen < cutoff {
			// Get domain for reverse key cleanup
			domain, err := rs.client.HGet(rs.ctx, key, "domain").Result()
			if err == nil {
				reverseKey := rs.prefix + "reverse:" + domain
				rs.client.Del(rs.ctx, reverseKey)
			}

			// Delete main key
			rs.client.Del(rs.ctx, key)
			removed++
		}
	}

	return removed
}

// Close closes the Redis connection
func (rs *RedisStore) Close() error {
	return rs.client.Close()
}

// ExportToJSON exports all domain data to JSON format
func (rs *RedisStore) ExportToJSON() ([]byte, error) {
	pattern := rs.prefix + "*"
	keys, err := rs.client.Keys(rs.ctx, pattern).Result()
	if err != nil {
		return nil, err
	}

	data := make(map[string]DomainRecord)

	for _, key := range keys {
		// Skip reverse keys
		if containsString(key, ":reverse:") {
			continue
		}

		result, err := rs.client.HGetAll(rs.ctx, key).Result()
		if err != nil {
			continue
		}

		// Parse timestamps
		firstSeen, _ := strconv.ParseInt(result["first_seen"], 10, 64)
		lastSeen, _ := strconv.ParseInt(result["last_seen"], 10, 64)
		useCount, _ := strconv.Atoi(result["use_count"])

		record := DomainRecord{
			Domain:     result["domain"],
			SSHKeyHash: result["ssh_key_hash"],
			FirstSeen:  time.Unix(firstSeen, 0),
			LastSeen:   time.Unix(lastSeen, 0),
			UseCount:   useCount,
		}

		data[result["ssh_key_hash"]] = record
	}

	return json.MarshalIndent(data, "", "  ")
}

// ImportFromJSON imports domain data from JSON format
func (rs *RedisStore) ImportFromJSON(jsonData []byte) error {
	var data map[string]DomainRecord
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return err
	}

	pipe := rs.client.Pipeline()

	for keyHash, record := range data {
		key := rs.prefix + keyHash

		recordMap := map[string]interface{}{
			"domain":       record.Domain,
			"ssh_key_hash": record.SSHKeyHash,
			"first_seen":   record.FirstSeen.Unix(),
			"last_seen":    record.LastSeen.Unix(),
			"use_count":    record.UseCount,
		}

		pipe.HMSet(rs.ctx, key, recordMap)
		pipe.Expire(rs.ctx, key, 365*24*time.Hour)

		// Reverse index
		reverseKey := rs.prefix + "reverse:" + record.Domain
		pipe.Set(rs.ctx, reverseKey, keyHash, 365*24*time.Hour)
	}

	_, err := pipe.Exec(rs.ctx)
	return err
}

// Helper function to check if string contains substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
