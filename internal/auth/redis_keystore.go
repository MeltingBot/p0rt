package auth

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/ssh"
)

// Ensure RedisKeyStore implements KeyStoreInterface
var _ KeyStoreInterface = (*RedisKeyStore)(nil)

// RedisKeyStore manages authorized SSH keys using Redis as storage
type RedisKeyStore struct {
	mu        sync.RWMutex
	keys      map[string]*KeyAccess // fingerprint -> access (cached)
	client    *redis.Client
	allowAll  bool      // if true, all keys are allowed (open mode)
	keyPrefix string    // Redis key prefix
	ctx       context.Context
}

// NewRedisKeyStore creates a new Redis-backed key store
func NewRedisKeyStore(redisURL, keyPrefix string) (*RedisKeyStore, error) {
	if keyPrefix == "" {
		keyPrefix = "p0rt:keys:"
	}
	
	// Parse Redis URL
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}
	
	client := redis.NewClient(opts)
	ctx := context.Background()
	
	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis connection failed: %w", err)
	}
	
	ks := &RedisKeyStore{
		keys:      make(map[string]*KeyAccess),
		client:    client,
		allowAll:  false,
		keyPrefix: keyPrefix,
		ctx:       ctx,
	}

	// Check environment variable for open mode
	if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
		ks.allowAll = true
		log.Println("RedisKeyStore: Running in OPEN ACCESS mode - all keys allowed")
	}

	// Load existing keys from Redis
	if err := ks.loadKeys(); err != nil {
		log.Printf("RedisKeyStore: Failed to load keys: %v", err)
	}

	return ks, nil
}

// IsKeyAllowed checks if a public key is allowed
func (ks *RedisKeyStore) IsKeyAllowed(pubKey ssh.PublicKey) (bool, *KeyAccess) {
	// In open mode, all keys are allowed
	if ks.allowAll {
		return true, nil
	}

	fingerprint := ssh.FingerprintSHA256(pubKey)

	ks.mu.RLock()
	access, exists := ks.keys[fingerprint]
	ks.mu.RUnlock()

	if !exists {
		// Try to load from Redis if not in cache
		if access = ks.loadKeyFromRedis(fingerprint); access == nil {
			return false, nil
		}
		
		// Cache it
		ks.mu.Lock()
		ks.keys[fingerprint] = access
		ks.mu.Unlock()
	}

	// Check if key is active
	if !access.Active {
		return false, nil
	}

	// Check expiration
	if access.ExpiresAt != nil && time.Now().After(*access.ExpiresAt) {
		return false, nil
	}

	return true, access
}

// AddKey adds a new authorized key
func (ks *RedisKeyStore) AddKey(pubKeyStr string, comment string, tier string, expiresAt *time.Time) error {
	// Parse the public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(pubKey)

	access := &KeyAccess{
		Fingerprint: fingerprint,
		PublicKey:   pubKeyStr,
		Comment:     comment,
		Tier:        tier,
		AddedAt:     time.Now(),
		ExpiresAt:   expiresAt,
		Active:      true,
	}

	// Save to Redis
	if err := ks.saveKeyToRedis(fingerprint, access); err != nil {
		return err
	}

	// Update cache
	ks.mu.Lock()
	ks.keys[fingerprint] = access
	ks.mu.Unlock()

	return nil
}

// AddKeyByFingerprint adds a key using only the fingerprint
func (ks *RedisKeyStore) AddKeyByFingerprint(fingerprint string, comment string, tier string, expiresAt *time.Time) error {
	access := &KeyAccess{
		Fingerprint: fingerprint,
		PublicKey:   "", // No public key stored
		Comment:     comment,
		Tier:        tier,
		AddedAt:     time.Now(),
		ExpiresAt:   expiresAt,
		Active:      true,
	}

	// Save to Redis
	if err := ks.saveKeyToRedis(fingerprint, access); err != nil {
		return err
	}

	// Update cache
	ks.mu.Lock()
	ks.keys[fingerprint] = access
	ks.mu.Unlock()

	return nil
}

// RemoveKey removes a key by fingerprint
func (ks *RedisKeyStore) RemoveKey(fingerprint string) error {
	// Remove from Redis
	redisKey := ks.keyPrefix + fingerprint
	if err := ks.client.Del(ks.ctx, redisKey).Err(); err != nil {
		return fmt.Errorf("failed to remove key from Redis: %w", err)
	}

	// Remove from cache
	ks.mu.Lock()
	delete(ks.keys, fingerprint)
	ks.mu.Unlock()

	return nil
}

// DeactivateKey deactivates a key without removing it
func (ks *RedisKeyStore) DeactivateKey(fingerprint string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	access, exists := ks.keys[fingerprint]
	if !exists {
		// Load from Redis
		access = ks.loadKeyFromRedis(fingerprint)
		if access == nil {
			return fmt.Errorf("key not found: %s", fingerprint)
		}
		ks.keys[fingerprint] = access
	}

	access.Active = false
	return ks.saveKeyToRedis(fingerprint, access)
}

// ActivateKey reactivates a deactivated key
func (ks *RedisKeyStore) ActivateKey(fingerprint string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	access, exists := ks.keys[fingerprint]
	if !exists {
		// Load from Redis
		access = ks.loadKeyFromRedis(fingerprint)
		if access == nil {
			return fmt.Errorf("key not found: %s", fingerprint)
		}
		ks.keys[fingerprint] = access
	}

	access.Active = true
	return ks.saveKeyToRedis(fingerprint, access)
}

// ListKeys returns all keys
func (ks *RedisKeyStore) ListKeys() map[string]*KeyAccess {
	// Load all keys from Redis
	if err := ks.loadKeys(); err != nil {
		log.Printf("RedisKeyStore: Failed to refresh keys: %v", err)
	}

	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[string]*KeyAccess)
	for k, v := range ks.keys {
		result[k] = v
	}

	return result
}

// GetKeysByTier returns all keys for a specific tier
func (ks *RedisKeyStore) GetKeysByTier(tier string) []*KeyAccess {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var result []*KeyAccess
	for _, access := range ks.keys {
		if access.Tier == tier && access.Active {
			result = append(result, access)
		}
	}

	return result
}

// loadKeys loads all keys from Redis
func (ks *RedisKeyStore) loadKeys() error {
	pattern := ks.keyPrefix + "*"
	keys, err := ks.client.Keys(ks.ctx, pattern).Result()
	if err != nil {
		return err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Clear existing cache
	ks.keys = make(map[string]*KeyAccess)

	for _, key := range keys {
		fingerprint := strings.TrimPrefix(key, ks.keyPrefix)
		if access := ks.loadKeyFromRedis(fingerprint); access != nil {
			ks.keys[fingerprint] = access
		}
	}

	return nil
}

// loadKeyFromRedis loads a single key from Redis
func (ks *RedisKeyStore) loadKeyFromRedis(fingerprint string) *KeyAccess {
	redisKey := ks.keyPrefix + fingerprint
	data, err := ks.client.Get(ks.ctx, redisKey).Result()
	if err != nil {
		if err != redis.Nil {
			log.Printf("RedisKeyStore: Failed to load key %s: %v", fingerprint, err)
		}
		return nil
	}

	var access KeyAccess
	if err := json.Unmarshal([]byte(data), &access); err != nil {
		log.Printf("RedisKeyStore: Failed to parse key %s: %v", fingerprint, err)
		return nil
	}

	return &access
}

// saveKeyToRedis saves a key to Redis
func (ks *RedisKeyStore) saveKeyToRedis(fingerprint string, access *KeyAccess) error {
	data, err := json.Marshal(access)
	if err != nil {
		return fmt.Errorf("failed to marshal key data: %w", err)
	}

	redisKey := ks.keyPrefix + fingerprint
	
	// Set with TTL if key has expiration
	if access.ExpiresAt != nil {
		ttl := time.Until(*access.ExpiresAt)
		if ttl > 0 {
			return ks.client.Set(ks.ctx, redisKey, data, ttl).Err()
		}
	}

	// Set without TTL
	return ks.client.Set(ks.ctx, redisKey, data, 0).Err()
}

// ImportFromFile imports keys from an authorized_keys format file
func (ks *RedisKeyStore) ImportFromFile(filePath string, tier string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	imported := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract comment if present
		parts := strings.Fields(line)
		comment := ""
		if len(parts) >= 3 {
			comment = strings.Join(parts[2:], " ")
		}

		if err := ks.AddKey(line, comment, tier, nil); err != nil {
			log.Printf("Failed to import key: %v", err)
			continue
		}

		imported++
	}

	log.Printf("RedisKeyStore: Imported %d keys with tier '%s'", imported, tier)
	return scanner.Err()
}

// Close closes the Redis connection
func (ks *RedisKeyStore) Close() error {
	return ks.client.Close()
}