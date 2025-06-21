package auth

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// KeyStoreInterface defines the interface for SSH key storage
type KeyStoreInterface interface {
	IsKeyAllowed(pubKey ssh.PublicKey) (bool, *KeyAccess)
	AddKey(pubKeyStr string, comment string, tier string, expiresAt *time.Time) error
	AddKeyByFingerprint(fingerprint string, comment string, tier string, expiresAt *time.Time) error
	RemoveKey(fingerprint string) error
	DeactivateKey(fingerprint string) error
	ActivateKey(fingerprint string) error
	ListKeys() map[string]*KeyAccess
	GetKeysByTier(tier string) []*KeyAccess
	ImportFromFile(filePath string, tier string) error
}

// NewKeyStoreFromConfig creates a key store based on environment configuration
func NewKeyStoreFromConfig() (KeyStoreInterface, error) {
	// Check if Redis URL is provided
	redisURL := getRedisURL()
	if redisURL != "" {
		return NewRedisKeyStore(redisURL, "p0rt:keys:")
	}

	// Fallback to JSON file storage
	keysFile := os.Getenv("P0RT_AUTHORIZED_KEYS")
	if keysFile == "" {
		keysFile = "authorized_keys.json"
	}
	
	return NewKeyStore(keysFile), nil
}

// getRedisURL returns the Redis URL from environment variables
func getRedisURL() string {
	// Try different environment variable names
	if url := os.Getenv("REDIS_URL"); url != "" {
		return url
	}
	if url := os.Getenv("P0RT_REDIS_URL"); url != "" {
		return url
	}
	
	// Build URL from components
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
	
	url := fmt.Sprintf("redis://:%s@%s:%s/%s", password, host, port, db)
	if password == "" {
		url = fmt.Sprintf("redis://%s:%s/%s", host, port, db)
	}
	
	return url
}