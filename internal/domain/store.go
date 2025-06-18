package domain

import (
	"fmt"
	"time"
)

// Store interface for domain persistence backends
type Store interface {
	// GetDomain returns the domain for a given SSH key hash
	GetDomain(sshKeyHash string) (string, bool)

	// SetDomain stores a domain assignment
	SetDomain(sshKeyHash, domain string) error

	// IsDomainTaken checks if a domain is already assigned to another key
	IsDomainTaken(domain string) (bool, string)

	// GetStats returns statistics about domain usage
	GetStats() map[string]interface{}

	// Cleanup removes domains that haven't been used in a specified duration
	Cleanup(maxAge time.Duration) int
}

// StorageConfig is imported from config package
// Use a local type to avoid circular imports
type storageConfig struct {
	Type          string
	DataDir       string
	RedisURL      string
	RedisPassword string
	RedisDB       int
}

// NewStore creates a store based on configuration
func NewStore(config storageConfig) (Store, error) {
	switch config.Type {
	case "redis":
		return NewRedisStore(config.RedisURL, config.RedisPassword, config.RedisDB)
	case "json", "":
		// Default to JSON if not specified
		if config.DataDir == "" {
			config.DataDir = "./data"
		}
		return NewDomainStore(config.DataDir)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.Type)
	}
}
