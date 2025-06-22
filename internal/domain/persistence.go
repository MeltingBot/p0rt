package domain

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DomainStore handles persistent storage of SSH key to domain mappings
type DomainStore struct {
	filePath string
	mutex    sync.RWMutex
	data     map[string]DomainRecord
}

// DomainRecord stores information about a domain assignment
type DomainRecord struct {
	Domain     string    `json:"domain"`
	SSHKeyHash string    `json:"ssh_key_hash"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	UseCount   int       `json:"use_count"`
}

// NewDomainStore creates a new domain store
func NewDomainStore(dataDir string) (*DomainStore, error) {
	// Use default data directory if empty
	if dataDir == "" {
		dataDir = "./data"
	}

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory '%s': %w", dataDir, err)
	}

	filePath := filepath.Join(dataDir, "domains.json")
	store := &DomainStore{
		filePath: filePath,
		data:     make(map[string]DomainRecord),
	}

	// Load existing data
	if err := store.load(); err != nil {
		// If file doesn't exist, that's okay
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load domain store: %w", err)
		}
	}

	// Start periodic save
	go store.periodicSave()

	return store, nil
}

// GetDomain returns the domain for a given SSH key hash, or empty string if not found
func (ds *DomainStore) GetDomain(sshKeyHash string) (string, bool) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	record, exists := ds.data[sshKeyHash]
	if !exists {
		return "", false
	}

	return record.Domain, true
}

// SetDomain stores a domain assignment
func (ds *DomainStore) SetDomain(sshKeyHash, domain string) error {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	now := time.Now()

	if record, exists := ds.data[sshKeyHash]; exists {
		// Update existing record
		record.LastSeen = now
		record.UseCount++
		ds.data[sshKeyHash] = record
	} else {
		// Create new record
		ds.data[sshKeyHash] = DomainRecord{
			Domain:     domain,
			SSHKeyHash: sshKeyHash,
			FirstSeen:  now,
			LastSeen:   now,
			UseCount:   1,
		}
	}

	// Save immediately for important changes
	return ds.save()
}

// IsDomainTaken checks if a domain is already assigned to another key
func (ds *DomainStore) IsDomainTaken(domain string) (bool, string) {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	for keyHash, record := range ds.data {
		if record.Domain == domain {
			return true, keyHash
		}
	}

	return false, ""
}

// GetStats returns statistics about domain usage
func (ds *DomainStore) GetStats() map[string]interface{} {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	totalDomains := len(ds.data)
	var activeLast24h int
	var activeLast7d int

	now := time.Now()
	for _, record := range ds.data {
		if now.Sub(record.LastSeen) < 24*time.Hour {
			activeLast24h++
		}
		if now.Sub(record.LastSeen) < 7*24*time.Hour {
			activeLast7d++
		}
	}

	return map[string]interface{}{
		"total_domains":   totalDomains,
		"active_last_24h": activeLast24h,
		"active_last_7d":  activeLast7d,
		"storage_file":    ds.filePath,
	}
}

// load reads the domain data from disk
func (ds *DomainStore) load() error {
	data, err := ioutil.ReadFile(ds.filePath)
	if err != nil {
		return err
	}

	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	return json.Unmarshal(data, &ds.data)
}

// save writes the domain data to disk
func (ds *DomainStore) save() error {
	data, err := json.MarshalIndent(ds.data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain data: %w", err)
	}

	// Write to temp file first
	tempFile := ds.filePath + ".tmp"
	if err := ioutil.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempFile, ds.filePath); err != nil {
		os.Remove(tempFile) // Clean up
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// periodicSave saves the data periodically
func (ds *DomainStore) periodicSave() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ds.mutex.RLock()
		hasData := len(ds.data) > 0
		ds.mutex.RUnlock()

		if hasData {
			if err := ds.save(); err != nil {
				// Log error but don't crash
				fmt.Printf("Error saving domain store: %v\n", err)
			}
		}
	}
}

// Cleanup removes domains that haven't been used in a specified duration
func (ds *DomainStore) Cleanup(maxAge time.Duration) int {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	now := time.Now()
	removed := 0

	for keyHash, record := range ds.data {
		if now.Sub(record.LastSeen) > maxAge {
			delete(ds.data, keyHash)
			removed++
		}
	}

	if removed > 0 {
		ds.save()
	}

	return removed
}
