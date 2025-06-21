package auth

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// KeyAccess represents access level for a key
type KeyAccess struct {
	Fingerprint string     `json:"fingerprint"`
	PublicKey   string     `json:"public_key"`
	Comment     string     `json:"comment"`
	Tier        string     `json:"tier"` // "beta", "free", "premium", "vip"
	AddedAt     time.Time  `json:"added_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Active      bool       `json:"active"`
}

// KeyStore manages authorized SSH keys
type KeyStore struct {
	mu        sync.RWMutex
	keys      map[string]*KeyAccess // fingerprint -> access
	filePath  string
	allowAll  bool      // if true, all keys are allowed (open mode)
	lastCheck time.Time // last time we checked file modification
}

// NewKeyStore creates a new key store
func NewKeyStore(filePath string) *KeyStore {
	// Use default file path if empty
	if filePath == "" {
		filePath = "authorized_keys.json"
	}
	
	// Create directory if it doesn't exist
	if dir := filepath.Dir(filePath); dir != "." && dir != "" {
		os.MkdirAll(dir, 0755)
	}
	
	ks := &KeyStore{
		keys:      make(map[string]*KeyAccess),
		filePath:  filePath,
		allowAll:  false,
		lastCheck: time.Now(),
	}

	// Check environment variable for open mode
	if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
		ks.allowAll = true
		log.Println("KeyStore: Running in OPEN ACCESS mode - all keys allowed")
	}

	// Load existing keys
	if err := ks.loadKeys(); err != nil {
		log.Printf("KeyStore: Failed to load keys: %v", err)
	}

	return ks
}

// IsKeyAllowed checks if a public key is allowed
func (ks *KeyStore) IsKeyAllowed(pubKey ssh.PublicKey) (bool, *KeyAccess) {
	// In open mode, all keys are allowed
	if ks.allowAll {
		return true, nil
	}

	// Check if we need to reload keys from file
	ks.checkAndReloadKeys()

	fingerprint := ssh.FingerprintSHA256(pubKey)

	ks.mu.RLock()
	defer ks.mu.RUnlock()

	access, exists := ks.keys[fingerprint]
	if !exists {
		return false, nil
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
func (ks *KeyStore) AddKey(pubKeyStr string, comment string, tier string, expiresAt *time.Time) error {
	// Parse the public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(pubKey)

	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.keys[fingerprint] = &KeyAccess{
		Fingerprint: fingerprint,
		PublicKey:   pubKeyStr,
		Comment:     comment,
		Tier:        tier,
		AddedAt:     time.Now(),
		ExpiresAt:   expiresAt,
		Active:      true,
	}

	return ks.saveKeys()
}

// AddKeyByFingerprint adds a key using only the fingerprint (no public key required)
func (ks *KeyStore) AddKeyByFingerprint(fingerprint string, comment string, tier string, expiresAt *time.Time) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.keys[fingerprint] = &KeyAccess{
		Fingerprint: fingerprint,
		PublicKey:   "", // No public key stored
		Comment:     comment,
		Tier:        tier,
		AddedAt:     time.Now(),
		ExpiresAt:   expiresAt,
		Active:      true,
	}

	return ks.saveKeys()
}

// RemoveKey removes a key by fingerprint
func (ks *KeyStore) RemoveKey(fingerprint string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	delete(ks.keys, fingerprint)
	return ks.saveKeys()
}

// DeactivateKey deactivates a key without removing it
func (ks *KeyStore) DeactivateKey(fingerprint string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if access, exists := ks.keys[fingerprint]; exists {
		access.Active = false
		return ks.saveKeys()
	}

	return fmt.Errorf("key not found: %s", fingerprint)
}

// ActivateKey reactivates a deactivated key
func (ks *KeyStore) ActivateKey(fingerprint string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if access, exists := ks.keys[fingerprint]; exists {
		access.Active = true
		return ks.saveKeys()
	}

	return fmt.Errorf("key not found: %s", fingerprint)
}

// ListKeys returns all keys
func (ks *KeyStore) ListKeys() map[string]*KeyAccess {
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
func (ks *KeyStore) GetKeysByTier(tier string) []*KeyAccess {
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

// loadKeys loads keys from file
func (ks *KeyStore) loadKeys() error {
	file, err := os.Open(ks.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, that's OK
			return nil
		}
		return err
	}
	defer file.Close()

	var keys []*KeyAccess
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&keys); err != nil {
		return err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Convert to map
	for _, key := range keys {
		ks.keys[key.Fingerprint] = key
	}

	log.Printf("KeyStore: Loaded %d authorized keys", len(ks.keys))
	return nil
}

// saveKeys saves keys to file
func (ks *KeyStore) saveKeys() error {
	// Convert map to slice
	var keys []*KeyAccess
	for _, key := range ks.keys {
		keys = append(keys, key)
	}

	// Create temporary file
	tmpFile := ks.filePath + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(keys); err != nil {
		os.Remove(tmpFile)
		return err
	}

	// Atomic rename
	return os.Rename(tmpFile, ks.filePath)
}

// ImportFromFile imports keys from an authorized_keys format file
func (ks *KeyStore) ImportFromFile(filePath string, tier string) error {
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

	log.Printf("KeyStore: Imported %d keys with tier '%s'", imported, tier)
	return scanner.Err()
}

// GenerateKeyFingerprint generates a fingerprint from a public key string
func GenerateKeyFingerprint(pubKeyStr string) (string, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		return "", err
	}

	return ssh.FingerprintSHA256(pubKey), nil
}

// HashKey generates a short hash from a key fingerprint for logging
func HashKey(fingerprint string) string {
	h := sha256.Sum256([]byte(fingerprint))
	return fmt.Sprintf("%x", h[:4])
}

// checkAndReloadKeys checks if the key file has been modified and reloads if necessary
func (ks *KeyStore) checkAndReloadKeys() {
	// Only check every 1 second to avoid too frequent file system calls
	now := time.Now()
	if now.Sub(ks.lastCheck) < time.Second {
		return
	}
	
	ks.lastCheck = now
	
	// Check file modification time
	info, err := os.Stat(ks.filePath)
	if err != nil {
		// File doesn't exist or error accessing it
		return
	}
	
	// If file was modified after we last loaded it, reload
	if info.ModTime().After(ks.lastCheck.Add(-2 * time.Second)) {
		ks.mu.Lock()
		defer ks.mu.Unlock()
		
		// Clear existing keys
		ks.keys = make(map[string]*KeyAccess)
		
		// Reload from file
		if err := ks.loadKeysUnsafe(); err != nil {
			log.Printf("KeyStore: Failed to reload keys: %v", err)
		} else {
			log.Printf("KeyStore: Reloaded %d authorized keys", len(ks.keys))
		}
	}
}

// loadKeysUnsafe loads keys without locking (assumes caller has lock)
func (ks *KeyStore) loadKeysUnsafe() error {
	file, err := os.Open(ks.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, that's OK
			return nil
		}
		return err
	}
	defer file.Close()

	var keys []*KeyAccess
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&keys); err != nil {
		return err
	}

	// Convert to map
	for _, key := range keys {
		ks.keys[key.Fingerprint] = key
	}

	return nil
}
