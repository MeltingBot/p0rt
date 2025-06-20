package domain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ReservationManager handles reserved domains for specific SSH keys
type ReservationManager struct {
	reservations map[string]string // domain -> SSH key fingerprint
	reverseMap   map[string]string // SSH key fingerprint -> domain
	mu           sync.RWMutex
	filePath     string
}

// Reservation represents a domain reservation
type Reservation struct {
	Domain      string    `json:"domain"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Comment     string    `json:"comment,omitempty"`
}

// NewReservationManager creates a new reservation manager
func NewReservationManager(dataDir string) (*ReservationManager, error) {
	// Use default data directory if empty
	if dataDir == "" {
		dataDir = "./data"
	}
	
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory '%s': %w", dataDir, err)
	}

	rm := &ReservationManager{
		reservations: make(map[string]string),
		reverseMap:   make(map[string]string),
		filePath:     filepath.Join(dataDir, "reservations.json"),
	}

	// Load existing reservations
	if err := rm.load(); err != nil {
		return nil, fmt.Errorf("failed to load reservations: %w", err)
	}

	return rm, nil
}

// IsReserved checks if a domain is reserved and returns the SSH key fingerprint if it is
func (rm *ReservationManager) IsReserved(domain string) (bool, string) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	fingerprint, exists := rm.reservations[domain]
	return exists, fingerprint
}

// GetReservedDomain returns the reserved domain for an SSH key fingerprint
func (rm *ReservationManager) GetReservedDomain(fingerprint string) (string, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	domain, exists := rm.reverseMap[fingerprint]
	return domain, exists
}

// AddReservation adds a domain reservation for an SSH key fingerprint
func (rm *ReservationManager) AddReservation(domain, fingerprint, comment string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Validate domain format (must be three words separated by hyphens)
	if !isValidThreeWordDomain(domain) {
		return fmt.Errorf("invalid domain format: must be three words separated by hyphens")
	}

	// Check if domain is already reserved
	if existingFingerprint, exists := rm.reservations[domain]; exists {
		if existingFingerprint != fingerprint {
			return fmt.Errorf("domain %s is already reserved for another SSH key", domain)
		}
		// Update existing reservation
		rm.reservations[domain] = fingerprint
		rm.reverseMap[fingerprint] = domain
		return rm.save()
	}

	// Check if fingerprint already has a reservation
	if existingDomain, exists := rm.reverseMap[fingerprint]; exists {
		return fmt.Errorf("SSH key fingerprint %s already has reserved domain: %s", fingerprint, existingDomain)
	}

	// Add new reservation
	rm.reservations[domain] = fingerprint
	rm.reverseMap[fingerprint] = domain

	return rm.save()
}

// RemoveReservation removes a domain reservation
func (rm *ReservationManager) RemoveReservation(domain string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	fingerprint, exists := rm.reservations[domain]
	if !exists {
		return fmt.Errorf("domain %s is not reserved", domain)
	}

	delete(rm.reservations, domain)
	delete(rm.reverseMap, fingerprint)

	return rm.save()
}

// RemoveReservationByFingerprint removes a reservation by SSH key fingerprint
func (rm *ReservationManager) RemoveReservationByFingerprint(fingerprint string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	domain, exists := rm.reverseMap[fingerprint]
	if !exists {
		return fmt.Errorf("no reservation found for SSH key fingerprint %s", fingerprint)
	}

	delete(rm.reservations, domain)
	delete(rm.reverseMap, fingerprint)

	return rm.save()
}

// ListReservations returns all current reservations
func (rm *ReservationManager) ListReservations() []Reservation {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	reservations := make([]Reservation, 0, len(rm.reservations))
	for domain, fingerprint := range rm.reservations {
		reservations = append(reservations, Reservation{
			Domain:      domain,
			Fingerprint: fingerprint,
			CreatedAt:   time.Now(), // TODO: store actual creation time
			UpdatedAt:   time.Now(),
		})
	}

	return reservations
}

// GetStats returns reservation statistics
func (rm *ReservationManager) GetStats() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return map[string]interface{}{
		"total_reservations": len(rm.reservations),
		"reserved_domains":   len(rm.reservations),
	}
}

// load reads reservations from file
func (rm *ReservationManager) load() error {
	data, err := os.ReadFile(rm.filePath)
	if os.IsNotExist(err) {
		// File doesn't exist yet, that's okay
		return nil
	}
	if err != nil {
		return err
	}

	var reservations []Reservation
	if err := json.Unmarshal(data, &reservations); err != nil {
		return err
	}

	// Rebuild maps
	rm.reservations = make(map[string]string)
	rm.reverseMap = make(map[string]string)

	for _, res := range reservations {
		rm.reservations[res.Domain] = res.Fingerprint
		rm.reverseMap[res.Fingerprint] = res.Domain
	}

	return nil
}

// save writes reservations to file
func (rm *ReservationManager) save() error {
	reservations := make([]Reservation, 0, len(rm.reservations))
	for domain, fingerprint := range rm.reservations {
		reservations = append(reservations, Reservation{
			Domain:      domain,
			Fingerprint: fingerprint,
			CreatedAt:   time.Now(), // TODO: store actual times
			UpdatedAt:   time.Now(),
		})
	}

	data, err := json.MarshalIndent(reservations, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(rm.filePath, data, 0644)
}

// isValidThreeWordDomain checks if a domain follows the three-word format
func isValidThreeWordDomain(domain string) bool {
	parts := strings.Split(domain, "-")
	if len(parts) != 3 {
		return false
	}

	// Check that each part is a valid word (non-empty, alphanumeric)
	for _, part := range parts {
		if len(part) == 0 {
			return false
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
				return false
			}
		}
	}

	return true
}
