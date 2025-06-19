package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisReservationManager handles reserved domains using Redis
type RedisReservationManager struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisReservationManager creates a new Redis-based reservation manager
func NewRedisReservationManager(redisURL, password string, db int) (*RedisReservationManager, error) {
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

	return &RedisReservationManager{
		client: client,
		ctx:    ctx,
	}, nil
}

// IsReserved checks if a domain is reserved and returns the SSH key fingerprint if it is
func (rm *RedisReservationManager) IsReserved(domain string) (bool, string) {
	key := fmt.Sprintf("reservation:domain:%s", domain)
	fingerprint, err := rm.client.Get(rm.ctx, key).Result()
	if err == redis.Nil {
		return false, ""
	}
	if err != nil {
		return false, ""
	}
	return true, fingerprint
}

// GetReservedDomain returns the reserved domain for an SSH key fingerprint
func (rm *RedisReservationManager) GetReservedDomain(fingerprint string) (string, bool) {
	key := fmt.Sprintf("reservation:fingerprint:%s", fingerprint)
	domain, err := rm.client.Get(rm.ctx, key).Result()
	if err == redis.Nil {
		return "", false
	}
	if err != nil {
		return "", false
	}
	return domain, true
}

// AddReservation adds a domain reservation for an SSH key fingerprint
func (rm *RedisReservationManager) AddReservation(domain, fingerprint, comment string) error {
	// Validate domain format (must be three words separated by hyphens)
	if !isValidThreeWordDomain(domain) {
		return fmt.Errorf("invalid domain format: must be three words separated by hyphens")
	}

	// Check if domain is already reserved
	if reserved, existingFingerprint := rm.IsReserved(domain); reserved {
		if existingFingerprint != fingerprint {
			return fmt.Errorf("domain %s is already reserved for another SSH key", domain)
		}
		// Update existing reservation
		return rm.setReservation(domain, fingerprint, comment)
	}

	// Check if fingerprint already has a reservation
	if existingDomain, exists := rm.GetReservedDomain(fingerprint); exists {
		return fmt.Errorf("SSH key fingerprint %s already has reserved domain: %s", fingerprint, existingDomain)
	}

	// Add new reservation
	return rm.setReservation(domain, fingerprint, comment)
}

// setReservation sets the reservation in Redis
func (rm *RedisReservationManager) setReservation(domain, fingerprint, comment string) error {
	pipe := rm.client.Pipeline()

	// Set domain -> fingerprint mapping
	domainKey := fmt.Sprintf("reservation:domain:%s", domain)
	pipe.Set(rm.ctx, domainKey, fingerprint, 0)

	// Set fingerprint -> domain mapping
	fingerprintKey := fmt.Sprintf("reservation:fingerprint:%s", fingerprint)
	pipe.Set(rm.ctx, fingerprintKey, domain, 0)

	// Store reservation details
	reservation := Reservation{
		Domain:      domain,
		Fingerprint: fingerprint,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Comment:     comment,
	}

	reservationData, err := json.Marshal(reservation)
	if err != nil {
		return fmt.Errorf("failed to marshal reservation: %w", err)
	}

	detailsKey := fmt.Sprintf("reservation:details:%s", domain)
	pipe.Set(rm.ctx, detailsKey, reservationData, 0)

	// Add to reservation list
	pipe.SAdd(rm.ctx, "reservations:list", domain)

	_, err = pipe.Exec(rm.ctx)
	return err
}

// RemoveReservation removes a domain reservation
func (rm *RedisReservationManager) RemoveReservation(domain string) error {
	// Get fingerprint first
	reserved, fingerprint := rm.IsReserved(domain)
	if !reserved {
		return fmt.Errorf("domain %s is not reserved", domain)
	}

	pipe := rm.client.Pipeline()

	// Remove domain -> fingerprint mapping
	domainKey := fmt.Sprintf("reservation:domain:%s", domain)
	pipe.Del(rm.ctx, domainKey)

	// Remove fingerprint -> domain mapping
	fingerprintKey := fmt.Sprintf("reservation:fingerprint:%s", fingerprint)
	pipe.Del(rm.ctx, fingerprintKey)

	// Remove reservation details
	detailsKey := fmt.Sprintf("reservation:details:%s", domain)
	pipe.Del(rm.ctx, detailsKey)

	// Remove from reservation list
	pipe.SRem(rm.ctx, "reservations:list", domain)

	_, err := pipe.Exec(rm.ctx)
	return err
}

// RemoveReservationByFingerprint removes a reservation by SSH key fingerprint
func (rm *RedisReservationManager) RemoveReservationByFingerprint(fingerprint string) error {
	domain, exists := rm.GetReservedDomain(fingerprint)
	if !exists {
		return fmt.Errorf("no reservation found for SSH key fingerprint %s", fingerprint)
	}

	return rm.RemoveReservation(domain)
}

// ListReservations returns all current reservations
func (rm *RedisReservationManager) ListReservations() []Reservation {
	domains, err := rm.client.SMembers(rm.ctx, "reservations:list").Result()
	if err != nil {
		return []Reservation{}
	}

	var reservations []Reservation
	for _, domain := range domains {
		detailsKey := fmt.Sprintf("reservation:details:%s", domain)
		data, err := rm.client.Get(rm.ctx, detailsKey).Result()
		if err != nil {
			continue
		}

		var reservation Reservation
		if err := json.Unmarshal([]byte(data), &reservation); err != nil {
			continue
		}

		reservations = append(reservations, reservation)
	}

	return reservations
}

// GetStats returns reservation statistics
func (rm *RedisReservationManager) GetStats() map[string]interface{} {
	count, err := rm.client.SCard(rm.ctx, "reservations:list").Result()
	if err != nil {
		count = 0
	}

	return map[string]interface{}{
		"total_reservations": count,
		"reserved_domains":   count,
		"storage_type":       "redis",
	}
}

// Close closes the Redis connection
func (rm *RedisReservationManager) Close() error {
	return rm.client.Close()
}