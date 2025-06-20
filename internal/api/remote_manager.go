package api

import (
	"fmt"

	"github.com/p0rt/p0rt/internal/domain"
)

// RemoteReservationManager implements ReservationManagerInterface using API calls
type RemoteReservationManager struct {
	client *Client
}

// NewRemoteReservationManager creates a new remote reservation manager
func NewRemoteReservationManager(baseURL, apiKey string) *RemoteReservationManager {
	return &RemoteReservationManager{
		client: NewClient(baseURL, apiKey),
	}
}

// IsReserved checks if a domain is reserved
func (r *RemoteReservationManager) IsReserved(domain string) (bool, string) {
	reservation, err := r.client.GetReservation(domain)
	if err != nil {
		return false, ""
	}
	if reservation == nil {
		return false, ""
	}
	return true, reservation.Fingerprint
}

// GetReservedDomain gets the reserved domain for a fingerprint
func (r *RemoteReservationManager) GetReservedDomain(fingerprint string) (string, bool) {
	reservations, err := r.client.ListReservations()
	if err != nil {
		return "", false
	}

	for _, res := range reservations {
		if res.Fingerprint == fingerprint {
			return res.Domain, true
		}
	}

	return "", false
}

// AddReservation adds a new reservation
func (r *RemoteReservationManager) AddReservation(domain, fingerprint, comment string) error {
	return r.client.AddReservation(domain, fingerprint, comment)
}

// RemoveReservation removes a reservation by domain
func (r *RemoteReservationManager) RemoveReservation(domain string) error {
	return r.client.RemoveReservation(domain)
}

// RemoveReservationByFingerprint removes a reservation by fingerprint
func (r *RemoteReservationManager) RemoveReservationByFingerprint(fingerprint string) error {
	reservations, err := r.client.ListReservations()
	if err != nil {
		return err
	}

	for _, res := range reservations {
		if res.Fingerprint == fingerprint {
			return r.client.RemoveReservation(res.Domain)
		}
	}

	return fmt.Errorf("no reservation found for fingerprint %s", fingerprint)
}

// ListReservations lists all reservations
func (r *RemoteReservationManager) ListReservations() []domain.Reservation {
	reservations, err := r.client.ListReservations()
	if err != nil {
		return []domain.Reservation{}
	}
	return reservations
}

// GetStats gets reservation statistics
func (r *RemoteReservationManager) GetStats() map[string]interface{} {
	statsResponse, err := r.client.GetStats()
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}
	return statsResponse.ReservationStats
}

// Ping checks if the remote API is accessible
func (r *RemoteReservationManager) Ping() error {
	return r.client.Ping()
}
