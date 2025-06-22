package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/p0rt/p0rt/internal/domain"
	"github.com/p0rt/p0rt/internal/stats"
)

// Client represents an API client
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new API client
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// makeRequest makes an HTTP request to the API
func (c *Client) makeRequest(method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errorResponse struct {
			Error   bool   `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(responseBody, &errorResponse); err == nil && errorResponse.Error {
			return nil, fmt.Errorf("API error: %s", errorResponse.Message)
		}
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(responseBody))
	}

	return responseBody, nil
}

// APIReservationsResponse represents the response from the reservations API
type APIReservationsResponse struct {
	Success      bool                 `json:"success"`
	Reservations []domain.Reservation `json:"reservations"`
	Count        int                  `json:"count"`
	Timestamp    string               `json:"timestamp"`
}

// APIReservationResponse represents the response from a single reservation API
type APIReservationResponse struct {
	Success     bool                `json:"success"`
	Reservation *domain.Reservation `json:"reservation"`
	Timestamp   string              `json:"timestamp"`
}

// APIStatsResponse represents the response from the stats API
type APIStatsResponse struct {
	Success          bool                   `json:"success"`
	GlobalStats      *stats.GlobalStats     `json:"global_stats"`
	ReservationStats map[string]interface{} `json:"reservation_stats"`
	Timestamp        string                 `json:"timestamp"`
}

// APITunnelStatsResponse represents the response from the tunnel stats API
type APITunnelStatsResponse struct {
	Success     bool               `json:"success"`
	TunnelStats *stats.TunnelStats `json:"tunnel_stats"`
	Timestamp   string             `json:"timestamp"`
}

// APIStatusResponse represents the response from the status API
type APIStatusResponse struct {
	Success       bool   `json:"success"`
	Service       string `json:"service"`
	Version       string `json:"version"`
	APIVersion    string `json:"api_version"`
	Uptime        string `json:"uptime,omitempty"`
	ActiveTunnels int    `json:"active_tunnels,omitempty"`
	Timestamp     string `json:"timestamp"`
}

// ListReservations retrieves all reservations from the API
func (c *Client) ListReservations() ([]domain.Reservation, error) {
	responseBody, err := c.makeRequest("GET", "/api/v1/reservations", nil)
	if err != nil {
		return nil, err
	}

	var response APIReservationsResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API request failed")
	}

	return response.Reservations, nil
}

// GetReservation retrieves a specific reservation from the API
func (c *Client) GetReservation(domain string) (*domain.Reservation, error) {
	path := "/api/v1/reservations/" + url.PathEscape(domain)
	responseBody, err := c.makeRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response APIReservationResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API request failed")
	}

	return response.Reservation, nil
}

// AddReservation adds a new reservation via the API
func (c *Client) AddReservation(domain, fingerprint, comment string) error {
	body := map[string]string{
		"domain":      domain,
		"fingerprint": fingerprint,
		"comment":     comment,
	}

	_, err := c.makeRequest("POST", "/api/v1/reservations", body)
	return err
}

// RemoveReservation removes a reservation via the API
func (c *Client) RemoveReservation(domain string) error {
	path := "/api/v1/reservations/" + url.PathEscape(domain)
	_, err := c.makeRequest("DELETE", path, nil)
	return err
}

// GetStats retrieves system statistics from the API
func (c *Client) GetStats() (*APIStatsResponse, error) {
	responseBody, err := c.makeRequest("GET", "/api/v1/stats", nil)
	if err != nil {
		return nil, err
	}

	var response APIStatsResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API request failed")
	}

	return &response, nil
}

// GetTunnelStats retrieves tunnel statistics for a specific domain from the API
func (c *Client) GetTunnelStats(domain string) (*stats.TunnelStats, error) {
	path := "/api/v1/stats/tunnel/" + url.PathEscape(domain)
	responseBody, err := c.makeRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response APITunnelStatsResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API request failed")
	}

	return response.TunnelStats, nil
}

// GetStatus retrieves server status from the API
func (c *Client) GetStatus() (*APIStatusResponse, error) {
	responseBody, err := c.makeRequest("GET", "/api/v1/status", nil)
	if err != nil {
		return nil, err
	}

	var response APIStatusResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API request failed")
	}

	return &response, nil
}

// GetSecurityStats gets security statistics
func (c *Client) GetSecurityStats() (map[string]interface{}, error) {
	responseBody, err := c.makeRequest("GET", "/api/v1/security/stats", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Success       bool                   `json:"success"`
		SecurityStats map[string]interface{} `json:"security_stats"`
	}

	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("API request failed")
	}

	return result.SecurityStats, nil
}

// GetSecurityBans gets banned IP information
func (c *Client) GetSecurityBans() ([]map[string]interface{}, error) {
	responseBody, err := c.makeRequest("GET", "/api/v1/security/bans", nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Success   bool                     `json:"success"`
		BannedIPs []map[string]interface{} `json:"banned_ips"`
	}

	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("API request failed")
	}

	return result.BannedIPs, nil
}

// Ping checks if the API is accessible
func (c *Client) Ping() error {
	_, err := c.GetStatus()
	return err
}

// GetHistory retrieves connection history from the API
func (c *Client) GetHistory(limit int) ([]*stats.ConnectionRecord, error) {
	path := fmt.Sprintf("/api/v1/history?limit=%d", limit)
	responseBody, err := c.makeRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Success bool                      `json:"success"`
		History []*stats.ConnectionRecord `json:"history"`
		Count   int                       `json:"count"`
		Limit   int                       `json:"limit"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API request failed")
	}

	return response.History, nil
}

// GetConnections retrieves active connections from the API
func (c *Client) GetConnections() ([]*stats.ConnectionRecord, error) {
	responseBody, err := c.makeRequest("GET", "/api/v1/connections", nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Success     bool                      `json:"success"`
		Connections []*stats.ConnectionRecord `json:"connections"`
		Count       int                       `json:"count"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API request failed")
	}

	return response.Connections, nil
}

// GetAccessMode retrieves the current access mode from the API
func (c *Client) GetAccessMode() (string, error) {
	responseBody, err := c.makeRequest("GET", "/api/v1/access", nil)
	if err != nil {
		return "", err
	}

	var response struct {
		Success    bool   `json:"success"`
		AccessMode string `json:"access_mode"`
		OpenAccess bool   `json:"open_access"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if !response.Success {
		return "", fmt.Errorf("API request failed")
	}

	return response.AccessMode, nil
}

// SetAccessMode changes the access mode via the API
func (c *Client) SetAccessMode(mode string) error {
	body := map[string]string{
		"mode": mode,
	}

	_, err := c.makeRequest("POST", "/api/v1/access", body)
	return err
}

// GetAbuseReports gets abuse reports from the API
func (c *Client) GetAbuseReports(status string, showAll bool) (interface{}, error) {
	url := c.baseURL + "/api/v1/abuse/reports"

	// Add query parameters
	params := make([]string, 0)
	if status != "" {
		params = append(params, "status="+status)
	}
	if showAll {
		params = append(params, "all=true")
	}
	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if errMsg, ok := result["message"].(string); ok {
			return nil, fmt.Errorf("API error: %s", errMsg)
		}
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	return result["reports"], nil
}

// ProcessAbuseReport processes an abuse report via API
func (c *Client) ProcessAbuseReport(reportID, action string) error {
	url := c.baseURL + "/api/v1/abuse/reports/" + reportID

	reqBody := map[string]string{
		"action": action,
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		if errMsg, ok := result["message"].(string); ok {
			return fmt.Errorf("API error: %s", errMsg)
		}
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	return nil
}

// GetAbuseStats gets abuse statistics from the API
func (c *Client) GetAbuseStats() (interface{}, error) {
	url := c.baseURL + "/api/v1/abuse/stats"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if errMsg, ok := result["message"].(string); ok {
			return nil, fmt.Errorf("API error: %s", errMsg)
		}
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	return result["stats"], nil
}

// UnbanIP unbans an IP address via the API
func (c *Client) UnbanIP(ip string) error {
	path := "/api/v1/security/unban"
	body := map[string]string{
		"ip": ip,
	}

	_, err := c.makeRequest("POST", path, body)
	return err
}
