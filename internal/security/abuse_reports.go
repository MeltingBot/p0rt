package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// AbuseReport represents a single abuse report
type AbuseReport struct {
	ID          string     `json:"id"`
	Domain      string     `json:"domain"`
	ReporterIP  string     `json:"reporter_ip"`
	Reason      string     `json:"reason"`
	Details     string     `json:"details"`
	ReportedAt  time.Time  `json:"reported_at"`
	Status      string     `json:"status"` // "pending", "banned", "accepted"
	ProcessedBy string     `json:"processed_by,omitempty"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
}

// SSHServerInterface defines the interface for SSH server operations
type SSHServerInterface interface {
	UnbanIP(ip string)
	UnbanIPFromTracker(ip string)
}

// globalIPUnbanService is a global service for IP unbanning
var globalIPUnbanService SSHServerInterface

// AbuseReportManager manages abuse reports with Redis or JSON storage
type AbuseReportManager struct {
	redisClient *redis.Client
	ctx         context.Context
	keyPrefix   string
	useRedis    bool
	sshServer   SSHServerInterface // Reference to SSH server for IP unbanning

	// JSON storage
	jsonFilePath string
	reports      map[string]*AbuseReport // ID -> Report
	mutex        sync.RWMutex
}

// NewAbuseReportManager creates a new abuse report manager
func NewAbuseReportManager() *AbuseReportManager {
	manager := &AbuseReportManager{
		ctx:       context.Background(),
		keyPrefix: "p0rt:abuse:",
		reports:   make(map[string]*AbuseReport),
	}

	manager.initRedis()
	if !manager.useRedis {
		manager.initJSON()
	}
	return manager
}

// SetSSHServer sets the SSH server reference for IP unbanning operations
func (arm *AbuseReportManager) SetSSHServer(server SSHServerInterface) {
	arm.sshServer = server
}

// SetGlobalIPUnbanService sets the global IP unban service
func SetGlobalIPUnbanService(service SSHServerInterface) {
	globalIPUnbanService = service
	log.Printf("Global IP unban service registered")
}

// GetGlobalIPUnbanService returns the global IP unban service
func GetGlobalIPUnbanService() SSHServerInterface {
	return globalIPUnbanService
}

// NewAbuseReportManagerWithRedis creates a new abuse report manager with provided Redis URL
func NewAbuseReportManagerWithRedis(redisURL string) *AbuseReportManager {
	manager := &AbuseReportManager{
		ctx:       context.Background(),
		keyPrefix: "p0rt:abuse:",
		reports:   make(map[string]*AbuseReport),
	}

	if redisURL != "" {
		manager.initRedisWithURL(redisURL)
	} else {
		manager.initRedis()
	}
	if !manager.useRedis {
		manager.initJSON()
	}
	return manager
}

// initRedis initializes Redis connection
func (arm *AbuseReportManager) initRedis() {
	redisURL := getAbuseRedisURL()
	if redisURL == "" {
		log.Println("AbuseReportManager: No Redis URL found, reports will only be logged")
		return
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Printf("AbuseReportManager: Invalid Redis URL: %v", err)
		return
	}

	arm.redisClient = redis.NewClient(opts)

	// Test connection
	if err := arm.redisClient.Ping(arm.ctx).Err(); err != nil {
		log.Printf("AbuseReportManager: Redis connection failed: %v", err)
		arm.redisClient.Close()
		arm.redisClient = nil
		return
	}

	arm.useRedis = true
	log.Println("AbuseReportManager: Using Redis storage for abuse reports")
}

// initJSON initializes JSON file storage
func (arm *AbuseReportManager) initJSON() {
	arm.jsonFilePath = filepath.Join("data", "abuse_reports.json")

	// Ensure data directory exists
	if err := os.MkdirAll(filepath.Dir(arm.jsonFilePath), 0755); err != nil {
		log.Printf("AbuseReportManager: Failed to create data directory: %v", err)
		return
	}

	// Load existing reports
	if err := arm.loadFromJSON(); err != nil {
		log.Printf("AbuseReportManager: Failed to load reports from JSON: %v", err)
	}

	log.Printf("AbuseReportManager: Using JSON storage for abuse reports (%s)", arm.jsonFilePath)
}

// loadFromJSON loads reports from JSON file
func (arm *AbuseReportManager) loadFromJSON() error {
	arm.mutex.Lock()
	defer arm.mutex.Unlock()

	data, err := os.ReadFile(arm.jsonFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, start with empty map
			return nil
		}
		return err
	}

	var reports map[string]*AbuseReport
	if err := json.Unmarshal(data, &reports); err != nil {
		return err
	}

	arm.reports = reports
	log.Printf("AbuseReportManager: Loaded %d abuse reports from JSON", len(arm.reports))
	return nil
}

// saveToJSON saves reports to JSON file
func (arm *AbuseReportManager) saveToJSON() error {
	arm.mutex.RLock()
	defer arm.mutex.RUnlock()

	data, err := json.MarshalIndent(arm.reports, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(arm.jsonFilePath, data, 0644)
}

// getAbuseRedisURL returns the Redis URL for abuse reports
func getAbuseRedisURL() string {
	// Use same Redis as other components
	if url := os.Getenv("REDIS_URL"); url != "" {
		return url
	}
	if url := os.Getenv("P0RT_REDIS_URL"); url != "" {
		return url
	}

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

	if password != "" {
		return fmt.Sprintf("redis://:%s@%s:%s/%s", password, host, port, db)
	}
	return fmt.Sprintf("redis://%s:%s/%s", host, port, db)
}

// initRedisWithURL initializes Redis connection with provided URL
func (arm *AbuseReportManager) initRedisWithURL(redisURL string) {
	if redisURL == "" {
		log.Println("AbuseReportManager: No Redis URL provided, reports will only be logged")
		return
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Printf("AbuseReportManager: Invalid Redis URL: %v", err)
		return
	}

	arm.redisClient = redis.NewClient(opts)

	// Test connection
	if err := arm.redisClient.Ping(arm.ctx).Err(); err != nil {
		log.Printf("AbuseReportManager: Redis connection failed: %v", err)
		arm.redisClient.Close()
		arm.redisClient = nil
		return
	}

	arm.useRedis = true
	log.Println("AbuseReportManager: Using Redis storage for abuse reports")
}

// SubmitReport submits a new abuse report
func (arm *AbuseReportManager) SubmitReport(domain, reporterIP, reason, details string) (*AbuseReport, error) {
	report := &AbuseReport{
		ID:         fmt.Sprintf("%s-%d", strings.ReplaceAll(domain, ".", "-"), time.Now().UnixNano()),
		Domain:     domain,
		ReporterIP: reporterIP,
		Reason:     reason,
		Details:    details,
		ReportedAt: time.Now(),
		Status:     "pending",
	}

	if arm.useRedis {
		if err := arm.saveReportToRedis(report); err != nil {
			return nil, fmt.Errorf("failed to save report to Redis: %w", err)
		}
	} else {
		arm.mutex.Lock()
		arm.reports[report.ID] = report
		arm.mutex.Unlock()

		if err := arm.saveToJSON(); err != nil {
			return nil, fmt.Errorf("failed to save report to JSON: %w", err)
		}
	}

	log.Printf("Abuse report submitted: %s from %s (ID: %s)", domain, reporterIP, report.ID)
	return report, nil
}

// ListReports returns all abuse reports, optionally filtered by status
func (arm *AbuseReportManager) ListReports(status string) ([]*AbuseReport, error) {
	if arm.useRedis {
		return arm.listReportsFromRedis(status)
	}

	return arm.listReportsFromJSON(status)
}

// listReportsFromRedis lists reports from Redis storage
func (arm *AbuseReportManager) listReportsFromRedis(status string) ([]*AbuseReport, error) {
	pattern := arm.keyPrefix + "report:*"
	keys, err := arm.redisClient.Keys(arm.ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get report keys: %w", err)
	}

	reports := make([]*AbuseReport, 0)
	for _, key := range keys {
		data, err := arm.redisClient.Get(arm.ctx, key).Result()
		if err != nil {
			continue
		}

		var report AbuseReport
		if err := json.Unmarshal([]byte(data), &report); err != nil {
			continue
		}

		// Filter by status if specified
		if status != "" && report.Status != status {
			continue
		}

		// Filter out automated SSH security events (they don't belong here)
		if strings.HasPrefix(report.Domain, "ssh-") || report.Domain == "ssh-blacklist" {
			continue
		}

		reports = append(reports, &report)
	}

	return reports, nil
}

// listReportsFromJSON lists reports from JSON storage
func (arm *AbuseReportManager) listReportsFromJSON(status string) ([]*AbuseReport, error) {
	arm.mutex.RLock()
	defer arm.mutex.RUnlock()

	reports := make([]*AbuseReport, 0)
	for _, report := range arm.reports {
		// Filter by status if specified
		if status != "" && report.Status != status {
			continue
		}

		// Filter out automated SSH security events
		if strings.HasPrefix(report.Domain, "ssh-") || report.Domain == "ssh-blacklist" {
			continue
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// ProcessReport processes a report (ban or accept)
func (arm *AbuseReportManager) ProcessReport(reportID, action, processedBy string) error {
	if arm.useRedis {
		return arm.processReportRedis(reportID, action, processedBy)
	}

	return arm.processReportJSON(reportID, action, processedBy)
}

// processReportRedis processes a report using Redis storage
func (arm *AbuseReportManager) processReportRedis(reportID, action, processedBy string) error {
	key := arm.keyPrefix + "report:" + reportID
	data, err := arm.redisClient.Get(arm.ctx, key).Result()
	if err != nil {
		return fmt.Errorf("report not found: %w", err)
	}

	var report AbuseReport
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		return fmt.Errorf("failed to unmarshal report: %w", err)
	}

	if action != "ban" && action != "accept" {
		return fmt.Errorf("invalid action: must be 'ban' or 'accept'")
	}

	// Update report status
	if action == "ban" {
		report.Status = "banned"
	} else {
		report.Status = "accepted"

		// If accepting, unban the reporter IP from SSH bans
		var unbanService SSHServerInterface
		if arm.sshServer != nil {
			unbanService = arm.sshServer
		} else {
			unbanService = GetGlobalIPUnbanService()
		}

		if unbanService != nil {
			log.Printf("🔓 Processing abuse report acceptance: unbanning IP %s", report.ReporterIP)
			unbanService.UnbanIP(report.ReporterIP)
			unbanService.UnbanIPFromTracker(report.ReporterIP)
			log.Printf("✅ Completed unbanning IP %s from all ban systems", report.ReporterIP)
		} else {
			log.Printf("⚠️ No IP unban service available for IP %s (local: %v, global: %v)",
				report.ReporterIP, arm.sshServer != nil, globalIPUnbanService != nil)
		}

		// Also clean up Redis keys (best effort)
		if err := arm.unbanReporterIP(report.ReporterIP); err != nil {
			log.Printf("Warning: failed to clean up Redis ban keys for IP %s: %v", report.ReporterIP, err)
		}
	}

	now := time.Now()
	report.ProcessedAt = &now
	report.ProcessedBy = processedBy

	// Save updated report
	if err := arm.saveReportToRedis(&report); err != nil {
		return fmt.Errorf("failed to update report: %w", err)
	}

	log.Printf("Abuse report %s processed: %s by %s", reportID, action, processedBy)
	return nil
}

// processReportJSON processes a report using JSON storage
func (arm *AbuseReportManager) processReportJSON(reportID, action, processedBy string) error {
	arm.mutex.Lock()
	defer arm.mutex.Unlock()

	report, exists := arm.reports[reportID]
	if !exists {
		return fmt.Errorf("report not found: %s", reportID)
	}

	if action != "ban" && action != "accept" {
		return fmt.Errorf("invalid action: must be 'ban' or 'accept'")
	}

	// Update report status
	if action == "ban" {
		report.Status = "banned"
	} else {
		report.Status = "accepted"

		// If accepting, unban the reporter IP from SSH bans
		var unbanService SSHServerInterface
		if arm.sshServer != nil {
			unbanService = arm.sshServer
		} else {
			unbanService = GetGlobalIPUnbanService()
		}

		if unbanService != nil {
			log.Printf("🔓 Processing abuse report acceptance: unbanning IP %s", report.ReporterIP)
			unbanService.UnbanIP(report.ReporterIP)
			unbanService.UnbanIPFromTracker(report.ReporterIP)
			log.Printf("✅ Completed unbanning IP %s from all ban systems", report.ReporterIP)
		} else {
			log.Printf("⚠️ No IP unban service available for IP %s (local: %v, global: %v)",
				report.ReporterIP, arm.sshServer != nil, globalIPUnbanService != nil)
		}
	}

	now := time.Now()
	report.ProcessedAt = &now
	report.ProcessedBy = processedBy

	// Save updated report
	if err := arm.saveToJSON(); err != nil {
		return fmt.Errorf("failed to update report: %w", err)
	}

	log.Printf("Abuse report %s processed: %s by %s", reportID, action, processedBy)
	return nil
}

// GetReport retrieves a specific report by ID
func (arm *AbuseReportManager) GetReport(reportID string) (*AbuseReport, error) {
	if arm.useRedis {
		return arm.getReportFromRedis(reportID)
	}

	return arm.getReportFromJSON(reportID)
}

// getReportFromRedis retrieves a report from Redis storage
func (arm *AbuseReportManager) getReportFromRedis(reportID string) (*AbuseReport, error) {
	key := arm.keyPrefix + "report:" + reportID
	data, err := arm.redisClient.Get(arm.ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("report not found: %w", err)
	}

	var report AbuseReport
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal report: %w", err)
	}

	return &report, nil
}

// getReportFromJSON retrieves a report from JSON storage
func (arm *AbuseReportManager) getReportFromJSON(reportID string) (*AbuseReport, error) {
	arm.mutex.RLock()
	defer arm.mutex.RUnlock()

	report, exists := arm.reports[reportID]
	if !exists {
		return nil, fmt.Errorf("report not found: %s", reportID)
	}

	return report, nil
}

// saveReportToRedis saves a report to Redis
func (arm *AbuseReportManager) saveReportToRedis(report *AbuseReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}

	key := arm.keyPrefix + "report:" + report.ID
	// Keep reports for 30 days
	return arm.redisClient.Set(arm.ctx, key, data, 30*24*time.Hour).Err()
}

// GetStats returns abuse report statistics
func (arm *AbuseReportManager) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_reports":    0,
		"pending_reports":  0,
		"banned_reports":   0,
		"accepted_reports": 0,
		"redis_available":  arm.useRedis,
		"json_available":   arm.jsonFilePath != "",
	}

	reports, err := arm.ListReports("")
	if err != nil {
		return stats
	}

	stats["total_reports"] = len(reports)

	for _, report := range reports {
		switch report.Status {
		case "pending":
			stats["pending_reports"] = stats["pending_reports"].(int) + 1
		case "banned":
			stats["banned_reports"] = stats["banned_reports"].(int) + 1
		case "accepted":
			stats["accepted_reports"] = stats["accepted_reports"].(int) + 1
		}
	}

	return stats
}

// IsDomainBanned checks if a domain has been banned via abuse report
func (arm *AbuseReportManager) IsDomainBanned(domain string) bool {
	log.Printf("🔍 Checking if domain '%s' is banned...", domain)

	if arm.useRedis {
		return arm.isDomainBannedRedis(domain)
	}

	return arm.isDomainBannedJSON(domain)
}

// isDomainBannedRedis checks domain ban status using Redis
func (arm *AbuseReportManager) isDomainBannedRedis(domain string) bool {
	pattern := arm.keyPrefix + "report:*"
	keys, err := arm.redisClient.Keys(arm.ctx, pattern).Result()
	if err != nil {
		log.Printf("🔍 Error getting abuse report keys: %v", err)
		return false
	}

	log.Printf("🔍 Found %d abuse reports to check", len(keys))

	for _, key := range keys {
		data, err := arm.redisClient.Get(arm.ctx, key).Result()
		if err != nil {
			continue
		}

		var report AbuseReport
		if err := json.Unmarshal([]byte(data), &report); err != nil {
			continue
		}

		log.Printf("🔍 Checking report: domain='%s', status='%s', target='%s'", report.Domain, report.Status, domain)

		// Check if this domain is banned (and not accepted)
		if report.Domain == domain && report.Status == "banned" {
			log.Printf("🚫 Domain '%s' is BANNED (found banned report)", domain)
			return true
		}

		// If domain was accepted, it's explicitly not banned
		if report.Domain == domain && report.Status == "accepted" {
			log.Printf("✅ Domain '%s' is NOT banned (found accepted report)", domain)
			return false
		}
	}

	log.Printf("🔍 Domain '%s' not found in any abuse reports - NOT banned", domain)
	return false
}

// isDomainBannedJSON checks domain ban status using JSON storage
func (arm *AbuseReportManager) isDomainBannedJSON(domain string) bool {
	arm.mutex.RLock()
	defer arm.mutex.RUnlock()

	log.Printf("🔍 Checking %d abuse reports from JSON storage", len(arm.reports))

	for _, report := range arm.reports {
		log.Printf("🔍 Checking report: domain='%s', status='%s', target='%s'", report.Domain, report.Status, domain)

		// Check if this domain is banned (and not accepted)
		if report.Domain == domain && report.Status == "banned" {
			log.Printf("🚫 Domain '%s' is BANNED (found banned report)", domain)
			return true
		}

		// If domain was accepted, it's explicitly not banned
		if report.Domain == domain && report.Status == "accepted" {
			log.Printf("✅ Domain '%s' is NOT banned (found accepted report)", domain)
			return false
		}
	}

	log.Printf("🔍 Domain '%s' not found in any abuse reports - NOT banned", domain)
	return false
}

// unbanReporterIP removes an IP from SSH banned IPs list when abuse report is accepted
func (arm *AbuseReportManager) unbanReporterIP(ip string) error {
	if !arm.useRedis {
		return fmt.Errorf("Redis not available")
	}

	// Remove from SSH banned IPs (assuming they're stored in Redis with key pattern)
	// This is a best-effort cleanup - the SSH server maintains its own ban list
	sshBanKey := "p0rt:ssh:banned_ips:" + ip
	err := arm.redisClient.Del(arm.ctx, sshBanKey).Err()
	if err != nil {
		return fmt.Errorf("failed to remove IP ban: %w", err)
	}

	// Also try alternative key patterns that might be used
	altKeys := []string{
		"ssh:banned:" + ip,
		"p0rt:banned:" + ip,
		"banned_ips:" + ip,
	}

	for _, key := range altKeys {
		arm.redisClient.Del(arm.ctx, key)
	}

	return nil
}
