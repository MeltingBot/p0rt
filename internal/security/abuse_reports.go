package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// AbuseReport represents a single abuse report
type AbuseReport struct {
	ID          string    `json:"id"`
	Domain      string    `json:"domain"`
	ReporterIP  string    `json:"reporter_ip"`
	Reason      string    `json:"reason"`
	Details     string    `json:"details"`
	ReportedAt  time.Time `json:"reported_at"`
	Status      string    `json:"status"` // "pending", "banned", "accepted"
	ProcessedBy string    `json:"processed_by,omitempty"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
}

// SSHServerInterface defines the interface for SSH server operations
type SSHServerInterface interface {
	UnbanIP(ip string)
	UnbanIPFromTracker(ip string)
	AddTemporaryWhitelist(ip string, duration time.Duration)
}

// globalIPUnbanService is a global service for IP unbanning
var globalIPUnbanService SSHServerInterface

// AbuseReportManager manages abuse reports with Redis storage
type AbuseReportManager struct {
	redisClient *redis.Client
	ctx         context.Context
	keyPrefix   string
	useRedis    bool
	sshServer   SSHServerInterface // Reference to SSH server for IP unbanning
}

// NewAbuseReportManager creates a new abuse report manager
func NewAbuseReportManager() *AbuseReportManager {
	manager := &AbuseReportManager{
		ctx:       context.Background(),
		keyPrefix: "p0rt:abuse:",
	}
	
	manager.initRedis()
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
	}
	
	if redisURL != "" {
		manager.initRedisWithURL(redisURL)
	} else {
		manager.initRedis()
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
	}
	
	log.Printf("Abuse report submitted: %s from %s (ID: %s)", domain, reporterIP, report.ID)
	return report, nil
}

// ListReports returns all abuse reports, optionally filtered by status
func (arm *AbuseReportManager) ListReports(status string) ([]*AbuseReport, error) {
	if !arm.useRedis {
		return []*AbuseReport{}, nil
	}
	
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

// ProcessReport processes a report (ban or accept)
func (arm *AbuseReportManager) ProcessReport(reportID, action, processedBy string) error {
	if !arm.useRedis {
		return fmt.Errorf("Redis not available")
	}
	
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
			log.Printf("Processing abuse report acceptance: unbanning IP %s", report.ReporterIP)
			unbanService.UnbanIP(report.ReporterIP)
			unbanService.UnbanIPFromTracker(report.ReporterIP)
			// Add to temporary whitelist for 10 minutes to prevent immediate re-banning
			unbanService.AddTemporaryWhitelist(report.ReporterIP, 10*time.Minute)
			log.Printf("✅ Completed unbanning IP %s from all systems and added to temporary whitelist", report.ReporterIP)
		} else {
			log.Printf("⚠️ No IP unban service available for IP %s", report.ReporterIP)
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

// GetReport retrieves a specific report by ID
func (arm *AbuseReportManager) GetReport(reportID string) (*AbuseReport, error) {
	if !arm.useRedis {
		return nil, fmt.Errorf("Redis not available")
	}
	
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
		"total_reports":   0,
		"pending_reports": 0,
		"banned_reports":  0,
		"accepted_reports": 0,
		"redis_available": arm.useRedis,
	}
	
	if !arm.useRedis {
		return stats
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
	if !arm.useRedis {
		return false
	}
	
	pattern := arm.keyPrefix + "report:*"
	keys, err := arm.redisClient.Keys(arm.ctx, pattern).Result()
	if err != nil {
		return false
	}
	
	for _, key := range keys {
		data, err := arm.redisClient.Get(arm.ctx, key).Result()
		if err != nil {
			continue
		}
		
		var report AbuseReport
		if err := json.Unmarshal([]byte(data), &report); err != nil {
			continue
		}
		
		// Check if this domain is banned (and not accepted)
		if report.Domain == domain && report.Status == "banned" {
			return true
		}
		
		// If domain was accepted, it's explicitly not banned
		if report.Domain == domain && report.Status == "accepted" {
			return false
		}
	}
	
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