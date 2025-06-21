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

// AbuseReportManager manages abuse reports with Redis storage
type AbuseReportManager struct {
	redisClient *redis.Client
	ctx         context.Context
	keyPrefix   string
	useRedis    bool
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