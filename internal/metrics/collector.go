package metrics

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// MetricData represents a simplified metric for the admin dashboard
type MetricData struct {
	Name   string                 `json:"name"`
	Type   string                 `json:"type"`
	Help   string                 `json:"help"`
	Value  float64                `json:"value,omitempty"`
	Values map[string]float64     `json:"values,omitempty"`
	Labels map[string]interface{} `json:"labels,omitempty"`
}

// DashboardMetrics represents metrics formatted for the admin dashboard
type DashboardMetrics struct {
	Timestamp   time.Time               `json:"timestamp"`
	Connections ConnectionMetrics       `json:"connections"`
	Traffic     TrafficMetrics          `json:"traffic"`
	Security    SecurityMetrics         `json:"security"`
	Domains     DomainMetrics           `json:"domains"`
	System      SystemMetrics           `json:"system"`
}

// ConnectionMetrics holds SSH connection related metrics
type ConnectionMetrics struct {
	ActiveSSH       int64              `json:"active_ssh"`
	ActiveTunnels   int64              `json:"active_tunnels"`
	TotalSuccess    int64              `json:"total_success"`
	TotalFailed     int64              `json:"total_failed"`
	AuthFailures    map[string]int64   `json:"auth_failures"`
	TopConnections  []DomainConnection `json:"top_connections"`
}

// TrafficMetrics holds HTTP traffic related metrics
type TrafficMetrics struct {
	RequestsTotal    int64                `json:"requests_total"`
	RequestsRate     float64              `json:"requests_rate"`
	BytesIn          int64                `json:"bytes_in"`
	BytesOut         int64                `json:"bytes_out"`
	AverageLatency   float64              `json:"avg_latency_ms"`
	P95Latency       float64              `json:"p95_latency_ms"`
	P99Latency       float64              `json:"p99_latency_ms"`
	StatusCodes      map[string]int64     `json:"status_codes"`
	TopDomains       []DomainTraffic      `json:"top_domains"`
	WebsocketActive  int64                `json:"websocket_active"`
}

// SecurityMetrics holds security related metrics
type SecurityMetrics struct {
	BannedIPs       int64             `json:"banned_ips"`
	BannedDomains   int64             `json:"banned_domains"`
	SecurityEvents  map[string]int64  `json:"security_events"`
	AbuseReports    map[string]int64  `json:"abuse_reports"`
	RateLimitHits   int64             `json:"rate_limit_hits"`
}

// DomainMetrics holds domain related metrics
type DomainMetrics struct {
	TotalGenerated  int64  `json:"total_generated"`
	TotalReserved   int64  `json:"total_reserved"`
	GenerationRate  float64 `json:"generation_rate"`
}

// SystemMetrics holds system related metrics
type SystemMetrics struct {
	UptimeSeconds   float64  `json:"uptime_seconds"`
	Version         string   `json:"version"`
	RedisConnected  bool     `json:"redis_connected"`
	RedisOps        int64    `json:"redis_operations"`
}

// DomainConnection represents a domain with connection count
type DomainConnection struct {
	Domain      string `json:"domain"`
	Connections int64  `json:"connections"`
}

// DomainTraffic represents a domain with traffic statistics
type DomainTraffic struct {
	Domain   string  `json:"domain"`
	Requests int64   `json:"requests"`
	BytesIn  int64   `json:"bytes_in"`
	BytesOut int64   `json:"bytes_out"`
}

// CollectDashboardMetrics collects and formats metrics for the admin dashboard
func CollectDashboardMetrics(ctx context.Context) (*DashboardMetrics, error) {
	// Create a custom registry to gather specific metrics
	registry := prometheus.NewRegistry()
	
	// Register all our custom metrics
	collectors := []prometheus.Collector{
		SSHConnectionsTotal,
		SSHConnectionsActive,
		SSHTunnelsActive,
		SSHAuthFailures,
		HTTPRequestsTotal,
		HTTPRequestDuration,
		HTTPBytesTransferred,
		WebSocketConnectionsTotal,
		WebSocketConnectionsActive,
		SecurityEventsTotal,
		BannedIPsTotal,
		BannedDomainsTotal,
		AbuseReportsTotal,
		RateLimitHitsTotal,
		DomainsGeneratedTotal,
		DomainsReservedTotal,
		SystemInfo,
		UptimeSeconds,
	}

	for _, collector := range collectors {
		if err := registry.Register(collector); err != nil {
			// Ignore already registered errors
			if !strings.Contains(err.Error(), "already registered") {
				return nil, fmt.Errorf("failed to register collector: %w", err)
			}
		}
	}

	// Gather all metrics
	metricFamilies, err := registry.Gather()
	if err != nil {
		return nil, fmt.Errorf("failed to gather metrics: %w", err)
	}

	// Parse metrics into dashboard format
	dashboard := &DashboardMetrics{
		Timestamp: time.Now(),
		Connections: ConnectionMetrics{
			AuthFailures: make(map[string]int64),
		},
		Traffic: TrafficMetrics{
			StatusCodes: make(map[string]int64),
		},
		Security: SecurityMetrics{
			SecurityEvents: make(map[string]int64),
			AbuseReports:   make(map[string]int64),
		},
	}

	// Process each metric family
	for _, mf := range metricFamilies {
		switch mf.GetName() {
		case "p0rt_ssh_connections_active":
			dashboard.Connections.ActiveSSH = int64(getGaugeValue(mf))
		case "p0rt_ssh_tunnels_active":
			dashboard.Connections.ActiveTunnels = int64(getGaugeValue(mf))
		case "p0rt_ssh_connections_total":
			parseConnectionsTotal(mf, &dashboard.Connections)
		case "p0rt_ssh_auth_failures_total":
			parseAuthFailures(mf, &dashboard.Connections)
		case "p0rt_http_requests_total":
			parseHTTPRequests(mf, &dashboard.Traffic)
		case "p0rt_http_request_duration_seconds":
			parseHTTPLatency(mf, &dashboard.Traffic)
		case "p0rt_http_bytes_total":
			parseHTTPBytes(mf, &dashboard.Traffic)
		case "p0rt_websocket_connections_active":
			dashboard.Traffic.WebsocketActive = int64(getGaugeValue(mf))
		case "p0rt_banned_ips_total":
			dashboard.Security.BannedIPs = int64(getGaugeValue(mf))
		case "p0rt_banned_domains_total":
			dashboard.Security.BannedDomains = int64(getGaugeValue(mf))
		case "p0rt_security_events_total":
			parseSecurityEvents(mf, &dashboard.Security)
		case "p0rt_abuse_reports_total":
			parseAbuseReports(mf, &dashboard.Security)
		case "p0rt_rate_limit_hits_total":
			dashboard.Security.RateLimitHits = int64(getCounterValue(mf))
		case "p0rt_domains_generated_total":
			dashboard.Domains.TotalGenerated = int64(getCounterValue(mf))
		case "p0rt_domains_reserved_total":
			dashboard.Domains.TotalReserved = int64(getGaugeValue(mf))
		case "p0rt_uptime_seconds":
			dashboard.System.UptimeSeconds = getGaugeValue(mf)
		case "p0rt_system_info":
			parseSystemInfo(mf, &dashboard.System)
		}
	}

	// Calculate derived metrics
	calculateRates(dashboard)

	return dashboard, nil
}

// Helper functions to extract values from Prometheus metrics

func getGaugeValue(mf *dto.MetricFamily) float64 {
	if len(mf.Metric) > 0 && mf.Metric[0].Gauge != nil {
		return mf.Metric[0].Gauge.GetValue()
	}
	return 0
}

func getCounterValue(mf *dto.MetricFamily) float64 {
	total := 0.0
	for _, m := range mf.Metric {
		if m.Counter != nil {
			total += m.Counter.GetValue()
		}
	}
	return total
}

func parseConnectionsTotal(mf *dto.MetricFamily, conn *ConnectionMetrics) {
	for _, m := range mf.Metric {
		for _, label := range m.Label {
			if label.GetName() == "status" {
				value := int64(m.Counter.GetValue())
				switch label.GetValue() {
				case "success":
					conn.TotalSuccess = value
				case "failed":
					conn.TotalFailed = value
				}
			}
		}
	}
}

func parseAuthFailures(mf *dto.MetricFamily, conn *ConnectionMetrics) {
	reasons := make(map[string]int64)
	for _, m := range mf.Metric {
		reason := ""
		for _, label := range m.Label {
			if label.GetName() == "reason" {
				reason = label.GetValue()
				break
			}
		}
		if reason != "" {
			reasons[reason] += int64(m.Counter.GetValue())
		}
	}
	conn.AuthFailures = reasons
}

func parseHTTPRequests(mf *dto.MetricFamily, traffic *TrafficMetrics) {
	statusCodes := make(map[string]int64)
	total := int64(0)
	
	for _, m := range mf.Metric {
		count := int64(m.Counter.GetValue())
		total += count
		
		for _, label := range m.Label {
			if label.GetName() == "status_code" {
				code := label.GetValue()
				statusCodes[code] += count
			}
		}
	}
	
	traffic.RequestsTotal = total
	traffic.StatusCodes = statusCodes
}

func parseHTTPLatency(mf *dto.MetricFamily, traffic *TrafficMetrics) {
	if len(mf.Metric) == 0 || mf.Metric[0].Histogram == nil {
		return
	}
	
	hist := mf.Metric[0].Histogram
	if hist.SampleSum != nil && hist.SampleCount != nil && *hist.SampleCount > 0 {
		// Convert seconds to milliseconds
		traffic.AverageLatency = (*hist.SampleSum / float64(*hist.SampleCount)) * 1000
	}
	
	// Extract percentiles from buckets if available
	// This is a simplified version - real percentile calculation would be more complex
	for _, bucket := range hist.Bucket {
		if bucket.UpperBound != nil {
			bound := *bucket.UpperBound * 1000 // Convert to ms
			if bound >= 100 && bound <= 200 {
				traffic.P95Latency = bound
			} else if bound >= 200 && bound <= 500 {
				traffic.P99Latency = bound
			}
		}
	}
}

func parseHTTPBytes(mf *dto.MetricFamily, traffic *TrafficMetrics) {
	for _, m := range mf.Metric {
		direction := ""
		for _, label := range m.Label {
			if label.GetName() == "direction" {
				direction = label.GetValue()
				break
			}
		}
		
		value := int64(m.Counter.GetValue())
		switch direction {
		case "in":
			traffic.BytesIn = value
		case "out":
			traffic.BytesOut = value
		}
	}
}

func parseSecurityEvents(mf *dto.MetricFamily, security *SecurityMetrics) {
	events := make(map[string]int64)
	for _, m := range mf.Metric {
		eventType := ""
		for _, label := range m.Label {
			if label.GetName() == "type" {
				eventType = label.GetValue()
				break
			}
		}
		if eventType != "" {
			events[eventType] += int64(m.Counter.GetValue())
		}
	}
	security.SecurityEvents = events
}

func parseAbuseReports(mf *dto.MetricFamily, security *SecurityMetrics) {
	reports := make(map[string]int64)
	for _, m := range mf.Metric {
		status := ""
		for _, label := range m.Label {
			if label.GetName() == "status" {
				status = label.GetValue()
				break
			}
		}
		if status != "" {
			reports[status] += int64(m.Counter.GetValue())
		}
	}
	security.AbuseReports = reports
}

func parseSystemInfo(mf *dto.MetricFamily, system *SystemMetrics) {
	if len(mf.Metric) > 0 {
		for _, label := range mf.Metric[0].Label {
			if label.GetName() == "version" {
				system.Version = label.GetValue()
				break
			}
		}
	}
}

func calculateRates(dashboard *DashboardMetrics) {
	// Calculate request rate (requests per second over last minute)
	if dashboard.System.UptimeSeconds > 60 {
		dashboard.Traffic.RequestsRate = float64(dashboard.Traffic.RequestsTotal) / dashboard.System.UptimeSeconds
	}
	
	// Calculate domain generation rate
	if dashboard.System.UptimeSeconds > 0 {
		dashboard.Domains.GenerationRate = float64(dashboard.Domains.TotalGenerated) / dashboard.System.UptimeSeconds
	}
}