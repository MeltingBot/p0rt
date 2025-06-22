package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// SSH Connection Metrics
	SSHConnectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_ssh_connections_total",
			Help: "Total number of SSH connections",
		},
		[]string{"status"}, // success, failed, banned
	)

	SSHConnectionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "p0rt_ssh_connections_active",
			Help: "Number of active SSH connections",
		},
	)

	SSHTunnelsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "p0rt_ssh_tunnels_active",
			Help: "Number of active SSH tunnels",
		},
	)

	SSHAuthFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_ssh_auth_failures_total",
			Help: "Total number of SSH authentication failures",
		},
		[]string{"ip", "reason"}, // brute_force, invalid_key, banned_ip
	)

	// HTTP Traffic Metrics
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "status_code", "domain_type"}, // tunnel, homepage, health
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "p0rt_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"method", "domain_type"},
	)

	HTTPBytesTransferred = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_http_bytes_total",
			Help: "Total bytes transferred via HTTP",
		},
		[]string{"direction", "domain"}, // in, out
	)

	WebSocketConnectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_websocket_connections_total",
			Help: "Total number of WebSocket connections",
		},
		[]string{"status"}, // success, failed, upgrade_failed
	)

	WebSocketConnectionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "p0rt_websocket_connections_active",
			Help: "Number of active WebSocket connections",
		},
	)

	// Security and Abuse Metrics
	SecurityEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_security_events_total",
			Help: "Total number of security events",
		},
		[]string{"type", "severity"}, // abuse_report, domain_ban, ip_ban, phishing_detected
	)

	BannedIPsTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "p0rt_banned_ips_total",
			Help: "Number of currently banned IP addresses",
		},
	)

	BannedDomainsTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "p0rt_banned_domains_total",
			Help: "Number of currently banned domains",
		},
	)

	AbuseReportsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_abuse_reports_total",
			Help: "Total number of abuse reports",
		},
		[]string{"type", "status"}, // phishing/spam/scam, pending/accepted/rejected
	)

	RateLimitHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_rate_limit_hits_total",
			Help: "Total number of rate limit hits",
		},
		[]string{"type", "ip"}, // ssh_connection, http_request, tunnel_creation
	)

	// Domain Metrics
	DomainsGeneratedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "p0rt_domains_generated_total",
			Help: "Total number of domains generated",
		},
	)

	DomainsReservedTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "p0rt_domains_reserved_total",
			Help: "Number of currently reserved domains",
		},
	)

	DomainUsageTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_domain_usage_total",
			Help: "Total domain usage statistics",
		},
		[]string{"domain", "type"}, // requests, bytes_transferred
	)

	// System Metrics
	SystemInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "p0rt_system_info",
			Help: "System information",
		},
		[]string{"version", "build_time", "git_commit"},
	)

	UptimeSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "p0rt_uptime_seconds",
			Help: "Service uptime in seconds",
		},
	)

	// Redis Metrics (if enabled)
	RedisConnectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_redis_connections_total",
			Help: "Total Redis connections",
		},
		[]string{"status"}, // success, failed
	)

	RedisOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p0rt_redis_operations_total",
			Help: "Total Redis operations",
		},
		[]string{"operation", "status"}, // get/set/del, success/failed
	)
)

// Helper functions for common metrics operations

func RecordSSHConnection(status string) {
	SSHConnectionsTotal.WithLabelValues(status).Inc()
}

func RecordHTTPRequest(method, statusCode, domainType string, duration float64) {
	HTTPRequestsTotal.WithLabelValues(method, statusCode, domainType).Inc()
	HTTPRequestDuration.WithLabelValues(method, domainType).Observe(duration)
}

func RecordBytesTransferred(direction, domain string, bytes int64) {
	HTTPBytesTransferred.WithLabelValues(direction, domain).Add(float64(bytes))
}

func RecordSecurityEvent(eventType, severity string) {
	SecurityEventsTotal.WithLabelValues(eventType, severity).Inc()
}

func RecordAbuseReport(reportType, status string) {
	AbuseReportsTotal.WithLabelValues(reportType, status).Inc()
}

func RecordRateLimitHit(limitType, ip string) {
	RateLimitHitsTotal.WithLabelValues(limitType, ip).Inc()
}

func SetSystemInfo(version, buildTime, gitCommit string) {
	SystemInfo.WithLabelValues(version, buildTime, gitCommit).Set(1)
}

func UpdateActiveConnections(ssh, tunnels, websockets int) {
	SSHConnectionsActive.Set(float64(ssh))
	SSHTunnelsActive.Set(float64(tunnels))
	WebSocketConnectionsActive.Set(float64(websockets))
}

func UpdateBannedCounts(ips, domains int) {
	BannedIPsTotal.Set(float64(ips))
	BannedDomainsTotal.Set(float64(domains))
}

func SetUptime(seconds float64) {
	UptimeSeconds.Set(seconds)
}