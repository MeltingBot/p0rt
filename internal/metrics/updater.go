package metrics

import (
	"time"
)

// MetricsUpdater handles periodic updates of gauge metrics
type MetricsUpdater struct {
	sshServer     SSHServerInterface
	abuseMonitor  AbuseMonitorInterface
	stopChan      chan struct{}
	updateTicker  *time.Ticker
}

// SSHServerInterface defines methods needed for SSH metrics
type SSHServerInterface interface {
	GetActiveConnectionCount() int
	GetActiveTunnelCount() int
}

// AbuseMonitorInterface defines methods needed for abuse metrics
type AbuseMonitorInterface interface {
	GetBannedIPCount() int
	GetBannedDomainCount() int
}

// NewMetricsUpdater creates a new metrics updater
func NewMetricsUpdater(sshServer SSHServerInterface, abuseMonitor AbuseMonitorInterface) *MetricsUpdater {
	return &MetricsUpdater{
		sshServer:    sshServer,
		abuseMonitor: abuseMonitor,
		stopChan:     make(chan struct{}),
		updateTicker: time.NewTicker(30 * time.Second), // Update every 30 seconds
	}
}

// Start begins the periodic metrics update
func (mu *MetricsUpdater) Start() {
	go func() {
		for {
			select {
			case <-mu.updateTicker.C:
				mu.updateMetrics()
			case <-mu.stopChan:
				mu.updateTicker.Stop()
				return
			}
		}
	}()
}

// Stop stops the metrics updater
func (mu *MetricsUpdater) Stop() {
	close(mu.stopChan)
}

// updateMetrics updates all gauge metrics with current values
func (mu *MetricsUpdater) updateMetrics() {
	// Update SSH connection metrics
	if mu.sshServer != nil {
		activeConnections := mu.sshServer.GetActiveConnectionCount()
		activeTunnels := mu.sshServer.GetActiveTunnelCount()
		UpdateActiveConnections(activeConnections, activeTunnels, 0) // WebSocket count handled separately
	}
	
	// Update security metrics
	if mu.abuseMonitor != nil {
		bannedIPs := mu.abuseMonitor.GetBannedIPCount()
		bannedDomains := mu.abuseMonitor.GetBannedDomainCount()
		UpdateBannedCounts(bannedIPs, bannedDomains)
	}
}

// UpdateMetricsNow forces an immediate metrics update
func (mu *MetricsUpdater) UpdateMetricsNow() {
	mu.updateMetrics()
}