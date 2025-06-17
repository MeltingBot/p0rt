package security

import (
	"strings"
	"testing"
)

func TestCheckDomain(t *testing.T) {
	monitor := NewAbuseMonitor()

	tests := []struct {
		domain   string
		expected bool
		reason   string
	}{
		{"whale-guitar-fox", true, ""},
		{"phishing-test-site", false, "phishing"},
		{"virus-download-site", false, "virus"},
		{"legitimate-domain", true, ""},
		{"malware-central", false, "malware"},
		{"spam-generator", false, "spam"},
		{"normal-app-demo", true, ""},
	}

	for _, test := range tests {
		allowed, reason := monitor.CheckDomain(test.domain)
		if allowed != test.expected {
			t.Errorf("Domain %s: expected %v, got %v", test.domain, test.expected, allowed)
		}
		if !test.expected && !strings.Contains(reason, test.reason) {
			t.Errorf("Domain %s: expected reason to contain '%s', got '%s'", test.domain, test.reason, reason)
		}
	}
}

func TestAnalyzeHTTPRequest(t *testing.T) {
	monitor := NewAbuseMonitor()

	tests := []struct {
		domain    string
		path      string
		userAgent string
		referer   string
		expected  bool
	}{
		{"test", "/api/users", "Mozilla/5.0", "", true},
		{"test", "/login", "Mozilla/5.0", "", false}, // phishing pattern
		{"test", "/", "Mozilla/5.0", "", true},
		{"test", "/verify-account", "Bot", "", false}, // phishing pattern
		{"test", "/casino-winner", "Mozilla/5.0", "", false}, // spam pattern
		{"test", "/dashboard", "Normal browser", "", true},
	}

	for _, test := range tests {
		allowed, _ := monitor.AnalyzeHTTPRequest(test.domain, test.path, test.userAgent, test.referer)
		if allowed != test.expected {
			t.Errorf("Request %s%s: expected %v, got %v", test.domain, test.path, test.expected, allowed)
		}
	}
}

func TestConnectionRateLimit(t *testing.T) {
	monitor := NewAbuseMonitor()
	keyHash := "test-key-hash"

	// Test normal connections
	for i := 0; i < 50; i++ {
		if !monitor.CheckConnectionRate(keyHash) {
			t.Errorf("Connection %d should be allowed", i+1)
		}
	}

	// Test rate limit
	for i := 50; i < 150; i++ {
		monitor.CheckConnectionRate(keyHash)
	}

	// Should be blocked now
	if monitor.CheckConnectionRate(keyHash) {
		t.Error("Connection should be blocked after exceeding rate limit")
	}
}