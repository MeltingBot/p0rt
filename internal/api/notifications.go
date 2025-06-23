package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// NotificationRequest represents a notification request
type NotificationRequest struct {
	Message string `json:"message,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// NotificationResponseLocal represents a notification response (internal)
type NotificationResponseLocal struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Sent      bool   `json:"sent"`
	Recipient string `json:"recipient,omitempty"`
	Timestamp string `json:"timestamp"`
}

// handleNotificationTest handles POST /api/v1/notifications/test
func (h *Handler) handleNotificationTest(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req NotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body for basic test
		req.Message = "Test notification from P0rt API"
	}

	// Generate test notification
	testMessage := h.generateTestNotification(req.Message)
	
	// In a real implementation, this would send the notification
	// For now, we simulate the notification system
	response := NotificationResponseLocal{
		Success:   true,
		Message:   "Test notification generated successfully",
		Sent:      true,
		Recipient: "system",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":      response.Success,
		"notification": response,
		"preview":      testMessage,
		"format":       "SSH Banner Message",
	})
}

// handleNotificationBanDomain handles POST /api/v1/notifications/ban-domain
func (h *Handler) handleNotificationBanDomain(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req NotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	// Validate domain format
	if !h.isValidDomain(req.Domain) {
		writeError(w, http.StatusBadRequest, "Invalid domain format")
		return
	}

	// Generate ban notification message
	banMessage := h.generateBanNotification(req.Domain, req.Reason)
	
	// Send real notification to SSH clients if SSH notifier is available
	notificationSent := false
	var notificationError string
	
	if h.sshNotifier != nil {
		// Extract subdomain from full domain (remove base domain)
		subdomain := req.Domain
		if strings.Contains(req.Domain, ".") {
			parts := strings.Split(req.Domain, ".")
			if len(parts) > 0 {
				subdomain = parts[0]
			}
		}
		// Determine notification type and send appropriate notification
		lowerReason := strings.ToLower(req.Reason)
		isBanNotification := strings.Contains(lowerReason, "ban") || 
							 strings.Contains(lowerReason, "abuse") || 
							 strings.Contains(lowerReason, "spam") ||
							 strings.Contains(lowerReason, "violation")
		
		if isBanNotification {
			h.sshNotifier.NotifyDomainBanned(subdomain)
		} else {
			message := req.Reason
			if message == "" {
				message = "General notification for your tunnel"
			}
			h.sshNotifier.NotifyDomain(subdomain, message)
		}
		notificationSent = true
	} else {
		notificationError = "SSH notification provider not available"
	}
	
	response := NotificationResponseLocal{
		Success:   notificationSent,
		Message:   fmt.Sprintf("Ban notification sent for domain: %s", req.Domain),
		Sent:      notificationSent,
		Recipient: req.Domain,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	
	if notificationError != "" {
		response.Message = fmt.Sprintf("Failed to send notification: %s", notificationError)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":      response.Success,
		"notification": response,
		"ban_message":  banMessage,
		"domain":       req.Domain,
		"reason":       req.Reason,
	})
}

// Helper methods for notifications

func (h *Handler) generateTestNotification(customMessage string) string {
	if customMessage != "" {
		return h.formatNotificationMessage("TEST", customMessage)
	}
	
	return h.formatNotificationMessage("TEST", 
		"This is a test notification from P0rt server.\n"+
		"Your SSH tunnel connection is working correctly.\n"+
		"Server time: "+time.Now().Format("2006-01-02 15:04:05 UTC"))
}

func (h *Handler) generateBanNotification(domain, reason string) string {
	message := fmt.Sprintf("NOTICE: Domain %s has been flagged for review.\n", domain)
	
	if reason != "" {
		message += fmt.Sprintf("Reason: %s\n", reason)
	} else {
		message += "Reason: Policy violation or abuse report\n"
	}
	
	message += "\nThis tunnel will be disconnected shortly.\n"
	message += "If you believe this is an error, please contact support.\n"
	message += fmt.Sprintf("Notification time: %s", time.Now().Format("2006-01-02 15:04:05 UTC"))
	
	return h.formatNotificationMessage("BAN", message)
}

func (h *Handler) formatNotificationMessage(messageType, content string) string {
	border := strings.Repeat("=", 60)
	
	return fmt.Sprintf("\n%s\n[P0RT %s NOTIFICATION]\n%s\n\n%s\n\n%s\n",
		border, messageType, border, content, border)
}

func (h *Handler) isValidDomain(domain string) bool {
	// Basic domain validation - accept both subdomains and full domains
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	// Check for valid characters and structure
	parts := strings.Split(domain, ".")
	// Accept both single subdomain (quick-tennis-tapir) and full domain (quick-tennis-tapir.p0rt.xyz)
	if len(parts) < 1 {
		return false
	}
	
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		
		// Check for valid characters (letters, numbers, hyphens)
		for _, char := range part {
			if !((char >= 'a' && char <= 'z') || 
				 (char >= 'A' && char <= 'Z') || 
				 (char >= '0' && char <= '9') || 
				 char == '-') {
				return false
			}
		}
		
		// Cannot start or end with hyphen
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}
	
	return true
}