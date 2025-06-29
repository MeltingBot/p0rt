package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// handleKeys handles /api/v1/keys endpoint
func (h *Handler) handleKeys(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if h.keyStore == nil {
		writeError(w, http.StatusInternalServerError, "Key management not available")
		return
	}

	switch r.Method {
	case http.MethodGet:
		// List all keys
		keys := h.keyStore.ListKeys()

		// Convert to a slice for JSON output
		var keyList []map[string]interface{}
		for fingerprint, access := range keys {
			keyInfo := map[string]interface{}{
				"fingerprint": fingerprint,
				"tier":        access.Tier,
				"active":      access.Active,
				"comment":     access.Comment,
				"added_at":    access.AddedAt.Format(time.RFC3339),
			}
			if access.ExpiresAt != nil {
				keyInfo["expires_at"] = access.ExpiresAt.Format(time.RFC3339)
			}
			keyList = append(keyList, keyInfo)
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":   true,
			"keys":      keyList,
			"count":     len(keyList),
			"timestamp": time.Now().Format(time.RFC3339),
		})

	case http.MethodPost:
		// Add new key
		var req struct {
			Fingerprint string     `json:"fingerprint"`
			PublicKey   string     `json:"public_key"`
			Comment     string     `json:"comment"`
			Tier        string     `json:"tier"`
			ExpiresAt   *time.Time `json:"expires_at"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// Validate input
		if req.Fingerprint == "" && req.PublicKey == "" {
			writeError(w, http.StatusBadRequest, "Either fingerprint or public_key is required")
			return
		}

		if req.Tier == "" {
			req.Tier = "free"
		}

		var err error
		if req.PublicKey != "" {
			err = h.keyStore.AddKey(req.PublicKey, req.Comment, req.Tier, req.ExpiresAt)
		} else {
			err = h.keyStore.AddKeyByFingerprint(req.Fingerprint, req.Comment, req.Tier, req.ExpiresAt)
		}

		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"success":     true,
			"message":     "SSH key added successfully",
			"fingerprint": req.Fingerprint,
			"tier":        req.Tier,
			"timestamp":   time.Now().Format(time.RFC3339),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleKey handles /api/v1/keys/{fingerprint} endpoint
func (h *Handler) handleKey(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateRequest(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if h.keyStore == nil {
		writeError(w, http.StatusInternalServerError, "Key management not available")
		return
	}

	// Extract fingerprint from path
	fingerprint := r.URL.Path[len("/api/v1/keys/"):]
	if fingerprint == "" {
		writeError(w, http.StatusBadRequest, "Fingerprint is required")
		return
	}

	switch r.Method {
	case http.MethodDelete:
		// Remove key
		if err := h.keyStore.RemoveKey(fingerprint); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":     true,
			"message":     "SSH key removed successfully",
			"fingerprint": fingerprint,
			"timestamp":   time.Now().Format(time.RFC3339),
		})

	case http.MethodPatch:
		// Activate/Deactivate key
		var req struct {
			Active bool `json:"active"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		var err error
		if req.Active {
			err = h.keyStore.ActivateKey(fingerprint)
		} else {
			err = h.keyStore.DeactivateKey(fingerprint)
		}

		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":     true,
			"message":     fmt.Sprintf("SSH key %s successfully", map[bool]string{true: "activated", false: "deactivated"}[req.Active]),
			"fingerprint": fingerprint,
			"active":      req.Active,
			"timestamp":   time.Now().Format(time.RFC3339),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}
