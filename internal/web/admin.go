package web

import (
	_ "embed"
	"log"
	"net/http"
	"strings"
)

//go:embed admin/static/admin.html
var adminHTML []byte

//go:embed admin/static/admin.css
var adminCSS []byte

//go:embed admin/static/admin.js
var adminJS []byte

// AdminHandler handles the web admin interface
type AdminHandler struct {
	apiKey string // Optional API key for authentication
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(apiKey string) *AdminHandler {
	return &AdminHandler{
		apiKey: apiKey,
	}
}

// RegisterRoutes registers admin routes
func (h *AdminHandler) RegisterRoutes(mux *http.ServeMux) {
	// Main admin interface
	mux.HandleFunc("/p0rtadmin", h.handleAdminPage)
	mux.HandleFunc("/p0rtadmin/", h.handleAdminAssets)
	
	log.Printf("🌐 Web admin interface available at /p0rtadmin")
}

// handleAdminPage serves the main admin HTML page
func (h *AdminHandler) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	// Security headers
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
	
	// Set content type and serve HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(adminHTML)
}

// handleAdminAssets serves static assets (CSS, JS)
func (h *AdminHandler) handleAdminAssets(w http.ResponseWriter, r *http.Request) {
	// Extract asset path
	assetPath := strings.TrimPrefix(r.URL.Path, "/p0rtadmin/")
	
	switch assetPath {
	case "admin.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		w.WriteHeader(http.StatusOK)
		w.Write(adminCSS)
		
	case "admin.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		w.WriteHeader(http.StatusOK)
		w.Write(adminJS)
		
	default:
		// Unknown asset, redirect to main admin page
		http.Redirect(w, r, "/p0rtadmin", http.StatusFound)
	}
}