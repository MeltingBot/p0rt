package web

import (
	_ "embed"
	"log"
	"net/http"
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
	// Admin assets (CSS, JS)
	mux.HandleFunc("/p0rtadmin/admin.css", h.handleAdminCSS)
	mux.HandleFunc("/p0rtadmin/admin.js", h.handleAdminJS)
	
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

// handleAdminCSS serves the CSS file
func (h *AdminHandler) handleAdminCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.WriteHeader(http.StatusOK)
	w.Write(adminCSS)
}

// handleAdminJS serves the JavaScript file
func (h *AdminHandler) handleAdminJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.WriteHeader(http.StatusOK)
	w.Write(adminJS)
}