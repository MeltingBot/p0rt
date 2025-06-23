package web

import (
	_ "embed"
	"html/template"
	"log"
	"net/http"
	"os"
)

//go:embed admin/static/admin.html
var adminHTML []byte

//go:embed admin/static/admin.css
var adminCSS []byte

//go:embed admin/static/admin.js
var adminJS []byte

// AdminHandler handles the web admin interface
type AdminHandler struct {
	apiKey    string // Optional API key for authentication
	adminURL  string // Admin URL from environment
	template  *template.Template
}

// AdminData contains data for the admin template
type AdminData struct {
	AdminURL string
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(apiKey string) *AdminHandler {
	adminURL := os.Getenv("ADMIN_URL")
	if adminURL == "" {
		log.Printf("⚠️  ADMIN_URL not set in environment - web admin interface disabled")
		return nil
	}

	tmpl, err := template.New("admin").Parse(string(adminHTML))
	if err != nil {
		panic("Failed to parse admin template: " + err.Error())
	}

	return &AdminHandler{
		apiKey:   apiKey,
		adminURL: adminURL,
		template: tmpl,
	}
}

// RegisterRoutes registers admin routes
func (h *AdminHandler) RegisterRoutes(mux *http.ServeMux) {
	if h.adminURL == "" {
		return // Admin interface disabled
	}

	// Main admin interface
	mux.HandleFunc(h.adminURL, h.handleAdminPage)
	// Admin assets (CSS, JS)
	mux.HandleFunc(h.adminURL+"/admin.css", h.handleAdminCSS)
	mux.HandleFunc(h.adminURL+"/admin.js", h.handleAdminJS)
	
	log.Printf("🌐 Web admin interface available at %s", h.adminURL)
}

// handleAdminPage serves the main admin HTML page
func (h *AdminHandler) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	// Security headers
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
	
	// Anti-cache headers to prevent Cloudflare and browser caching
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	
	// Set content type and serve HTML with template data
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	
	data := AdminData{
		AdminURL: h.adminURL,
	}
	
	if err := h.template.Execute(w, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleAdminCSS serves the CSS file
func (h *AdminHandler) handleAdminCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	w.Write(adminCSS)
}

// handleAdminJS serves the JavaScript file
func (h *AdminHandler) handleAdminJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	w.Write(adminJS)
}