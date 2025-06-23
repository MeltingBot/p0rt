package web

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed static/pages/connection-error.html
var connectionErrorHTML []byte

//go:embed static/pages/tunnel-error.html
var tunnelErrorHTML []byte

//go:embed static/pages/banned-domain.html
var bannedDomainHTML []byte

// Note: security-stats.html removed - security stats are in admin interface only

//go:embed static/css/base.css
var baseCSSFile []byte

//go:embed static/css/layout.css
var layoutCSSFile []byte

//go:embed static/css/components.css
var componentsCSSFile []byte

//go:embed static/css/pages/error-pages.css
var errorPagesCSSFile []byte

//go:embed static/css/pages/forms.css
var formsCSSFile []byte

// Note: dashboard.css removed - security dashboard is in admin interface only

// ErrorPageHandler handles error pages
type ErrorPageHandler struct {
	connectionErrorTmpl *template.Template
	tunnelErrorTmpl     *template.Template
	bannedDomainTmpl    *template.Template
}

// ErrorPageData contains data for error page templates
type ErrorPageData struct {
	Subdomain    string
	ErrorMessage string
}

// NewErrorPageHandler creates a new error page handler
func NewErrorPageHandler() *ErrorPageHandler {
	handler := &ErrorPageHandler{}

	// Parse all templates
	var err error
	handler.connectionErrorTmpl, err = template.New("connection-error").Parse(string(connectionErrorHTML))
	if err != nil {
		panic("Failed to parse connection error template: " + err.Error())
	}

	handler.tunnelErrorTmpl, err = template.New("tunnel-error").Parse(string(tunnelErrorHTML))
	if err != nil {
		panic("Failed to parse tunnel error template: " + err.Error())
	}

	handler.bannedDomainTmpl, err = template.New("banned-domain").Parse(string(bannedDomainHTML))
	if err != nil {
		panic("Failed to parse banned domain template: " + err.Error())
	}

	// Note: security stats template removed - moved to admin interface

	return handler
}

// ServeConnectionError serves the connection error page
func (h *ErrorPageHandler) ServeConnectionError(w http.ResponseWriter, subdomain, errorMessage string) {
	data := ErrorPageData{
		Subdomain:    subdomain,
		ErrorMessage: errorMessage,
	}

	// Set headers that help Cloudflare pass through our custom error page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Error-Type", "backend-connection")
	w.Header().Set("X-P0rt-Error", "local-service-down")
	
	// Use 200 OK to ensure Cloudflare passes through our custom error page
	// The page content will indicate the error to users
	w.WriteHeader(http.StatusOK)

	if err := h.connectionErrorTmpl.Execute(w, data); err != nil {
		// Fallback error response
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error serving error page"))
	}
}

// ServeTunnelError serves the tunnel not connected error page
func (h *ErrorPageHandler) ServeTunnelError(w http.ResponseWriter, subdomain string) {
	data := ErrorPageData{
		Subdomain: subdomain,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)

	if err := h.tunnelErrorTmpl.Execute(w, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// ServeBannedDomain serves the banned domain page
func (h *ErrorPageHandler) ServeBannedDomain(w http.ResponseWriter, subdomain string) {
	data := ErrorPageData{
		Subdomain: subdomain,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	if err := h.bannedDomainTmpl.Execute(w, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Note: ServeSecurityStats removed - security stats are now in admin interface only

// ServeCSSFile serves CSS files
func (h *ErrorPageHandler) ServeCSSFile(w http.ResponseWriter, filename string) {
	var cssContent []byte
	
	switch filename {
	case "base.css":
		cssContent = baseCSSFile
	case "layout.css":
		cssContent = layoutCSSFile
	case "components.css":
		cssContent = componentsCSSFile
	case "error-pages.css":
		cssContent = errorPagesCSSFile
	case "forms.css":
		cssContent = formsCSSFile
	// Note: dashboard.css removed - security dashboard styles are in admin interface
	default:
		http.NotFound(w, nil)
		return
	}

	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.WriteHeader(http.StatusOK)
	w.Write(cssContent)
}