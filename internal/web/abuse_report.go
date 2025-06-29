package web

import (
	_ "embed"
	"html/template"
	"net/http"
	"os"
)

//go:embed static/pages/abuse-report.html
var abuseReportHTML []byte

// CSS files for forms are already embedded in error_pages.go

// AbuseReportHandler handles the abuse report form
type AbuseReportHandler struct {
	template *template.Template
}

// AbuseReportData contains data for the abuse report template
type AbuseReportData struct {
	SiteKey string
}

// NewAbuseReportHandler creates a new abuse report handler
func NewAbuseReportHandler() *AbuseReportHandler {
	tmpl, err := template.New("abuse-report").Parse(string(abuseReportHTML))
	if err != nil {
		panic("Failed to parse abuse report template: " + err.Error())
	}

	return &AbuseReportHandler{
		template: tmpl,
	}
}

// ServeAbuseReportForm serves the abuse report form
func (h *AbuseReportHandler) ServeAbuseReportForm(w http.ResponseWriter, r *http.Request) {
	siteKey := os.Getenv("HCAPTCHA_SITE_KEY")
	if siteKey == "" {
		// Use test site key for development
		siteKey = "10000000-ffff-ffff-ffff-000000000001"
	}

	data := AbuseReportData{
		SiteKey: siteKey,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	if err := h.template.Execute(w, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
