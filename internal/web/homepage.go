package web

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed static/pages/homepage.html
var homepageHTML []byte

// HomepageHandler handles the homepage
type HomepageHandler struct {
	template *template.Template
}

// HomepageData contains data for the homepage template
type HomepageData struct {
	AccessBadge   template.HTML
	AccessSection template.HTML
}

// NewHomepageHandler creates a new homepage handler
func NewHomepageHandler() *HomepageHandler {
	tmpl, err := template.New("homepage").Parse(string(homepageHTML))
	if err != nil {
		panic("Failed to parse homepage template: " + err.Error())
	}

	return &HomepageHandler{
		template: tmpl,
	}
}

// ServeHomepage serves the homepage with dynamic content
func (h *HomepageHandler) ServeHomepage(w http.ResponseWriter, r *http.Request, accessBadge, accessSection string) {
	data := HomepageData{
		AccessBadge:   template.HTML(accessBadge),
		AccessSection: template.HTML(accessSection),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	if err := h.template.Execute(w, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
