package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/p0rt/p0rt/internal/api"
	"github.com/p0rt/p0rt/internal/domain"
	"github.com/p0rt/p0rt/internal/metrics"
	"github.com/p0rt/p0rt/internal/security"
	"github.com/p0rt/p0rt/internal/stats"
	"github.com/p0rt/p0rt/internal/web"
)

type HTTPProxy struct {
	sshServer          SSHServer
	abuseMonitor       *security.AbuseMonitor
	apiHandler         *api.Handler
	adminHandler       *web.AdminHandler
	homepageHandler    *web.HomepageHandler
	errorPageHandler   *web.ErrorPageHandler
	reservationManager domain.ReservationManagerInterface
	statsManager       *stats.Manager
}

type SSHServer interface {
	GetClient(domain string) ClientWithPort
	LogConnection(domain, clientIP, method, requestURL string)
	GetDomainStats() map[string]interface{}
	RecordHTTPRequest(domain string, bytesIn, bytesOut int64)
	RecordWebSocketUpgrade(domain string)
}

type ClientWithPort interface {
	GetPort() int
	GetFingerprint() string
	GetClientIP() string
}

// statsResponseWriter wraps http.ResponseWriter to capture bytes written
type statsResponseWriter struct {
	http.ResponseWriter
	bytesWritten int64
}

func (w *statsResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// extractClientIP extracts the real client IP from request headers
func extractClientIP(r *http.Request) string {
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientIP = realIP
	}
	// Properly extract IP from "host:port" format (works for both IPv4 and IPv6)
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	return normalizeIP(clientIP)
}

// normalizeIP removes brackets from IPv6 addresses for consistent storage
func normalizeIP(ip string) string {
	// Remove brackets from IPv6 addresses: [2001:db8::1] -> 2001:db8::1
	if len(ip) > 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
		return ip[1 : len(ip)-1]
	}
	return ip
}

// logStructured creates a structured log with timestamp, IP, method, path and message
func logStructured(r *http.Request, message string, args ...interface{}) {
	clientIP := extractClientIP(r)
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	formattedMessage := fmt.Sprintf(message, args...)
	log.Printf("%s %s %s %s - %s", timestamp, clientIP, r.Method, r.URL.Path, formattedMessage)
}

func NewHTTPProxy(sshServer SSHServer) *HTTPProxy {
	return &HTTPProxy{
		sshServer:        sshServer,
		abuseMonitor:     security.NewAbuseMonitor(),
		homepageHandler:  web.NewHomepageHandler(),
		errorPageHandler: web.NewErrorPageHandler(),
	}
}

// NewHTTPProxyWithAPI creates a new HTTP proxy with API support
func NewHTTPProxyWithAPI(sshServer SSHServer, reservationManager domain.ReservationManagerInterface, statsManager *stats.Manager, apiKey string) *HTTPProxy {
	proxy := &HTTPProxy{
		sshServer:          sshServer,
		abuseMonitor:       security.NewAbuseMonitor(),
		homepageHandler:    web.NewHomepageHandler(),
		errorPageHandler:   web.NewErrorPageHandler(),
		reservationManager: reservationManager,
		statsManager:       statsManager,
	}

	if reservationManager != nil {
		// Setup API handler with SSH notification support
		if securityProvider, ok := sshServer.(api.SecurityProvider); ok {
			sshNotifier := sshServer.(api.SSHNotificationProvider)
			proxy.apiHandler = api.NewHandlerWithSSH(reservationManager, statsManager, securityProvider, sshNotifier, apiKey)
		} else {
			proxy.apiHandler = api.NewHandler(reservationManager, statsManager, apiKey)
		}
	}

	// Setup web admin handler
	proxy.adminHandler = web.NewAdminHandler(apiKey)

	return proxy
}

func (p *HTTPProxy) Start(port string) error {
	mux := http.NewServeMux()

	// Register API routes FIRST (more specific routes)
	if p.apiHandler != nil {
		p.apiHandler.RegisterRoutes(mux)
	}

	// Register web admin interface
	if p.adminHandler != nil {
		p.adminHandler.RegisterRoutes(mux)
	}

	// Register CSS static files
	if p.errorPageHandler != nil {
		mux.HandleFunc("/static/css/base.css", func(w http.ResponseWriter, r *http.Request) {
			p.errorPageHandler.ServeCSSFile(w, "base.css")
		})
		mux.HandleFunc("/static/css/layout.css", func(w http.ResponseWriter, r *http.Request) {
			p.errorPageHandler.ServeCSSFile(w, "layout.css")
		})
		mux.HandleFunc("/static/css/components.css", func(w http.ResponseWriter, r *http.Request) {
			p.errorPageHandler.ServeCSSFile(w, "components.css")
		})
		mux.HandleFunc("/static/css/pages/error-pages.css", func(w http.ResponseWriter, r *http.Request) {
			p.errorPageHandler.ServeCSSFile(w, "error-pages.css")
		})
		mux.HandleFunc("/static/css/pages/forms.css", func(w http.ResponseWriter, r *http.Request) {
			p.errorPageHandler.ServeCSSFile(w, "forms.css")
		})
		// Note: dashboard.css removed - security dashboard is in admin interface only
	}

	// Endpoint pour signaler des abus
	mux.HandleFunc("/report-abuse", p.abuseMonitor.CreateAbuseReportHandler())

	// Note: Security stats moved to admin interface - no public endpoint needed

	// Endpoint pour statistiques de domaines (admin)
	mux.HandleFunc("/domain-stats", p.handleDomainStats)

	// Prometheus metrics endpoint (with basic auth)
	if metrics.IsMetricsEnabled() {
		mux.Handle("/metrics", metrics.BasicAuthMiddleware(promhttp.Handler()))
		log.Println("📊 Prometheus metrics endpoint enabled at /metrics")
	}

	// Ping endpoint pour CloudFlare health checks
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Catch-all route for tunnel proxying (MUST BE LAST)
	mux.HandleFunc("/", p.handleRequest)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  60 * time.Second, // Augmenté pour éviter 521
		WriteTimeout: 60 * time.Second, // Augmenté pour éviter 521
		IdleTimeout:  120 * time.Second,
		// Ajouter des headers par défaut pour CloudFlare
		ErrorLog: log.New(io.Discard, "", 0), // Éviter les logs d'erreur qui peuvent causer des problèmes
	}

	log.Printf("HTTP proxy server listening on port %s", port)
	return server.ListenAndServe()
}

func (p *HTTPProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.Host

	// Ajouter des headers pour CloudFlare
	w.Header().Set("Server", "P0rt")
	w.Header().Set("X-Powered-By", "P0rt")
	
	// Track request completion for metrics
	defer func() {
		duration := time.Since(start).Seconds()
		statusCode := "200" // Default, will be overridden if different
		domainType := "tunnel"
		
		if host == "p0rt.xyz" || host == "www.p0rt.xyz" {
			domainType = "homepage"
		} else if r.URL.Path == "/health" {
			domainType = "health"
		}
		
		metrics.RecordHTTPRequest(r.Method, statusCode, domainType, duration)
	}()

	if host == "p0rt.xyz" || host == "www.p0rt.xyz" {
		p.serveStaticContent(w, r)
		return
	}

	// Check if domain is banned BEFORE checking for active client
	if p.abuseMonitor != nil && p.abuseMonitor.GetReportManager().IsDomainBanned(host) {
		log.Printf("Blocked HTTP request to banned domain: %s from %s", host, extractClientIP(r))
		p.serveBannedDomainPage(w, r, host)
		return
	}

	// Try to find client by domain
	client := p.sshServer.GetClient(host)
	if client == nil {
		// If not found, try to extract subdomain for p0rt.xyz domains
		if strings.HasSuffix(host, ".p0rt.xyz") {
			parts := strings.Split(host, ".")
			if len(parts) >= 3 {
				subdomain := parts[0]
				client = p.sshServer.GetClient(subdomain)
			}
		}
	}

	if client == nil {
		p.serveErrorPage(w, r, host)
		return
	}

	// Add traceability headers
	if fingerprint := client.GetFingerprint(); fingerprint != "" {
		w.Header().Set("X-P0rt-Fingerprint", fingerprint)
	}
	if clientIP := client.GetClientIP(); clientIP != "" {
		w.Header().Set("X-P0rt-Origin", clientIP)
	}

	// Logger la connexion pour le client SSH
	clientIP := extractClientIP(r)

	// Construire l'URL de la requête
	requestURL := r.URL.Path
	if r.URL.RawQuery != "" {
		requestURL += "?" + r.URL.RawQuery
	}

	domain := strings.Split(host, ".")[0]

	// Note: HTTP content analysis removed for privacy reasons
	// Only SSH-level protections (bruteforce, scans) remain active

	// Check for suspicious connection patterns
	if securityProvider, ok := p.sshServer.(interface {
		RecordSecurityEvent(eventType security.EventType, ip string, details map[string]string)
	}); ok {
		// Look for scanning attempts
		if strings.Contains(requestURL, "/.env") ||
			strings.Contains(requestURL, "/wp-admin") ||
			strings.Contains(requestURL, "/admin") ||
			strings.Contains(requestURL, "/phpmyadmin") ||
			strings.Contains(requestURL, "/config") ||
			strings.Contains(requestURL, "..") {
			securityProvider.RecordSecurityEvent(security.EventPortScanning, clientIP, map[string]string{
				"url":    requestURL,
				"domain": domain,
				"type":   "web_scan",
			})
		}

		// Check user agent for bots/scanners
		userAgent := r.Header.Get("User-Agent")
		if strings.Contains(strings.ToLower(userAgent), "bot") ||
			strings.Contains(strings.ToLower(userAgent), "scanner") ||
			strings.Contains(strings.ToLower(userAgent), "crawler") ||
			userAgent == "" {
			securityProvider.RecordSecurityEvent(security.EventSuspiciousConn, clientIP, map[string]string{
				"user_agent": userAgent,
				"domain":     domain,
				"url":        requestURL,
			})
		}
	}

	p.sshServer.LogConnection(domain, clientIP, r.Method, requestURL)

	if r.Header.Get("Upgrade") == "websocket" {
		p.sshServer.RecordWebSocketUpgrade(domain)
		p.handleWebSocket(w, r, client.GetPort())
		return
	}

	targetURL := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("localhost", fmt.Sprintf("%d", client.GetPort())),
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Comprehensive error handling for tunnel vs backend issues
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		logStructured(req, "Proxy error for %s: %v", host, err)
		
		// Different error types need different status codes
		if strings.Contains(err.Error(), "connection refused") ||
		   strings.Contains(err.Error(), "connect: connection refused") ||
		   strings.Contains(err.Error(), "dial tcp") ||
		   strings.Contains(err.Error(), "no such host") {
			// Local service is down - 502 Bad Gateway
			p.serveConnectionErrorPage(rw, req, host, err)
		} else {
			// Other proxy errors - 502 Bad Gateway
			p.serveConnectionErrorPage(rw, req, host, err)
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// Ajouter des headers pour améliorer la compatibilité CloudFlare
		resp.Header.Set("X-Tunnel-Status", "active")
		return nil
	}

	// Vérifier que la connexion locale fonctionne avant de proxifier
	if !p.testLocalConnection(client.GetPort()) {
		p.serveConnectionErrorPage(w, r, host, fmt.Errorf("local service not responding"))
		return
	}

	// Create a response writer wrapper to capture traffic statistics
	bytesIn := r.ContentLength
	if bytesIn < 0 {
		bytesIn = 0
	}

	statsWriter := &statsResponseWriter{ResponseWriter: w}
	proxy.ServeHTTP(statsWriter, r)

	// Record HTTP request statistics
	p.sshServer.RecordHTTPRequest(domain, bytesIn, statsWriter.bytesWritten)
	
	// Record bytes transferred for Prometheus
	if bytesIn > 0 {
		metrics.RecordBytesTransferred("in", domain, bytesIn)
	}
	if statsWriter.bytesWritten > 0 {
		metrics.RecordBytesTransferred("out", domain, statsWriter.bytesWritten)
	}
}

func (p *HTTPProxy) handleWebSocket(w http.ResponseWriter, r *http.Request, targetPort int) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logStructured(r, "WebSocket upgrade failed: %v", err)
		metrics.RecordSecurityEvent("websocket_upgrade_failed", "low")
		return
	}
	defer clientConn.Close()

	targetAddr := net.JoinHostPort("localhost", fmt.Sprintf("%d", targetPort))
	targetURL := url.URL{Scheme: "ws", Host: targetAddr, Path: r.URL.Path}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	headers := http.Header{}
	for key, values := range r.Header {
		if key != "Upgrade" && key != "Connection" && key != "Sec-Websocket-Key" &&
			key != "Sec-Websocket-Version" && key != "Sec-Websocket-Extensions" {
			headers[key] = values
		}
	}

	targetConn, _, err := dialer.Dial(targetURL.String(), headers)
	if err != nil {
		logStructured(r, "Failed to connect to target WebSocket: %v", err)
		metrics.RecordSecurityEvent("websocket_connection_failed", "low")
		return
	}
	defer targetConn.Close()
	
	// Record successful WebSocket connection
	metrics.RecordSecurityEvent("websocket_connection_success", "info")

	errChan := make(chan error, 2)

	go func() {
		for {
			messageType, data, err := clientConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if err := targetConn.WriteMessage(messageType, data); err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		for {
			messageType, data, err := targetConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if err := clientConn.WriteMessage(messageType, data); err != nil {
				errChan <- err
				return
			}
		}
	}()

	<-errChan
}

func (p *HTTPProxy) testLocalConnection(port int) bool {
	// Test TCP connection to the local port
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", fmt.Sprintf("%d", port)), 1*time.Second)
	if err != nil {
		log.Printf("Local connection test failed for port %d: %v", port, err)
		return false
	}
	conn.Close()
	return true
}

// serveAbuseBlockedPage - removed for privacy

func (p *HTTPProxy) serveConnectionErrorPage(w http.ResponseWriter, _ *http.Request, host string, err error) {
	subdomain := ""
	if idx := strings.Index(host, "."); idx > 0 {
		subdomain = host[:idx]
	} else {
		subdomain = host
	}

	var errorMsg string
	errStr := err.Error()
	
	if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "connect: connection refused") {
		errorMsg = "The local service is not running or not accepting connections on the specified port."
	} else if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "i/o timeout") {
		errorMsg = "The local service is not responding (connection timeout)."
	} else if strings.Contains(errStr, "dial tcp") {
		errorMsg = "Unable to establish connection to the local service."
	} else if strings.Contains(errStr, "no such host") {
		errorMsg = "Cannot resolve the local service address."
	} else {
		errorMsg = fmt.Sprintf("Unable to connect to the local service: %s", errStr)
	}

	log.Printf("Serving connection error page for %s: %s", host, errorMsg)
	
	// Use error page handler to return proper 502 status
	if p.errorPageHandler != nil {
		p.errorPageHandler.ServeConnectionError(w, subdomain, errorMsg)
	} else {
		// Fallback if error handler not available
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Service Error</title></head>
<body><h1>Service Error</h1><p>%s</p><p>%s</p></body></html>`, subdomain, errorMsg)
	}
}

func (p *HTTPProxy) serveErrorPage(w http.ResponseWriter, _ *http.Request, host string) {
	subdomain := ""
	if idx := strings.Index(host, "."); idx > 0 {
		subdomain = host[:idx]
	}

	p.errorPageHandler.ServeTunnelError(w, subdomain)
}

func (p *HTTPProxy) serveBannedDomainPage(w http.ResponseWriter, _ *http.Request, host string) {
	subdomain := ""
	if idx := strings.Index(host, "."); idx > 0 {
		subdomain = host[:idx]
	}

	p.errorPageHandler.ServeBannedDomain(w, subdomain)
}

func (p *HTTPProxy) serveStaticContent(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		p.serveHomePage(w, r)
		return
	}

	http.NotFound(w, r)
}

func (p *HTTPProxy) serveHomePage(w http.ResponseWriter, r *http.Request) {
	// Get access mode from stats if available
	accessMode := "restricted"
	accessBadge := `<span class="bg-orange-500 text-white px-3 py-1 rounded-full text-sm font-semibold">🔒 Beta Access</span>`
	accessSection := ""

	if p.statsManager != nil {
		globalStats := p.statsManager.GetGlobalStats()
		if globalStats.AccessMode == "open" {
			accessMode = "open"
			accessBadge = `<span class="bg-green-500 text-white px-3 py-1 rounded-full text-sm font-semibold">✨ Open Access</span>`
		}
	}

	// Create access mode section based on current mode
	if accessMode == "restricted" {
		accessSection = `
            <div class="bg-orange-500/20 border-2 border-orange-500 rounded-xl p-8 mb-12 max-w-2xl mx-auto">
                <h3 class="text-2xl font-bold text-orange-400 mb-4">🔒 Beta Access Mode</h3>
                <p class="text-gray-200 mb-4">
                    P0rt is currently in beta access mode. Only pre-registered SSH keys can create tunnels.
                </p>
                <p class="text-gray-300 text-sm">
                    This helps us ensure quality of service during our beta phase. 
                    Contact us to request access or wait for open access launch.
                </p>
            </div>`
	} else {
		accessSection = `
            <div class="bg-green-500/20 border-2 border-green-500 rounded-xl p-8 mb-12 max-w-2xl mx-auto">
                <h3 class="text-2xl font-bold text-green-400 mb-4">✨ Open Access Mode</h3>
                <p class="text-gray-200 mb-4">
                    P0rt is open to everyone! Any SSH key can create tunnels instantly.
                </p>
                <p class="text-gray-300 text-sm">
                    No registration required. Just run the SSH command and start tunneling.
                </p>
            </div>`
	}

	// Use the embedded homepage handler
	if p.homepageHandler != nil {
		p.homepageHandler.ServeHomepage(w, r, accessBadge, accessSection)
	} else {
		// Fallback to simple response if handler not available
		http.Error(w, "Homepage handler not available", http.StatusInternalServerError)
	}
}

type TCPProxy struct {
	targetHost string
	targetPort int
}

func NewTCPProxy(targetHost string, targetPort int) *TCPProxy {
	return &TCPProxy{
		targetHost: targetHost,
		targetPort: targetPort,
	}
}

func (p *TCPProxy) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go p.handleConnection(conn)
	}
}

func (p *TCPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	targetAddr := net.JoinHostPort(p.targetHost, fmt.Sprintf("%d", p.targetPort))
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(targetConn, clientConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errChan <- err
	}()

	<-errChan
}

// Note: handleSecurityStats removed - security stats are now in admin interface only

func (p *HTTPProxy) handleDomainStats(w http.ResponseWriter, r *http.Request) {
	// Simple protection : seulement si la requête vient de localhost
	if r.Header.Get("X-Forwarded-For") != "" || !strings.HasPrefix(r.RemoteAddr, "127.0.0.1") {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	stats := p.sshServer.GetDomainStats()

	// Convert to JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":       "success",
		"timestamp":    time.Now().Format(time.RFC3339),
		"domain_stats": stats,
	}

	json, _ := json.Marshal(response)
	w.Write(json)
}

// GetAbuseMonitor returns the abuse monitor instance
func (p *HTTPProxy) GetAbuseMonitor() *security.AbuseMonitor {
	return p.abuseMonitor
}
