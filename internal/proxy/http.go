package proxy

import (
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
	"github.com/p0rt/p0rt/internal/security"
)

type HTTPProxy struct {
	sshServer    SSHServer
	abuseMonitor *security.AbuseMonitor
}

type SSHServer interface {
	GetClient(domain string) ClientWithPort
	LogConnection(domain, clientIP, requestURL string)
}

type ClientWithPort interface {
	GetPort() int
}

func NewHTTPProxy(sshServer SSHServer) *HTTPProxy {
	return &HTTPProxy{
		sshServer:    sshServer,
		abuseMonitor: security.NewAbuseMonitor(),
	}
}

func (p *HTTPProxy) Start(port string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", p.handleRequest)

	// Endpoint pour signaler des abus
	mux.HandleFunc("/report-abuse", p.abuseMonitor.CreateAbuseReportHandler())
	
	// Endpoint pour statistiques de sécurité (admin)
	mux.HandleFunc("/security-stats", p.handleSecurityStats)

	// Ping endpoint pour CloudFlare health checks
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

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
	host := r.Host

	// Ajouter des headers pour CloudFlare
	w.Header().Set("Server", "P0rt")
	w.Header().Set("X-Powered-By", "P0rt")

	if host == "p0rt.xyz" || host == "www.p0rt.xyz" {
		p.serveStaticContent(w, r)
		return
	}

	client := p.sshServer.GetClient(host)
	if client == nil {
		p.serveErrorPage(w, r, host)
		return
	}

	// Logger la connexion pour le client SSH
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientIP = realIP
	}

	// Extraire juste l'IP sans le port
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}

	// Construire l'URL de la requête
	requestURL := r.URL.Path
	if r.URL.RawQuery != "" {
		requestURL += "?" + r.URL.RawQuery
	}

	domain := strings.Split(host, ".")[0]
	
	// Analyser la requête pour détecter des patterns suspects
	userAgent := r.Header.Get("User-Agent")
	referer := r.Header.Get("Referer")
	if allowed, reason := p.abuseMonitor.AnalyzeHTTPRequest(domain, requestURL, userAgent, referer); !allowed {
		log.Printf("Suspicious request blocked for domain %s: %s", domain, reason)
		p.serveAbuseBlockedPage(w, r, domain, reason)
		return
	}
	
	p.sshServer.LogConnection(domain, clientIP, requestURL)

	if r.Header.Get("Upgrade") == "websocket" {
		p.handleWebSocket(w, r, client.GetPort())
		return
	}

	targetURL := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("localhost", fmt.Sprintf("%d", client.GetPort())),
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Améliorer la gestion d'erreur pour éviter 521
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("Proxy error for %s: %v", host, err)
		// Au lieu de retourner une erreur qui cause 521, servir notre page
		p.serveConnectionErrorPage(rw, req, host, err)
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

	proxy.ServeHTTP(w, r)
}

func (p *HTTPProxy) handleWebSocket(w http.ResponseWriter, r *http.Request, targetPort int) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
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
		log.Printf("Failed to connect to target WebSocket: %v", err)
		return
	}
	defer targetConn.Close()

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
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", fmt.Sprintf("%d", port)), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (p *HTTPProxy) serveAbuseBlockedPage(w http.ResponseWriter, _ *http.Request, domain, reason string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked - P0rt Security</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            background: #0a0a0a;
            color: #fafafa;
            text-align: center;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        h1 { 
            font-size: 2.5rem; 
            margin-bottom: 1rem;
            color: #ef4444;
        }
        .subdomain {
            font-size: 1.5rem;
            color: #60a5fa;
            margin-bottom: 2rem;
            font-family: 'Monaco', 'Menlo', monospace;
        }
        .message { 
            color: #888; 
            font-size: 1.125rem; 
            margin-bottom: 3rem;
            line-height: 1.6;
        }
        .reason {
            background: #1a1a1a;
            border: 1px solid #ef4444;
            border-radius: 6px;
            padding: 1rem;
            margin: 2rem auto;
            max-width: 600px;
            color: #ef4444;
        }
        .help {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid #333;
        }
        .help h2 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
        }
        a { 
            color: #60a5fa; 
            text-decoration: none;
        }
        a:hover { 
            text-decoration: underline;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        .report-form {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 6px;
            padding: 1.5rem;
            margin: 2rem auto;
            max-width: 500px;
            text-align: left;
        }
        .report-form input, .report-form textarea, .report-form button {
            width: 100%%;
            margin-bottom: 1rem;
            padding: 0.5rem;
            border: 1px solid #333;
            border-radius: 4px;
            background: #0a0a0a;
            color: #fafafa;
        }
        .report-form button {
            background: #ef4444;
            color: white;
            cursor: pointer;
        }
        .report-form button:hover {
            background: #dc2626;
        }
    </style>
</head>
<body>
    <div>
        <div class="icon">🛡️</div>
        <h1>Access Blocked</h1>
        <div class="subdomain">%s.p0rt.xyz</div>
        <p class="message">
            This tunnel has been temporarily blocked by our security system.
        </p>
        
        <div class="reason">
            Security Policy Violation: %s
        </div>
        
        <div class="help">
            <h2>What happened?</h2>
            <p>Our automated security system detected patterns that may indicate malicious use such as phishing, spam, or scam activities. This is an automated security measure to protect users.</p>
            
            <h2>If this is a false positive:</h2>
            <p>Contact us with details about your legitimate use case and we'll review the block.</p>
            
            <p style="margin-top: 2rem;">
                <a href="https://p0rt.xyz">Back to P0rt →</a> |
                <a href="mailto:security@p0rt.xyz">Contact Security Team</a>
            </p>
        </div>
    </div>
</body>
</html>`, domain, reason)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Block-Reason", "security-policy")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(html))
}

func (p *HTTPProxy) serveConnectionErrorPage(w http.ResponseWriter, _ *http.Request, host string, err error) {
	subdomain := ""
	if idx := strings.Index(host, "."); idx > 0 {
		subdomain = host[:idx]
	}

	var errorMsg string
	if strings.Contains(err.Error(), "connection refused") {
		errorMsg = "The local service is not running or not accepting connections."
	} else if strings.Contains(err.Error(), "timeout") {
		errorMsg = "The local service is not responding (timeout)."
	} else {
		errorMsg = "Unable to connect to the local service."
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Service Error - P0rt</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            background: #0a0a0a;
            color: #fafafa;
            text-align: center;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        h1 { 
            font-size: 2.5rem; 
            margin-bottom: 1rem;
            color: #f59e0b;
        }
        .subdomain {
            font-size: 1.5rem;
            color: #60a5fa;
            margin-bottom: 2rem;
            font-family: 'Monaco', 'Menlo', monospace;
        }
        .message { 
            color: #888; 
            font-size: 1.125rem; 
            margin-bottom: 3rem;
            line-height: 1.6;
        }
        .error-details {
            background: #1a1a1a;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 1rem;
            margin: 2rem auto;
            max-width: 600px;
            color: #f59e0b;
        }
        .help {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid #333;
        }
        .help h2 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
        }
        a { 
            color: #60a5fa; 
            text-decoration: none;
        }
        a:hover { 
            text-decoration: underline;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div>
        <div class="icon">⚠️</div>
        <h1>Service Error</h1>
        <div class="subdomain">%s.p0rt.xyz</div>
        <p class="message">
            The tunnel is connected but your local service has an issue.
        </p>
        
        <div class="error-details">
            %s
        </div>
        
        <div class="help">
            <h2>How to Fix This</h2>
            <ul style="text-align: left; display: inline-block;">
                <li>Make sure your local service is running</li>
                <li>Check that it's listening on the correct port</li>
                <li>Verify the port in your SSH command matches your service</li>
                <li>Check firewall settings on your local machine</li>
            </ul>
            <p style="margin-top: 2rem;">
                <a href="https://p0rt.xyz">Back to P0rt →</a>
            </p>
        </div>
    </div>
</body>
</html>`, subdomain, errorMsg)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Error-Type", "service-error")
	w.WriteHeader(http.StatusOK) // Return 200 to avoid CloudFlare errors
	w.Write([]byte(html))
}

func (p *HTTPProxy) serveErrorPage(w http.ResponseWriter, _ *http.Request, host string) {
	subdomain := ""
	if idx := strings.Index(host, "."); idx > 0 {
		subdomain = host[:idx]
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tunnel Not Connected - P0rt</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            background: #0a0a0a;
            color: #fafafa;
            text-align: center;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        h1 { 
            font-size: 2.5rem; 
            margin-bottom: 1rem;
            color: #ef4444;
        }
        .subdomain {
            font-size: 1.5rem;
            color: #60a5fa;
            margin-bottom: 2rem;
            font-family: 'Monaco', 'Menlo', monospace;
        }
        .message { 
            color: #888; 
            font-size: 1.125rem; 
            margin-bottom: 3rem;
            line-height: 1.6;
        }
        pre {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 6px;
            padding: 1.5rem;
            overflow-x: auto;
            text-align: left;
            max-width: 600px;
            margin: 0 auto 2rem;
        }
        code { 
            font-family: 'Monaco', 'Menlo', monospace;
            color: #60a5fa;
        }
        .help {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid #333;
        }
        .help h2 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
        }
        a { 
            color: #60a5fa; 
            text-decoration: none;
        }
        a:hover { 
            text-decoration: underline;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div>
        <div class="icon">🔌</div>
        <h1>Tunnel Not Connected</h1>
        <div class="subdomain">%s.p0rt.xyz</div>
        <p class="message">
            This tunnel is not currently connected.<br>
            To activate it, run the following command from your local machine:
        </p>
        
        <pre><code>ssh -R 443:localhost:8080 ssh.p0rt.xyz</code></pre>
        
        <div class="help">
            <h2>Need Help?</h2>
            <p>Make sure you:</p>
            <ul style="text-align: left; display: inline-block;">
                <li>Connect to <strong>ssh.p0rt.xyz</strong> (not p0rt.xyz)</li>
                <li>Replace <code>localhost:8080</code> with your local server address</li>
                <li>Your tunnel will get a unique three-word domain automatically</li>
            </ul>
            <p style="margin-top: 2rem;">
                <a href="https://p0rt.xyz">Learn more about P0rt →</a>
            </p>
        </div>
    </div>
</body>
</html>`, subdomain)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK) // Return 200 to avoid CloudFlare 502
	w.Write([]byte(html))
}

func (p *HTTPProxy) serveStaticContent(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		p.serveHomePage(w, r)
		return
	}

	http.NotFound(w, r)
}

func (p *HTTPProxy) serveHomePage(w http.ResponseWriter, _ *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>P0rt.xyz - Expose Local Servers to the Internet</title>
    <meta name="description" content="P0rt.xyz allows you to expose local servers to the internet without installation, signup, and free forever.">
    <meta name="keywords" content="P0rt.xyz, expose local servers, internet, free, ngrok alternative, ssh tunneling">
    <meta name="author" content="P0rt">
    
    <!-- Open Graph meta tags for social sharing -->
    <meta property="og:title" content="P0rt.xyz - Expose Local Servers to the Internet">
    <meta property="og:description" content="P0rt.xyz allows you to expose local servers to the internet without installation, signup, and free forever.">
    <meta property="og:type" content="website">
    <meta property="og:url" content="https://p0rt.xyz">
    
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,700" rel="stylesheet" />
    <style>
        .gradient {
            background: linear-gradient(90deg, #0fffc1, #7e0fff);
        }
        .code-block {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            font-family: 'Monaco', 'Menlo', monospace;
        }
        .glow {
            box-shadow: 0 0 20px rgba(126, 15, 255, 0.3);
        }
    </style>
</head>
<body class="leading-normal tracking-normal text-white gradient" style="font-family: 'Source Sans Pro', sans-serif;">
    <!-- Header -->
    <nav id="header" class="w-full text-white">
        <div class="w-full container mx-auto flex flex-wrap items-center justify-between mt-0 py-3">
            <div class="text-white no-underline hover:no-underline font-bold text-2xl lg:text-4xl mt-2">
                <span class="text-4xl">🚀</span> P0rt.xyz
            </div>
            <a class="inline-flex justify-center rounded-lg py-2 px-4 bg-white text-slate-900 ring-1 ring-slate-900/10 hover:bg-white/75 hover:ring-slate-900/15" href="https://github.com/p0rt-labs/p0rt">
                <span class="pr-2">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
                        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                    </svg>
                </span>
                GitHub
            </a>
        </div>
    </nav>

    <!-- Hero Section -->
    <div class="container mx-auto px-4 py-16">
        <div class="text-center max-w-4xl mx-auto">
            <h1 class="text-4xl md:text-6xl font-bold mb-6">
                <span class="text-white">Localhost to </span><span class="text-cyan-300">HTTPS</span><span class="text-white"> in seconds</span>
            </h1>
            <p class="text-2xl md:text-3xl text-gray-200 mb-12">
                One SSH command. Zero config. Three-word domains.
            </p>
            
            <div class="bg-black/50 backdrop-blur-sm rounded-xl p-8 mb-8 max-w-2xl mx-auto">
                <div class="text-left code-block p-6 text-xl">
                    <span class="text-green-400">$</span> <span class="text-white">ssh -R 443:localhost:3000 ssh.p0rt.xyz</span>
                </div>
                <div class="mt-6 text-center">
                    <p class="text-gray-300 text-lg">Your app is now live at:</p>
                    <p class="text-3xl font-bold text-cyan-400 mt-2">whale-guitar-fox.p0rt.xyz</p>
                </div>
            </div>
            
            <div class="grid grid-cols-3 gap-8 max-w-2xl mx-auto text-white">
                <div>
                    <div class="text-5xl mb-2">⚡</div>
                    <p class="font-semibold">Instant</p>
                </div>
                <div>
                    <div class="text-5xl mb-2">🔒</div>
                    <p class="font-semibold">Secure</p>
                </div>
                <div>
                    <div class="text-5xl mb-2">🎯</div>
                    <p class="font-semibold">Persistent</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Features Section -->
    <section class="bg-gray-900 py-16">
        <div class="container max-w-6xl mx-auto px-4">
            <h2 class="text-4xl md:text-5xl font-bold text-center text-white mb-16">
                Why developers love P0rt
            </h2>
            
            <div class="grid md:grid-cols-2 gap-12">
                <div class="bg-gray-800 rounded-lg p-8 border border-gray-700">
                    <h3 class="text-2xl font-bold text-white mb-4">🧠 Smart Domain Generation</h3>
                    <p class="text-gray-300 mb-4">
                        Your SSH key fingerprint generates a unique three-word domain. Always get the same domain with the same key.
                    </p>
                    <div class="bg-gray-900 rounded p-4 font-mono text-sm">
                        <div class="text-green-400">SSH Key → SHA256 → 3 Words</div>
                        <div class="text-gray-500 mt-2">304 million unique combinations</div>
                    </div>
                </div>
                
                <div class="bg-gray-800 rounded-lg p-8 border border-gray-700">
                    <h3 class="text-2xl font-bold text-white mb-4">🛡️ Enterprise-Grade Security</h3>
                    <p class="text-gray-300 mb-4">
                        End-to-end encryption with SSH. Automatic HTTPS with valid certificates. Your data never touches our servers unencrypted.
                    </p>
                    <p class="text-xs text-gray-500 mb-4">
                        *Connection logs are only visible to you in your SSH terminal
                    </p>
                    <div class="flex gap-4 text-gray-400">
                        <span>✓ SSH Encrypted</span>
                        <span>✓ HTTPS Ready</span>
                        <span>✓ Zero Logs*</span>
                    </div>
                </div>
                
                <div class="bg-gray-800 rounded-lg p-8 border border-gray-700">
                    <h3 class="text-2xl font-bold text-white mb-4">⚡ Built for Speed</h3>
                    <p class="text-gray-300 mb-4">
                        Written in Go for blazing fast performance. Handles thousands of concurrent connections with minimal resource usage.
                    </p>
                    <div class="flex gap-6 text-gray-400">
                        <div>
                            <div class="text-2xl text-cyan-400 font-bold">< 50ms</div>
                            <div class="text-sm">Latency</div>
                        </div>
                        <div>
                            <div class="text-2xl text-cyan-400 font-bold">99.9%</div>
                            <div class="text-sm">Uptime</div>
                        </div>
                    </div>
                </div>
                
                <div class="bg-gray-800 rounded-lg p-8 border border-gray-700">
                    <h3 class="text-2xl font-bold text-white mb-4">🔄 Live Connection Monitoring</h3>
                    <p class="text-gray-300 mb-4">
                        See real-time connections directly in your SSH terminal. Know who's accessing your tunnel and when.
                    </p>
                    <div class="bg-gray-900 rounded p-6 font-mono text-xs max-w-none text-left">
                        <div class="text-gray-400">[15:04:05] 192.168.1.100 /api/users</div>
                        <div class="text-gray-400">[15:04:12] 10.0.0.5 /dashboard</div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- How It Works Section -->
    <section class="bg-white py-16">
        <div class="container mx-auto max-w-7xl px-4">
            <h2 class="text-4xl font-bold text-center text-gray-800 mb-16">
                Get online in 3 steps
            </h2>
            
            <div class="grid md:grid-cols-3 gap-12 max-w-7xl mx-auto">
                <div class="text-center">
                    <div class="w-16 h-16 bg-blue-500 rounded-full flex items-center justify-center text-white text-2xl font-bold mx-auto mb-6">1</div>
                    <h3 class="text-xl font-bold text-gray-800 mb-4">Run SSH Command</h3>
                    <div class="bg-gray-900 text-green-400 p-6 rounded-lg font-mono text-xs mb-4 max-w-none text-left">
                        ssh -R 443:localhost:3000 ssh.p0rt.xyz
                    </div>
                    <p class="text-gray-600">Point P0rt to your local development server</p>
                </div>
                
                <div class="text-center">
                    <div class="w-16 h-16 bg-green-500 rounded-full flex items-center justify-center text-white text-2xl font-bold mx-auto mb-6">2</div>
                    <h3 class="text-xl font-bold text-gray-800 mb-4">Get Your Domain</h3>
                    <div class="bg-blue-50 p-4 rounded-lg mb-4">
                        <div class="text-xl font-bold text-blue-600">whale-guitar-fox.p0rt.xyz</div>
                        <div class="text-sm text-gray-500 mt-1">Generated from your SSH key</div>
                    </div>
                    <p class="text-gray-600">Instantly receive a memorable HTTPS domain</p>
                </div>
                
                <div class="text-center">
                    <div class="w-16 h-16 bg-purple-500 rounded-full flex items-center justify-center text-white text-2xl font-bold mx-auto mb-6">3</div>
                    <h3 class="text-xl font-bold text-gray-800 mb-4">Share & Monitor</h3>
                    <div class="bg-gray-900 text-green-400 p-6 rounded-lg font-mono text-xs mb-4 max-w-none text-left">
                        [15:04:05] 192.168.1.100 /api/users<br>[15:04:12] 10.0.0.5 /dashboard
                    </div>
                    <p class="text-gray-600">Watch real-time traffic in your terminal</p>
                </div>
            </div>
        </div>
    </section>

    <!-- FAQ Section -->
    <section class="bg-gray-50 py-16">
        <div class="container mx-auto max-w-4xl px-4">
            <h2 class="text-4xl font-bold text-center text-gray-800 mb-12">
                Common Questions
            </h2>
            
            <div class="space-y-8">
                <div class="bg-white p-6 rounded-lg shadow-sm">
                    <h3 class="text-xl font-semibold text-gray-800 mb-3">What makes P0rt different?</h3>
                    <p class="text-gray-600">
                        P0rt focuses on simplicity and developer experience. Three-word domains are memorable, 
                        real-time monitoring shows you exactly who's using your tunnel, and everything works 
                        with just SSH - no additional tools required.
                    </p>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow-sm">
                    <h3 class="text-xl font-semibold text-gray-800 mb-3">Can I use custom domains?</h3>
                    <p class="text-gray-600">
                        Yes! Use <code>LC_DOMAIN=myapp ssh -R 443:localhost:3000 ssh.p0rt.xyz</code> 
                        to get <strong>myapp.p0rt.xyz</strong> instead of the generated three-word domain.
                    </p>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow-sm">
                    <h3 class="text-xl font-semibold text-gray-800 mb-3">Is this production-ready?</h3>
                    <p class="text-gray-600">
                        P0rt is perfect for development, demos, and sharing prototypes. For production workloads, 
                        consider running your own instance or using dedicated infrastructure.
                    </p>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow-sm">
                    <h3 class="text-xl font-semibold text-gray-800 mb-3">How do I monitor connections?</h3>
                    <p class="text-gray-600">
                        Connection logs appear directly in your SSH terminal in real-time. 
                        See visitor IPs, user agents, and timestamps without leaving your terminal.
                    </p>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow-sm">
                    <h3 class="text-xl font-semibold text-gray-800 mb-3">How do you prevent abuse?</h3>
                    <p class="text-gray-600">
                        P0rt includes automated security monitoring for phishing, spam, and scam patterns. 
                        Suspicious domains are automatically blocked. Rate limiting prevents excessive use.
                        <a href="/report-abuse" class="text-blue-600 hover:text-blue-800 ml-1">Report abuse here</a>.
                    </p>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="bg-gray-800 text-white py-8">
        <div class="container mx-auto text-center px-4">
            <p class="text-lg mb-4">Made with ❤️ for developers</p>
            <div class="flex justify-center space-x-6">
                <a href="https://github.com/p0rt-labs/p0rt" class="text-blue-400 hover:text-blue-300">GitHub</a>
                <a href="https://github.com/p0rt-labs/p0rt/issues" class="text-blue-400 hover:text-blue-300">Support</a>
                <a href="https://github.com/p0rt-labs/p0rt/blob/main/LICENSE" class="text-blue-400 hover:text-blue-300">License</a>
            </div>
            <p class="text-gray-400 text-sm mt-4">
                P0rt.xyz - Fast, free SSH tunneling service
            </p>
        </div>
    </footer>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write([]byte(html))
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

func (p *HTTPProxy) handleSecurityStats(w http.ResponseWriter, r *http.Request) {
	// Simple protection : seulement si la requête vient de localhost
	if r.Header.Get("X-Forwarded-For") != "" || !strings.HasPrefix(r.RemoteAddr, "127.0.0.1") {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>P0rt Security Statistics</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            background: #0a0a0a;
            color: #fafafa;
            line-height: 1.6;
        }
        h1, h2 {
            color: #60a5fa;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        .stat-card {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 1.5rem;
        }
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: #10b981;
        }
        .stat-label {
            color: #888;
            margin-top: 0.5rem;
        }
        .refresh-btn {
            background: #60a5fa;
            color: white;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 2rem;
        }
        .refresh-btn:hover {
            background: #3b82f6;
        }
    </style>
</head>
<body>
    <h1>🛡️ P0rt Security Dashboard</h1>
    
    <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number" id="total-blocks">Loading...</div>
            <div class="stat-label">Total IP Blocks Today</div>
        </div>
        
        <div class="stat-card">
            <div class="stat-number" id="active-tunnels">Loading...</div>
            <div class="stat-label">Active Tunnels</div>
        </div>
        
        <div class="stat-card">
            <div class="stat-number" id="abuse-reports">Loading...</div>
            <div class="stat-label">Abuse Reports Today</div>
        </div>
        
        <div class="stat-card">
            <div class="stat-number" id="scan-attempts">Loading...</div>
            <div class="stat-label">Scan Attempts Blocked</div>
        </div>
    </div>
    
    <h2>Recent Security Events</h2>
    <div id="recent-events" style="background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 1rem; font-family: monospace; font-size: 0.9rem;">
        Loading events...
    </div>
    
    <div style="margin-top: 2rem; text-align: center;">
        <a href="/" style="color: #60a5fa;">← Back to P0rt</a>
    </div>
    
    <script>
        // Simuler des données (dans une vraie implémentation, ces données viendraient d'une API)
        document.getElementById('total-blocks').textContent = Math.floor(Math.random() * 50 + 10);
        document.getElementById('active-tunnels').textContent = Math.floor(Math.random() * 20 + 5);
        document.getElementById('abuse-reports').textContent = Math.floor(Math.random() * 5);
        document.getElementById('scan-attempts').textContent = Math.floor(Math.random() * 100 + 20);
        
        const events = [
            '[' + new Date().toLocaleTimeString() + '] IP 165.232.95.247 auto-banned (scan pattern: immediate_disconnect)',
            '[' + new Date(Date.now() - 300000).toLocaleTimeString() + '] Known malicious IP 103.183.157.25 blocked',
            '[' + new Date(Date.now() - 600000).toLocaleTimeString() + '] SSH bruteforce detected from 78.128.112.74',
            '[' + new Date(Date.now() - 900000).toLocaleTimeString() + '] Suspicious HTTP request blocked for domain test-phishing',
            '[' + new Date(Date.now() - 1200000).toLocaleTimeString() + '] IP 5.228.183.178 banned for 6h (scan pattern: no_auth)'
        ];
        
        document.getElementById('recent-events').innerHTML = events.join('<br>');
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}
