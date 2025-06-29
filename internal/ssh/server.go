package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/p0rt/p0rt/internal/auth"
	"github.com/p0rt/p0rt/internal/metrics"
	"github.com/p0rt/p0rt/internal/security"
	"github.com/p0rt/p0rt/internal/stats"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	Domain     string
	Port       int
	Conn       ssh.Conn
	Channels   <-chan ssh.NewChannel
	Requests   <-chan *ssh.Request
	Key        string
	LogChannel chan string
	KeyAccess  *auth.KeyAccess // Store key access info
	SSHChannel ssh.Channel     // Reference to the SSH channel for direct messaging
}

type Server struct {
	config          *ssh.ServerConfig
	clients         map[string]*Client
	clientOps       chan func() // Canal pour opérations thread-safe sur clients
	port            string
	domainGenerator DomainGenerator
	tcpManager      TCPManager
	abuseMonitor    *security.AbuseMonitor
	baseDomain      string
	statsManager    *stats.Manager
	securityTracker security.SecurityTrackerInterface
	keyStore        auth.KeyStoreInterface // SSH key allowlist

	// Protection anti-bruteforce (legacy - will be replaced by SecurityTracker)
	failedAttempts map[string]int
	failedMutex    sync.RWMutex
	bannedIPs      map[string]time.Time

	// Tracking for banned domain connection attempts
	bannedDomainAttempts map[string]int // IP -> attempt count for banned domains
	bannedDomainMutex    sync.RWMutex

	// Track failed SSH sessions to prevent multi-key attempts from being counted as separate failures
	failedSessions map[string]time.Time // sessionID -> last failure time
	sessionMutex   sync.RWMutex
}

type DomainGenerator interface {
	Generate(key string) string
	GenerateRandom() string
}

type TCPManager interface {
	CreateForwarder(client *Client, bindAddr string, bindPort uint32) (int, error)
	Close(port int) error
}

func NewServer(port string, hostKey string, domainGen DomainGenerator, tcpManager TCPManager, baseDomain string) (*Server, error) {
	// Load key store
	keysFile := os.Getenv("P0RT_AUTHORIZED_KEYS")
	if keysFile == "" {
		keysFile = "authorized_keys.json"
	}

	statsManager := stats.NewManager()
	keyStore, err := auth.NewKeyStoreFromConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %w", err)
	}

	// Set access mode in stats based on key store configuration
	if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
		statsManager.SetAccessMode("open")
	} else {
		statsManager.SetAccessMode("restricted")
	}

	server := &Server{
		clients:              make(map[string]*Client),
		clientOps:            make(chan func(), 100),
		port:                 port,
		domainGenerator:      domainGen,
		tcpManager:           tcpManager,
		abuseMonitor:         security.NewAbuseMonitor(),
		baseDomain:           baseDomain,
		statsManager:         statsManager,
		securityTracker:      createSecurityTracker(),
		keyStore:             keyStore,
		failedAttempts:       make(map[string]int),
		bannedIPs:            make(map[string]time.Time),
		bannedDomainAttempts: make(map[string]int),
		failedSessions:       make(map[string]time.Time),
	}

	// Set IP protection function for security tracker
	server.securityTracker.SetValidConnectionsChecker(server.hasValidConnectionsFromIP)

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			clientIP := normalizeClientIP(conn.RemoteAddr().String())

			// Check if IP is banned using SecurityTracker (skip for private IPs)
			if !server.isPrivateIP(clientIP) {
				isBanned := server.securityTracker.IsBanned(clientIP)
				if isBanned {
					// Don't record additional security events for already banned IPs
					// This prevents cascading event accumulation
					metrics.RecordSSHConnection("banned")
					log.Printf("Banned IP attempted connection: %s (silently rejected)", clientIP)
					return nil, fmt.Errorf("IP banned")
				}
			}

			// Check if key is in allowlist
			allowed, keyAccess := server.keyStore.IsKeyAllowed(key)
			if !allowed {
				fingerprint := ssh.FingerprintSHA256(key)

				// Create session ID from IP + username + session start time pattern
				// This helps identify multiple key attempts from the same SSH session
				sessionID := fmt.Sprintf("%s-%s", clientIP, conn.User())

				log.Printf("Unauthorized key attempted connection: %s from %s (session: %s)", fingerprint, clientIP, sessionID)

				if !server.isPrivateIP(clientIP) {
					// Only record IP-based tracking if no valid connections from this IP exist
					if !server.hasValidConnectionsFromIP(clientIP) {
						// Check if we already recorded a failure for this session recently (within 30 seconds)
						server.sessionMutex.Lock()
						lastFailure, sessionExists := server.failedSessions[sessionID]
						shouldRecord := !sessionExists || time.Since(lastFailure) > 30*time.Second
						if shouldRecord {
							server.failedSessions[sessionID] = time.Now()
						}
						server.sessionMutex.Unlock()

						if shouldRecord {
							server.securityTracker.RecordEvent(security.EventAuthFailure, clientIP, map[string]string{
								"reason":      "unauthorized_key",
								"fingerprint": fingerprint,
								"session_id":  sessionID,
							})
							log.Printf("Recorded auth failure for session %s (first failure or > 30s since last)", sessionID)
						} else {
							log.Printf("Skipping auth failure recording for session %s (within 30s of last failure)", sessionID)
						}
					} else {
						log.Printf("Unauthorized key attempt from IP %s with valid active connections - reduced tracking", clientIP)
					}
				}
				metrics.RecordSSHConnection("failed")
				metrics.RecordSecurityEvent("unauthorized_key", "medium")
				return nil, fmt.Errorf("unauthorized key")
			}

			keyData := base64.StdEncoding.EncodeToString(key.Marshal())

			// Vérifier les limites de connexion pour cette clé SSH (skip for private IPs)
			keyHash := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
			if !server.abuseMonitor.CheckConnectionRate(keyHash) {
				if !server.isPrivateIP(clientIP) {
					server.securityTracker.RecordEvent(security.EventRateLimitHit, clientIP, map[string]string{
						"reason":   "connection_rate_limit",
						"key_hash": keyHash[:8],
					})
				}
				log.Printf("Connection rate limit exceeded for SSH key: %s", keyHash[:8])
				return nil, fmt.Errorf("connection rate limit exceeded")
			}

			// Log successful authentication with tier info
			tierInfo := "open"
			if keyAccess != nil {
				tierInfo = keyAccess.Tier
			}
			if os.Getenv("P0RT_VERBOSE") == "true" {
				log.Printf("Successful SSH authentication from %s (key: %s, tier: %s)", clientIP, keyHash[:8], tierInfo)
			}

			// Record successful SSH connection
			metrics.RecordSSHConnection("success")

			permissions := &ssh.Permissions{
				Extensions: map[string]string{
					"public-key": keyData,
					"key-hash":   keyHash,
				},
			}

			// Store tier info in permissions for later use
			if keyAccess != nil {
				permissions.Extensions["tier"] = keyAccess.Tier
				permissions.Extensions["key-comment"] = keyAccess.Comment
			}

			return permissions, nil
		},
		// Track authentication failures
		NoClientAuthCallback: func(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
			clientIP := normalizeClientIP(conn.RemoteAddr().String())

			// Skip tracking for private IPs
			if !server.isPrivateIP(clientIP) {
				// Only record IP-based tracking if no valid connections from this IP exist
				if !server.hasValidConnectionsFromIP(clientIP) {
					// Apply session-based tracking for no-auth attempts too
					sessionID := fmt.Sprintf("%s-%s", clientIP, conn.User())

					server.sessionMutex.Lock()
					lastFailure, sessionExists := server.failedSessions[sessionID]
					shouldRecord := !sessionExists || time.Since(lastFailure) > 30*time.Second
					if shouldRecord {
						server.failedSessions[sessionID] = time.Now()
					}
					server.sessionMutex.Unlock()

					if shouldRecord {
						server.securityTracker.RecordEvent(security.EventAuthFailure, clientIP, map[string]string{
							"reason":     "no_public_key",
							"user":       conn.User(),
							"session_id": sessionID,
						})
						log.Printf("🚨 Recorded no-auth failure for session %s (first failure or > 30s since last)", sessionID)
					} else {
						log.Printf("ℹ️ Skipping no-auth failure recording for session %s (within 30s of last failure)", sessionID)
					}
				} else {
					log.Printf("⚠️ No public key attempt from IP %s with valid active connections - reduced tracking", clientIP)
				}
			}

			return nil, fmt.Errorf("public key authentication required")
		},
	}

	var signer ssh.Signer

	if hostKey != "" {
		signer, err = ssh.ParsePrivateKey([]byte(hostKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key: %w", err)
		}
	} else {
		signer, err = loadOrGenerateHostKey()
		if err != nil {
			return nil, fmt.Errorf("failed to load or generate host key: %w", err)
		}
	}

	config.AddHostKey(signer)
	server.config = config

	// Démarrer le gestionnaire d'opérations clients
	go server.handleClientOps()

	// Démarrer le nettoyage périodique des IPs bannies
	go server.cleanupBannedIPs()

	// Démarrer le nettoyage périodique des sessions d'authentification échouées
	go server.cleanupFailedSessions()

	// Set SSH server reference in abuse report manager for IP unbanning
	server.abuseMonitor.GetReportManager().SetSSHServer(server)

	// Register global IP unban service for API and CLI access
	security.SetGlobalIPUnbanService(server)

	return server, nil
}

func (s *Server) handleClientOps() {
	for op := range s.clientOps {
		op()
	}
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %w", s.port, err)
	}
	defer listener.Close()

	log.Printf("SSH server listening on port %s", s.port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(netConn net.Conn) {
	clientIP := normalizeClientIP(netConn.RemoteAddr().String())

	// Skip security checks for private IPs (Docker internal, localhost, etc.)
	if s.isPrivateIP(clientIP) {
		// Private IPs are allowed without security tracking
	} else {
		// Vérifier si l'IP est bannie avant même d'essayer le handshake
		localBanned := s.isIPBanned(clientIP)
		trackerBanned := s.securityTracker.IsBanned(clientIP)

		if localBanned || trackerBanned {
			// Check if this IP has valid active connections before blocking
			if !s.hasValidConnectionsFromIP(clientIP) {
				log.Printf("Blocked banned IP: %s (local: %t, tracker: %t)", clientIP, localBanned, trackerBanned)
				s.securityTracker.RecordEvent(security.EventAuthFailure, clientIP, map[string]string{
					"reason": "banned_ip_connection_attempt",
				})
				netConn.Close()
				return
			} else {
				log.Printf("⚠️ Banned IP %s has valid active connections, allowing connection attempt", clientIP)
			}
		}
	}

	// Vérifier si l'IP est dans la liste noire connue (skip for private IPs)
	if !s.isPrivateIP(clientIP) && s.abuseMonitor.IsKnownMaliciousIP(clientIP) {
		log.Printf("Blocked known malicious IP: %s", clientIP)
		// Bannir immédiatement pour 24h
		s.failedMutex.Lock()
		s.bannedIPs[clientIP] = time.Now().Add(24 * time.Hour)
		s.failedMutex.Unlock()
		log.Printf("Known malicious IP %s auto-banned for 24h (blacklist)", clientIP)

		// Record in SecurityTracker
		s.securityTracker.RecordEvent(security.EventAbuseReport, clientIP, map[string]string{
			"reason": "known_malicious_ip",
			"action": "blocked_and_banned_24h",
			"type":   "blacklist",
		})

		netConn.Close()
		return
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.config)
	if err != nil {
		// Skip error tracking for private IPs
		if !s.isPrivateIP(clientIP) {
			// Incrémenter les tentatives échouées
			s.recordFailedAttempt(clientIP)

			// Record failed connection metric
			metrics.RecordSSHConnection("failed")

			// Log détaillé pour différents types d'erreurs et détection de scans
			if strings.Contains(err.Error(), "no auth passed yet") {
				log.Printf("Auth failure from %s: No valid authentication", clientIP)
				// Pattern de scan : connexion sans tentative d'auth
				s.detectScanPattern(clientIP, "no_auth")
				s.securityTracker.RecordEvent(security.EventPortScanning, clientIP, map[string]string{
					"pattern": "no_auth",
					"error":   err.Error(),
				})
			} else if strings.Contains(err.Error(), "reason 11") {
				log.Printf("Scan attempt from %s: Client disconnected immediately", clientIP)
				// Pattern de scan : connexion puis déconnexion immédiate
				s.detectScanPattern(clientIP, "immediate_disconnect")
				s.securityTracker.RecordEvent(security.EventPortScanning, clientIP, map[string]string{
					"pattern": "immediate_disconnect",
					"error":   err.Error(),
				})
			} else if strings.Contains(err.Error(), "EOF") {
				log.Printf("Connection dropped from %s: EOF", clientIP)
				// Pattern de scan : connexion puis abandon
				s.detectScanPattern(clientIP, "connection_drop")
				s.securityTracker.RecordEvent(security.EventPortScanning, clientIP, map[string]string{
					"pattern": "connection_drop",
					"error":   "EOF",
				})
			} else {
				log.Printf("Failed handshake from %s: %v", clientIP, err)
				s.securityTracker.RecordEvent(security.EventAuthFailure, clientIP, map[string]string{
					"error": err.Error(),
				})
			}
		}
		return
	}

	// Réinitialiser les tentatives échouées en cas de succès
	s.resetFailedAttempts(clientIP)

	publicKey := sshConn.Permissions.Extensions["public-key"]

	// Create client with key access info
	client := &Client{
		Conn:       sshConn,
		Channels:   chans,
		Requests:   reqs,
		Key:        publicKey,
		LogChannel: make(chan string, 100),
	}

	// Get key access info from permissions
	if _, ok := sshConn.Permissions.Extensions["tier"]; ok {
		// Parse the public key to get fingerprint
		keyData, err := base64.StdEncoding.DecodeString(publicKey)
		if err == nil {
			pubKey, err := ssh.ParsePublicKey(keyData)
			if err == nil {
				fingerprint := ssh.FingerprintSHA256(pubKey)
				keys := s.keyStore.ListKeys()
				for _, access := range keys {
					if access.Fingerprint == fingerprint {
						client.KeyAccess = access
						break
					}
				}
			}
		}
	}

	// S'assurer que le client est supprimé à la déconnexion
	defer func() {
		log.Printf("Cleaning up connection for domain: %s", client.Domain)

		// Fermer la connexion SSH
		if sshConn != nil {
			sshConn.Close()
		}

		// Nettoyer le client
		if client.Domain != "" {
			s.removeClient(client.Domain)
			log.Printf("Removed client for domain: %s", client.Domain)
		}

		// Backup: nettoyer le port TCP
		if client.Port > 0 {
			err := s.tcpManager.Close(client.Port)
			if err != nil {
				log.Printf("Error closing TCP port %d: %v", client.Port, err)
			}
		}

		// Update active connections metric
		s.updateActiveConnectionsMetric()
		log.Printf("Connection cleanup completed for: %s", client.Domain)
	}()

	// Détecter la déconnexion via Wait()
	go func() {
		err := sshConn.Wait()
		if err != nil {
			log.Printf("SSH connection closed for domain %s: %v", client.Domain, err)
		} else {
			log.Printf("SSH connection gracefully closed for domain: %s", client.Domain)
		}
	}()

	go s.handleRequests(client)
	s.handleChannels(client)
}

func (s *Server) handleRequests(client *Client) {
	for req := range client.Requests {
		switch req.Type {
		case "tcpip-forward":
			s.handleTCPForward(client, req)
		case "cancel-tcpip-forward":
			req.Reply(true, nil)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (s *Server) handleTCPForward(client *Client, req *ssh.Request) {
	type forwardRequest struct {
		BindAddr string
		BindPort uint32
	}

	var forward forwardRequest
	if err := ssh.Unmarshal(req.Payload, &forward); err != nil {
		req.Reply(false, nil)
		return
	}

	// Vérifier si l'adresse contient un sous-domaine personnalisé
	// Format: "subdomain:port" ou juste "port" pour 443
	var customDomain string
	bindAddr := forward.BindAddr

	// Si l'adresse n'est pas vide et ne ressemble pas à une IP/hostname standard
	if bindAddr != "" && bindAddr != "0.0.0.0" && bindAddr != "localhost" && bindAddr != "127.0.0.1" {
		// Diviser sur ':' pour extraire le sous-domaine potentiel
		parts := strings.Split(bindAddr, ":")
		if len(parts) > 1 {
			// Format "subdomain:port" - extraire le sous-domaine
			customDomain = parts[0]
			// Le port est déjà dans forward.BindPort
		} else if forward.BindPort != 443 {
			// Si pas de ':' mais port différent de 443, considérer bindAddr comme sous-domaine
			customDomain = bindAddr
		}
	}

	// Accepter différents ports pour plus de flexibilité, pas seulement 443
	if forward.BindPort != 443 && forward.BindPort != 80 && forward.BindPort != 8080 && customDomain == "" {
		req.Reply(false, nil)
		return
	}

	localPort, err := s.tcpManager.CreateForwarder(client, forward.BindAddr, forward.BindPort)
	if err != nil {
		log.Printf("Failed to create TCP forwarder: %v", err)
		req.Reply(false, nil)
		return
	}

	client.Port = localPort

	type forwardResponse struct {
		BoundPort uint32
	}

	response := forwardResponse{BoundPort: uint32(localPort)}
	req.Reply(true, ssh.Marshal(&response))
}

func (s *Server) handleChannels(client *Client) {
	for newChannel := range client.Channels {
		switch newChannel.ChannelType() {
		case "session":
			go s.handleSession(client, newChannel)
		case "direct-tcpip":
			go s.handleDirectTCPIP(newChannel)
		default:
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func (s *Server) handleSession(client *Client, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel: %v", err)
		return
	}
	defer channel.Close()

	var domain string
	var reservedDomain string

	for req := range requests {
		switch req.Type {
		case "env":
			type envRequest struct {
				Name  string
				Value string
			}
			var env envRequest
			if err := ssh.Unmarshal(req.Payload, &env); err == nil {
				if env.Name == "LC_DOMAIN" {
					reservedDomain = env.Value
				}
			}
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "shell", "pty-req":
			if req.WantReply {
				req.Reply(true, nil)
			}

			if req.Type == "shell" {
				// Assigner le domaine si pas encore fait
				if client.Domain == "" {
					// Store SSH channel reference for direct messaging
					client.SSHChannel = channel

					// Use reserved domain if provided, otherwise generate new one
					if reservedDomain != "" {
						domain = reservedDomain
					} else {
						domain = s.domainGenerator.Generate(client.Key)
					}

					// For ban checking, use the full domain name (generated domain needs base domain appended)
					fullDomainForBanCheck := domain + "." + s.baseDomain

					// Check if domain is banned via abuse reports
					isDomainBanned := s.abuseMonitor.GetReportManager().IsDomainBanned(fullDomainForBanCheck)
					log.Printf("🚫 Domain ban check for '%s' (full: '%s'): banned = %t", domain, fullDomainForBanCheck, isDomainBanned)
					if isDomainBanned {
						// Get client IP for tracking attempts
						clientIP := normalizeClientIP(client.Conn.RemoteAddr().String())

						// Track banned domain connection attempts
						s.bannedDomainMutex.Lock()
						s.bannedDomainAttempts[clientIP]++
						attempts := s.bannedDomainAttempts[clientIP]
						s.bannedDomainMutex.Unlock()

						log.Printf("Domain %s is banned, connection attempt #%d from IP %s", domain, attempts, clientIP)

						// If more than 5 attempts, ban the IP
						if attempts > 5 {
							s.recordFailedAttempt(clientIP)
							log.Printf("IP %s banned after %d attempts to access banned domain %s", clientIP, attempts, domain)
							channel.Write([]byte("\r\n❌ Error: Your IP has been banned for repeated attempts to access banned domains.\r\n"))
							channel.Write([]byte("Contact support if you believe this is an error.\r\n"))
						} else {
							// Just reject the domain access with helpful message
							channel.Write([]byte(fmt.Sprintf("\r\n❌ Error: Domain '%s' has been banned due to abuse reports.\r\n", fullDomainForBanCheck)))
							channel.Write([]byte("This domain is currently suspended.\r\n"))
							channel.Write([]byte("Contact support if you believe this is an error.\r\n"))
							channel.Write([]byte(fmt.Sprintf("⚠️  Warning: %d/5 attempts. Further attempts may result in IP ban.\r\n", attempts)))
						}

						channel.Close()
						return
					}

					client.Domain = domain

					// Ajout via canal (lock-free)
					done := make(chan bool)
					s.clientOps <- func() {
						s.clients[domain] = client
						done <- true
					}
					<-done

					// Get client IP and fingerprint
					clientIP := normalizeClientIP(client.Conn.RemoteAddr().String())

					// Get fingerprint from public key
					fingerprint := ""
					if keyData, err := base64.StdEncoding.DecodeString(client.Key); err == nil {
						if pubKey, err := ssh.ParsePublicKey(keyData); err == nil {
							fingerprint = ssh.FingerprintSHA256(pubKey)
						}
					}

					// Record tunnel connection statistics with details
					s.statsManager.TunnelConnectedWithDetails(domain, clientIP, fingerprint)

					log.Printf("Client connected: %s -> https://%s.p0rt.xyz (IP: %s)", domain, domain, clientIP)
					s.updateStats()
				} else {
					domain = client.Domain
				}

				// Message de bienvenue avec escape sequences pour forcer un formatage correct
				channel.Write([]byte("\033[2J\033[H")) // Clear screen and move cursor to home
				channel.Write([]byte("P0rt Tunnel Connected\r\n"))

				// Show tier information if available
				if client.KeyAccess != nil {
					tierMsg := fmt.Sprintf("Access Tier: %s", strings.ToUpper(client.KeyAccess.Tier))
					if client.KeyAccess.Comment != "" {
						tierMsg += fmt.Sprintf(" (%s)", client.KeyAccess.Comment)
					}
					channel.Write([]byte(fmt.Sprintf("%s\r\n", tierMsg)))
				}

				// Generate tunnel URL using standard p0rt domain
				tunnelURL := fmt.Sprintf("https://%s.%s", domain, s.baseDomain)

				channel.Write([]byte(fmt.Sprintf("Your tunnel: %s\r\n", tunnelURL)))
				channel.Write([]byte("\r\nConnections:\r\n"))

				// Démarrer le monitoring des connexions
				go s.monitorConnections(client, channel)

				// Démarrer le heartbeat pour maintenir la connexion active
				go s.keepConnectionAlive(client, domain)

				// Garder le canal ouvert et détecter la fermeture
				go func() {
					io.Copy(io.Discard, channel)
					// Quand le canal se ferme, fermer le canal de log
					close(client.LogChannel)
					// Le nettoyage du client sera fait dans le defer de handleConnection
				}()
			}

		case "exec":
			if req.WantReply {
				req.Reply(true, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (s *Server) handleDirectTCPIP(newChannel ssh.NewChannel) {
	type directTCPIP struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}

	var direct directTCPIP
	if err := ssh.Unmarshal(newChannel.ExtraData(), &direct); err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "failed to parse request")
		return
	}

	channel, _, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", direct.DestAddr, direct.DestPort))
	if err != nil {
		return
	}
	defer conn.Close()

	go io.Copy(channel, conn)
	io.Copy(conn, channel)
}

func (s *Server) GetClient(domain string) *Client {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return nil
	}

	subdomain := parts[0]
	resultChan := make(chan *Client)

	s.clientOps <- func() {
		client := s.clients[subdomain]
		resultChan <- client
	}

	return <-resultChan
}

func (s *Server) removeClient(domain string) {
	if domain == "" {
		return
	}

	done := make(chan bool)

	s.clientOps <- func() {
		if client, exists := s.clients[domain]; exists {
			if client.Port > 0 {
				if err := s.tcpManager.Close(client.Port); err != nil {
					log.Printf("Error closing TCP forwarder for %s: %v", domain, err)
				}
			}
			delete(s.clients, domain)

			// Record tunnel disconnection statistics
			s.statsManager.TunnelDisconnected(domain)

			log.Printf("Client disconnected: %s", domain)
		}
		done <- true
	}

	<-done
	s.updateStats()
}

func (s *Server) updateStats() {
	countChan := make(chan int)

	s.clientOps <- func() {
		countChan <- len(s.clients)
	}

	count := <-countChan
	stats := fmt.Sprintf(`{"connected_clients": %d}`, count)
	os.WriteFile("stats.json", []byte(stats), 0644)
}

func (s *Server) updateActiveConnectionsMetric() {
	countChan := make(chan int)
	tunnelsChan := make(chan int)

	s.clientOps <- func() {
		totalClients := len(s.clients)
		activeTunnels := 0
		for _, client := range s.clients {
			if client.Domain != "" && client.Port > 0 {
				activeTunnels++
			}
		}
		countChan <- totalClients
		tunnelsChan <- activeTunnels
	}

	sshConnections := <-countChan
	tunnels := <-tunnelsChan

	// Update Prometheus metrics
	metrics.UpdateActiveConnections(sshConnections, tunnels, 0) // WebSocket count handled separately
}

// GetActiveConnectionCount returns the number of active SSH connections
func (s *Server) GetActiveConnectionCount() int {
	countChan := make(chan int)

	s.clientOps <- func() {
		countChan <- len(s.clients)
	}

	return <-countChan
}

// GetActiveTunnelCount returns the number of active tunnels
func (s *Server) GetActiveTunnelCount() int {
	countChan := make(chan int)

	s.clientOps <- func() {
		activeTunnels := 0
		for _, client := range s.clients {
			if client.Domain != "" && client.Port > 0 {
				activeTunnels++
			}
		}
		countChan <- activeTunnels
	}

	return <-countChan
}

// NotifyDomain sends a general notification to SSH clients for their domain
func (s *Server) NotifyDomain(domain, message string) {
	done := make(chan bool)

	s.clientOps <- func() {
		if client, exists := s.clients[domain]; exists {
			// Send simple notification via LogChannel
			select {
			case client.LogChannel <- message:
				// Notification sent successfully
			default:
				// LogChannel full, skip notification
			}
		}
		done <- true
	}

	<-done
}

// NotifyDomainBanned notifies SSH clients if their domain has been banned
// TODO: Rename to NotifyDomain and accept message/type parameters
func (s *Server) NotifyDomainBanned(domain string) {

	done := make(chan bool)

	s.clientOps <- func() {
		// Debug: List all current clients
		log.Printf("📋 Current connected clients:")
		clientsFound := 0
		for clientDomain, client := range s.clients {
			clientsFound++
			log.Printf("  - Domain: '%s', Port: %d, HasSSHChannel: %t, HasLogChannel: %t",
				clientDomain, client.Port, client.SSHChannel != nil, client.LogChannel != nil)
		}

		if clientsFound == 0 {
		}

		if client, exists := s.clients[domain]; exists {
			// Create notification messages for LogChannel
			// These will be displayed with timestamp by monitorConnections
			notifications := []string{
				strings.Repeat("=", 60),
				"🚫 NOTIFICATION - IMMEDIATE ACTION REQUIRED",
				strings.Repeat("=", 60),
				fmt.Sprintf("Domain: %s.%s", domain, s.baseDomain),
				"Reason: Abuse reports received and processed",
				"Action: Tunnel will be terminated in 5 seconds",
				"",
				"If you believe this is an error:",
				"- Contact support immediately",
				"- Provide your SSH key fingerprint",
				"- Include details about legitimate use",
				strings.Repeat("=", 60),
			}

			// For other delivery methods, create formatted message
			banMessage := "\r\n" + strings.Join(notifications, "\r\n") + "\r\n"

			// Try to send via SSH channel directly first (more reliable)
			if client.SSHChannel != nil {
				_, err := client.SSHChannel.Write([]byte(banMessage))
				if err == nil {
					log.Printf("✅ Sent ban notification directly to SSH channel for client %s", domain)
				} else {
					log.Printf("❌ Failed to send direct SSH notification for client %s: %v", domain, err)
				}
			} else {
				log.Printf("⚠️ No SSH channel available for client %s (client may not have requested a shell)", domain)
			}

			// Try to send global request as alternative notification method
			if client.Conn != nil {
				// Send a global request that the client can handle
				sent, _, err := client.Conn.SendRequest("notification@p0rt.xyz", false, []byte(banMessage))
				if err == nil && sent {
					log.Printf("✅ Sent notification via global request for client %s", domain)
				} else if err != nil {
					log.Printf("❌ Failed to send global request notification: %v", err)
				}
			}

			// Try to open a new channel for notification if no shell channel exists
			if client.SSHChannel == nil && client.Conn != nil {
				// Try to open a session channel for notification
				channel, _, err := client.Conn.OpenChannel("session", nil)
				if err == nil {
					defer channel.Close()

					// Send the notification message
					_, writeErr := channel.Write([]byte(banMessage))
					if writeErr == nil {
						log.Printf("✅ Sent notification via new session channel for client %s", domain)
					} else {
						log.Printf("❌ Failed to write to new session channel: %v", writeErr)
					}
				} else {
					log.Printf("❌ Failed to open session channel for notification: %v", err)
				}
			}

			// Send via LogChannel - this works since logs are displayed to the user
			// Send each line separately so they appear properly formatted
			sentCount := 0
			for _, line := range notifications {
				select {
				case client.LogChannel <- line:
					sentCount++
				default:
					log.Printf("⚠️ LogChannel full for client %s after %d lines", domain, sentCount)
					break
				}
			}
			if sentCount > 0 {
				log.Printf("📝 Sent %d lines of notification to LogChannel for client %s", sentCount, domain)
			}

			// Close the connection after notification
			go func() {
				time.Sleep(5 * time.Second) // Give time for message to be sent
				if client.SSHChannel != nil {
					client.SSHChannel.Close()
				}
				client.Conn.Close()
				log.Printf("🔌 Closed connection for banned domain %s", domain)
			}()
		} else {
			log.Printf("❌ No client found for domain '%s'", domain)
		}
		done <- true
	}

	<-done
}

const hostKeyFile = "ssh_host_key"

func loadOrGenerateHostKey() (ssh.Signer, error) {
	// Essayer de charger la clé existante
	if keyData, err := os.ReadFile(hostKeyFile); err == nil {
		signer, err := ssh.ParsePrivateKey(keyData)
		if err == nil {
			log.Printf("Loaded existing SSH host key from %s", hostKeyFile)
			return signer, nil
		}
		log.Printf("Failed to parse existing host key: %v", err)
	}

	// Générer une nouvelle clé
	log.Printf("Generating new SSH host key...")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	keyData := pem.EncodeToMemory(privateKeyPEM)

	// Sauvegarder la clé
	if err := os.WriteFile(hostKeyFile, keyData, 0600); err != nil {
		log.Printf("Warning: Failed to save host key to %s: %v", hostKeyFile, err)
	} else {
		log.Printf("Saved SSH host key to %s", hostKeyFile)
	}

	return ssh.ParsePrivateKey(keyData)
}

func (s *Server) monitorConnections(client *Client, channel ssh.Channel) {
	for logMsg := range client.LogChannel {
		timestamp := time.Now().Format("15:04:05")
		formattedMsg := fmt.Sprintf("[%s] %s\r\n", timestamp, logMsg)
		channel.Write([]byte(formattedMsg))
	}
}

// LogConnection envoie un log de connexion au client SSH
func (s *Server) LogConnection(domain, clientIP, method, requestURL string) {
	clientChan := make(chan *Client)

	s.clientOps <- func() {
		client := s.clients[domain]
		clientChan <- client
	}

	client := <-clientChan
	if client != nil && client.LogChannel != nil {
		// Create structured log with UTC timestamp, source IP, HTTP method, and path
		timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		logMsg := fmt.Sprintf("%s %s %s %s", timestamp, clientIP, method, requestURL)
		select {
		case client.LogChannel <- logMsg:
		default:
			// Canal plein, ignorer le message
		}
	}
}

// GetStats returns the statistics manager
func (s *Server) GetStats() *stats.Manager {
	return s.statsManager
}

// RecordHTTPRequest records HTTP request statistics
func (s *Server) RecordHTTPRequest(domain string, bytesIn, bytesOut int64) {
	s.statsManager.HTTPRequest(domain, bytesIn, bytesOut)
}

// RecordWebSocketUpgrade records WebSocket upgrade statistics
func (s *Server) RecordWebSocketUpgrade(domain string) {
	s.statsManager.WebSocketUpgrade(domain)
}

// keepConnectionAlive sends periodic heartbeats to keep the connection marked as active
func (s *Server) keepConnectionAlive(client *Client, domain string) {
	ticker := time.NewTicker(5 * time.Minute) // Send heartbeat every 5 minutes
	defer ticker.Stop()

	// Canal pour détecter la déconnexion SSH
	done := make(chan struct{})

	// Goroutine pour surveiller la déconnexion SSH
	go func() {
		defer close(done)
		err := client.Conn.Wait()
		if err != nil {
			log.Printf("SSH connection closed for %s: %v", domain, err)
		}
	}()

	for {
		select {
		case <-ticker.C:
			// Check if client is still connected
			if client.Conn == nil {
				log.Printf("Client connection is nil for %s, stopping heartbeat", domain)
				return
			}

			// Test de ping SSH pour vérifier la connectivité
			_, _, err := client.Conn.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				log.Printf("SSH keepalive failed for %s: %v", domain, err)
				return
			}

			// Update last activity time to prevent cleanup
			s.statsManager.KeepConnectionAlive(domain)
			log.Printf("Heartbeat sent for connection: %s", domain)

		case <-done:
			// Connexion SSH fermée
			log.Printf("SSH connection closed for %s, stopping heartbeat", domain)
			return
		}
	}
}

// Protection anti-bruteforce
const (
	maxFailedAttempts = 5
	banDuration       = 15 * time.Minute
)

func (s *Server) isIPBanned(ip string) bool {
	s.failedMutex.RLock()
	defer s.failedMutex.RUnlock()

	if banTime, exists := s.bannedIPs[ip]; exists {
		if time.Since(banTime) < banDuration {
			return true
		}
		// Ban expiré, le supprimer
		delete(s.bannedIPs, ip)
	}
	return false
}

// hasValidConnectionsFromIP checks if an IP has active valid connections
func (s *Server) hasValidConnectionsFromIP(ip string) bool {
	hasValid := false
	done := make(chan bool)

	s.clientOps <- func() {
		for _, client := range s.clients {
			if client.Conn != nil {
				clientIP := normalizeClientIP(client.Conn.RemoteAddr().String())
				if clientIP == ip {
					hasValid = true
					break
				}
			}
		}
		done <- true
	}

	<-done
	return hasValid
}

// UnbanIP removes an IP from the banned IPs list
func (s *Server) UnbanIP(ip string) {
	s.failedMutex.Lock()
	defer s.failedMutex.Unlock()

	delete(s.bannedIPs, ip)
	delete(s.failedAttempts, ip)

	// Also clear banned domain attempts for this IP
	s.bannedDomainMutex.Lock()
	delete(s.bannedDomainAttempts, ip)
	s.bannedDomainMutex.Unlock()

	log.Printf("IP %s has been unbanned and banned domain attempts cleared", ip)
}

func (s *Server) recordFailedAttempt(ip string) {
	// Skip tracking for private IPs
	if s.isPrivateIP(ip) {
		return
	}

	// Skip tracking if IP has valid active connections
	if s.hasValidConnectionsFromIP(ip) {
		log.Printf("Failed attempt from IP %s with valid active connections - skipping ban tracking", ip)
		return
	}

	s.failedMutex.Lock()
	defer s.failedMutex.Unlock()

	s.failedAttempts[ip]++
	attempts := s.failedAttempts[ip]

	// Bannissement progressif : 3 tentatives = 15min, 5 tentatives = 1h, 10+ tentatives = 24h
	if attempts >= 3 {
		banDuration := 15 * time.Minute
		if attempts >= 5 {
			banDuration = 1 * time.Hour
		}
		if attempts >= 10 {
			banDuration = 24 * time.Hour
		}

		s.bannedIPs[ip] = time.Now().Add(banDuration)
		delete(s.failedAttempts, ip)
		log.Printf("IP %s banned for %v after %d failed attempts", ip, banDuration, attempts)

		// Reporter à l'AbuseMonitor pour tracking
		s.abuseMonitor.ReportAbuse("ssh-bruteforce", ip, fmt.Sprintf("SSH bruteforce: %d attempts", attempts))

		// Also report to SecurityTracker for unified tracking
		s.securityTracker.RecordEvent(security.EventBruteForce, ip, map[string]string{
			"attempts": fmt.Sprintf("%d", attempts),
			"action":   "banned",
			"duration": banDuration.String(),
		})
	} else {
		log.Printf("Failed attempt %d/3 from %s", attempts, ip)
	}
}

func (s *Server) resetFailedAttempts(ip string) {
	s.failedMutex.Lock()
	defer s.failedMutex.Unlock()

	delete(s.failedAttempts, ip)
}

func (s *Server) detectScanPattern(ip, pattern string) {
	// Skip scan detection for private IPs
	if s.isPrivateIP(ip) {
		return
	}

	// Skip banning if IP has valid active connections
	if s.hasValidConnectionsFromIP(ip) {
		log.Printf("Scan pattern detected from IP %s with valid active connections - skipping ban (pattern: %s)", ip, pattern)
		return
	}

	// Les patterns de scan automatique sont souvent identifiables
	// et peuvent justifier un bannissement immédiat plus long
	scanPatterns := []string{"no_auth", "immediate_disconnect", "connection_drop"}

	s.failedMutex.Lock()
	defer s.failedMutex.Unlock()

	// Si c'est un pattern de scan connu, bannir immédiatement pour 6h
	for _, scanPattern := range scanPatterns {
		if pattern == scanPattern {
			s.bannedIPs[ip] = time.Now().Add(6 * time.Hour)
			delete(s.failedAttempts, ip)
			log.Printf("IP %s auto-banned for 6h (scan pattern: %s)", ip, pattern)

			// Log the security event (already tracked by SecurityTracker below)

			// Also report to SecurityTracker with abuse report
			s.securityTracker.RecordEvent(security.EventAbuseReport, ip, map[string]string{
				"pattern": pattern,
				"action":  "auto_banned_6h",
				"type":    "ssh_scan",
			})
			return
		}
	}
}

func (s *Server) cleanupBannedIPs() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.failedMutex.Lock()
		now := time.Now()
		for ip, banUntil := range s.bannedIPs {
			if now.After(banUntil) {
				delete(s.bannedIPs, ip)
				log.Printf("IP %s unbanned", ip)
			}
		}
		s.failedMutex.Unlock()
	}
}

// cleanupFailedSessions removes old failed session entries (cleanup every 5 minutes, remove entries older than 1 hour)
func (s *Server) cleanupFailedSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.sessionMutex.Lock()
		now := time.Now()
		cleaned := 0
		for sessionID, lastFailure := range s.failedSessions {
			if now.Sub(lastFailure) > 1*time.Hour {
				delete(s.failedSessions, sessionID)
				cleaned++
			}
		}
		if cleaned > 0 {
			log.Printf("Cleaned up %d expired failed session entries", cleaned)
		}
		s.sessionMutex.Unlock()
	}
}

func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return ssh.ParsePrivateKey(pem.EncodeToMemory(privateKeyPEM))
}

func (s *Server) ForwardConnection(client *Client, srcAddr string, srcPort uint32, channel ssh.Channel) error {
	destPort := strconv.Itoa(client.Port)
	conn, err := net.Dial("tcp", "localhost:"+destPort)
	if err != nil {
		return err
	}
	defer conn.Close()

	go io.Copy(channel, conn)
	io.Copy(conn, channel)
	return nil
}

// GetSecurityStats returns security statistics from the tracker
func (s *Server) GetSecurityStats() security.SecurityStats {
	return s.securityTracker.GetSecurityStats()
}

// GetBannedIPs returns all currently banned IP addresses
func (s *Server) GetBannedIPs() []security.BannedIP {
	return s.securityTracker.GetBannedIPs()
}

// BanIP manually bans an IP address
func (s *Server) BanIP(ip, reason string, duration time.Duration) {
	s.securityTracker.BanIP(ip, reason, duration)
}

// UnbanIPFromTracker removes a ban on an IP address via security tracker
func (s *Server) UnbanIPFromTracker(ip string) {
	s.securityTracker.UnbanIP(ip)
}

// RecordSecurityEvent records a security event
func (s *Server) RecordSecurityEvent(eventType security.EventType, ip string, details map[string]string) {
	s.securityTracker.RecordEvent(eventType, ip, details)
}

// isPrivateIP checks if an IP is private/local (Docker, localhost, RFC1918)
func (s *Server) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return parsedIP.IsLoopback() || parsedIP.IsPrivate()
}

// normalizeClientIP extracts and normalizes IP from network address
func normalizeClientIP(addr string) string {
	// Properly extract IP from "host:port" format (works for both IPv4 and IPv6)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}

	// Remove brackets from IPv6 addresses: [2001:db8::1] -> 2001:db8::1
	if len(addr) > 2 && addr[0] == '[' && addr[len(addr)-1] == ']' {
		return addr[1 : len(addr)-1]
	}
	return addr
}

// createSecurityTracker creates a security tracker based on environment configuration
func createSecurityTracker() security.SecurityTrackerInterface {
	// Check if Redis URL is available
	redisURL := security.GetRedisURLFromEnv()
	if redisURL != "" {
		// Try Redis first
		tracker, err := security.NewSecurityTrackerFromConfig("redis", "", redisURL, os.Getenv("REDIS_PASSWORD"), getRedisDB())
		if err != nil {
			log.Printf("Failed to create Redis security tracker, falling back to JSON: %v", err)
		} else {
			return tracker
		}
	}

	// Fallback to JSON storage
	return security.NewSecurityTracker("./data/security")
}

// getRedisDB gets Redis DB from environment
func getRedisDB() int {
	if dbStr := os.Getenv("REDIS_DB"); dbStr != "" {
		if db, err := strconv.Atoi(dbStr); err == nil {
			return db
		}
	}
	return 0
}
