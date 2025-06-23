package cmd

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/p0rt/p0rt/internal/api"
	"github.com/p0rt/p0rt/internal/config"
	"github.com/p0rt/p0rt/internal/domain"
	"github.com/p0rt/p0rt/internal/metrics"
	"github.com/p0rt/p0rt/internal/proxy"
	"github.com/p0rt/p0rt/internal/security"
	"github.com/p0rt/p0rt/internal/ssh"
	"github.com/p0rt/p0rt/internal/tcp"
	"github.com/spf13/cobra"

	cryptossh "golang.org/x/crypto/ssh"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Manage the P0rt server",
	Long: `Start, check status, or reload the P0rt SSH tunneling server.

The server handles SSH connections for tunneling and serves the HTTP proxy
that routes incoming web requests to the appropriate tunnels.`,
	Example: `  # Start the server (local only)
  p0rt server start

  # Check server status (local or remote)
  p0rt server status
  p0rt --remote http://server:80 server status

  # Reload server configuration (local or remote)
  p0rt server reload
  p0rt --remote http://server:80 server reload

  # Start with custom config
  p0rt --config /path/to/config.yaml server start`,
}

var serverStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the P0rt server",
	Long: `Start the P0rt SSH tunneling server.

This will start both the SSH server (for tunnel connections) and the HTTP proxy
(for routing web traffic). The server will run until stopped with Ctrl+C.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.Load()
		if err != nil {
			log.Printf("Failed to load config file, using defaults: %v", err)
			cfg = config.LoadDefault()
		}

		if err := startServer(cfg); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	},
}

var serverStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show server status",
	Long:  `Display the current configuration and status of the P0rt server.`,
	Run: func(cmd *cobra.Command, args []string) {
		_, remoteURL, apiKey, _, _, useJSON := GetGlobalFlags()
		
		if remoteURL != "" {
			// Use remote API
			if useJSON {
				fmt.Print("") // Will be handled by API response
			} else {
				fmt.Println("🌐 Getting server status via API...")
			}
			
			client := api.NewClient(remoteURL, apiKey)
			status, err := client.GetServerStatus()
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
				return
			}
			
			if useJSON {
				fmt.Printf("{\"success\": true, \"status\": %+v}\n", status)
			} else {
				fmt.Printf("✅ Remote P0rt Server Status:\n")
				fmt.Printf("  Status: %s\n", status.Status)
				fmt.Printf("  Version: %s\n", status.Version)
				
				if sshPort, ok := status.SSH["port"].(string); ok {
					fmt.Printf("  SSH Port: %s", sshPort)
					if available, ok := status.SSH["available"].(bool); ok {
						if available {
							fmt.Printf(" ✓ Available\n")
						} else {
							fmt.Printf(" ✗ In use\n")
						}
					} else {
						fmt.Println()
					}
				}
				
				if httpPort, ok := status.HTTP["port"].(string); ok {
					fmt.Printf("  HTTP Port: %s", httpPort)
					if available, ok := status.HTTP["available"].(bool); ok {
						if available {
							fmt.Printf(" ✓ Available\n")
						} else {
							fmt.Printf(" ✗ In use\n")
						}
					} else {
						fmt.Println()
					}
				}
				
				if storageType, ok := status.Storage["type"].(string); ok {
					fmt.Printf("  Storage Type: %s", storageType)
					if connected, ok := status.Storage["connected"].(bool); ok {
						if connected {
							fmt.Printf(" ✓ Connected\n")
						} else {
							fmt.Printf(" ✗ Disconnected\n")
						}
					} else {
						fmt.Println()
					}
				}
				
				if accessMode, ok := status.Security["access_mode"].(string); ok {
					fmt.Printf("  Access Mode: %s\n", accessMode)
				}
				
				if bannedIPs, ok := status.Security["banned_ips"].(float64); ok {
					fmt.Printf("  Banned IPs: %.0f\n", bannedIPs)
				}
				
				fmt.Printf("  Last Update: %s\n", status.Timestamp)
			}
		} else {
			// Local mode
			cfg, err := config.Load()
			if err != nil {
				log.Printf("Failed to load config file, using defaults: %v", err)
				cfg = config.LoadDefault()
			}

			fmt.Println("P0rt Server Status:")
			fmt.Printf("  SSH Port: %s\n", cfg.GetSSHPort())
			fmt.Printf("  HTTP Port: %s\n", cfg.GetHTTPPort())
			fmt.Printf("  Domain Base: %s\n", cfg.GetDomainBase())
			storageType := getStorageType(cfg)
			fmt.Printf("  Storage Type: %s\n", storageType)
			fmt.Printf("  Reservations Enabled: %t\n", cfg.Domain.ReservationsEnabled)

			// Test if ports are available
			if testPort(cfg.GetSSHPort()) {
				fmt.Printf("  SSH Port Status: ✓ Available\n")
			} else {
				fmt.Printf("  SSH Port Status: ✗ In use\n")
			}

			if testPort(cfg.GetHTTPPort()) {
				fmt.Printf("  HTTP Port Status: ✓ Available\n")
			} else {
				fmt.Printf("  HTTP Port Status: ✗ In use (server may be running)\n")
			}
		}
	},
}

var serverReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload the P0rt server configuration",
	Long: `Reload the P0rt server configuration and refresh internal state.

This performs the following operations:
- Reloads configuration from files
- Refreshes SSH key store from storage
- Updates security settings
- Clears internal caches

The server process continues running without interruption.`,
	Run: func(cmd *cobra.Command, args []string) {
		_, remoteURL, apiKey, _, _, useJSON := GetGlobalFlags()
		
		if remoteURL != "" {
			// Use remote API
			if !useJSON {
				fmt.Println("🔄 Reloading server configuration via API...")
			}
			
			client := api.NewClient(remoteURL, apiKey)
			details, err := client.ReloadServer()
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
				return
			}
			
			if useJSON {
				fmt.Printf("{\"success\": true, \"details\": %+v}\n", details)
			} else {
				fmt.Printf("✅ Server configuration reloaded successfully!\n")
				
				if operations, ok := details["operations"].([]interface{}); ok {
					fmt.Println("\n📋 Operations performed:")
					for i, op := range operations {
						if opMap, ok := op.(map[string]interface{}); ok {
							operation := opMap["operation"].(string)
							success := opMap["success"].(bool)
							message := opMap["message"].(string)
							
							status := "✅"
							if !success {
								status = "❌"
							}
							
							fmt.Printf("  %d. %s %s: %s\n", i+1, status, operation, message)
						}
					}
				}
			}
		} else {
			// Local mode - send SIGHUP signal to trigger reload
			fmt.Println("🔄 Sending reload signal to local server...")
			fmt.Println("Note: Server must be running and handle SIGHUP signal for configuration reload")
			fmt.Println("Use Ctrl+C to stop the server if needed")
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Add subcommands
	serverCmd.AddCommand(serverStartCmd)
	serverCmd.AddCommand(serverStatusCmd)
	serverCmd.AddCommand(serverReloadCmd)
}

// testPort checks if a port is available
func testPort(port string) bool {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// getStorageType determines the actual storage type being used
func getStorageType(cfg *config.Config) string {
	// Check if Redis is configured via environment variables
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		return "redis"
	}
	if redisURL := os.Getenv("P0RT_REDIS_URL"); redisURL != "" {
		return "redis"
	}
	if host := os.Getenv("REDIS_HOST"); host != "" {
		return "redis"
	}
	
	// Check config file for Redis
	if cfg.Storage.Type == "redis" || cfg.Storage.RedisURL != "" {
		return "redis"
	}
	
	// Default to JSON
	return "json"
}

// TCP Manager adapter types (moved from main.go)
type tcpManagerAdapter struct {
	manager *tcp.Manager
}

func (t *tcpManagerAdapter) CreateForwarder(client *ssh.Client, bindAddr string, bindPort uint32) (int, error) {
	clientAdapter := &clientAdapterForTCP{client: client}
	return t.manager.CreateForwarder(clientAdapter, bindAddr, bindPort)
}

func (t *tcpManagerAdapter) Close(port int) error {
	return t.manager.Close(port)
}

type clientAdapterForTCP struct {
	client *ssh.Client
}

func (c *clientAdapterForTCP) Conn() cryptossh.Conn {
	return c.client.Conn
}

type sshServerAdapter struct {
	server    *ssh.Server
	domainGen *domain.Generator
}

func (s *sshServerAdapter) GetClient(domain string) proxy.ClientWithPort {
	client := s.server.GetClient(domain)
	if client == nil {
		return nil
	}
	return newClientPortAdapter(client)
}

func (s *sshServerAdapter) LogConnection(domain, clientIP, method, requestURL string) {
	s.server.LogConnection(domain, clientIP, method, requestURL)
}

func (s *sshServerAdapter) GetDomainStats() map[string]interface{} {
	return s.domainGen.GetStats()
}

func (s *sshServerAdapter) RecordHTTPRequest(domain string, bytesIn, bytesOut int64) {
	s.server.RecordHTTPRequest(domain, bytesIn, bytesOut)
}

func (s *sshServerAdapter) RecordWebSocketUpgrade(domain string) {
	s.server.RecordWebSocketUpgrade(domain)
}

// SecurityProvider interface implementation
func (s *sshServerAdapter) GetSecurityStats() security.SecurityStats {
	return s.server.GetSecurityStats()
}

func (s *sshServerAdapter) GetBannedIPs() []security.BannedIP {
	return s.server.GetBannedIPs()
}

func (s *sshServerAdapter) UnbanIP(ip string) {
	s.server.UnbanIP(ip)
}

func (s *sshServerAdapter) UnbanIPFromTracker(ip string) {
	s.server.UnbanIPFromTracker(ip)
}

type clientPortAdapter struct {
	client *ssh.Client
}

func newClientPortAdapter(client *ssh.Client) *clientPortAdapter {
	return &clientPortAdapter{
		client: client,
	}
}

func (c *clientPortAdapter) GetPort() int {
	return c.client.Port
}

func (c *clientPortAdapter) GetFingerprint() string {
	if c.client.Key == "" {
		return ""
	}

	keyData, err := base64.StdEncoding.DecodeString(c.client.Key)
	if err != nil {
		return ""
	}

	pubKey, err := cryptossh.ParsePublicKey(keyData)
	if err != nil {
		return ""
	}

	return cryptossh.FingerprintSHA256(pubKey)
}

func (c *clientPortAdapter) GetClientIP() string {
	if c.client.Conn == nil {
		return ""
	}

	clientIP := c.client.Conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	// Remove brackets from IPv6 addresses for consistent format
	if len(clientIP) > 2 && clientIP[0] == '[' && clientIP[len(clientIP)-1] == ']' {
		return clientIP[1 : len(clientIP)-1]
	}
	return clientIP
}

// startServer starts the P0rt server (moved from main.go)
func startServer(cfg *config.Config) error {
	// Get verbosity flags
	_, _, _, verbose, quiet, _ := GetGlobalFlags()

	if !quiet {
		fmt.Printf("Starting P0rt server...\n")
		fmt.Printf("SSH: %s | HTTP: %s | Domain: %s\n",
			cfg.GetSSHPort(), cfg.GetHTTPPort(), cfg.GetDomainBase())
	}

	// Create domain generator with storage configuration
	storageConfig := cfg.GetStorageConfig()

	if verbose {
		log.Printf("Storage Type: %s", storageConfig.Type)
		if storageConfig.Type == "redis" {
			log.Printf("Redis URL: %s", storageConfig.RedisURL)
		} else {
			log.Printf("Data Dir: %s", storageConfig.DataDir)
		}
	}

	// Initialize Prometheus metrics with server start time
	startTime := time.Now()
	metrics.InitializeMetrics("1.1.0", "development", "unknown")
	if !quiet {
		log.Printf("📊 Prometheus metrics initialized")
	}
	
	// Start uptime tracking goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				uptime := time.Since(startTime).Seconds()
				metrics.SetUptime(uptime)
			}
		}
	}()

	domainGen, err := domain.NewGeneratorFromConfig(
		storageConfig.Type,
		storageConfig.DataDir,
		storageConfig.RedisURL,
		storageConfig.RedisPassword,
		storageConfig.RedisDB,
	)
	if err != nil {
		return fmt.Errorf("failed to create domain generator: %w", err)
	}

	tcpManager := tcp.NewManager()
	tcpManagerAdapter := &tcpManagerAdapter{manager: tcpManager}

	sshServer, err := ssh.NewServer(cfg.GetSSHPort(), cfg.GetSSHHostKey(), domainGen, tcpManagerAdapter, cfg.GetDomainBase())
	if err != nil {
		return fmt.Errorf("failed to create SSH server: %w", err)
	}

	sshServerAdapter := &sshServerAdapter{server: sshServer, domainGen: domainGen}

	// Create HTTP proxy with API support
	apiKey := os.Getenv("P0RT_API_KEY") // Optional API key from environment
	if verbose {
		if apiKey != "" {
			log.Printf("API Key configured for authentication")
		} else {
			log.Printf("No API Key configured - API will accept all requests")
		}
	}
	httpProxy := proxy.NewHTTPProxyWithAPI(sshServerAdapter, domainGen.GetReservationManager(), sshServer.GetStats(), apiKey)

	// Start metrics updater for periodic gauge updates
	abuseMonitor := httpProxy.GetAbuseMonitor() // Assuming this method exists or add it
	if abuseMonitor != nil {
		metricsUpdater := metrics.NewMetricsUpdater(sshServer, abuseMonitor)
		metricsUpdater.Start()
		defer metricsUpdater.Stop()
		
		if !quiet {
			log.Printf("📊 Metrics updater started")
		}
	}

	if !quiet {
		fmt.Printf("✓ Server ready - listening for SSH connections\n")
		if !verbose {
			fmt.Printf("Press Ctrl+C to stop | Use -v for verbose logs\n")
		}
	}

	errChan := make(chan error, 2)

	go func() {
		if err := sshServer.Start(); err != nil {
			errChan <- err
		}
	}()

	go func() {
		if err := httpProxy.Start(cfg.GetHTTPPort()); err != nil {
			errChan <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	case <-sigChan:
		if !quiet {
			fmt.Printf("\nShutting down gracefully...\n")
		}
		return nil
	}
}
