package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/p0rt/p0rt/internal/config"
	"github.com/p0rt/p0rt/internal/domain"
	"github.com/p0rt/p0rt/internal/proxy"
	"github.com/p0rt/p0rt/internal/security"
	"github.com/p0rt/p0rt/internal/ssh"
	"github.com/p0rt/p0rt/internal/tcp"

	cryptossh "golang.org/x/crypto/ssh"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Manage the P0rt server",
	Long: `Start, stop, restart, or check the status of the P0rt SSH tunneling server.

The server handles SSH connections for tunneling and serves the HTTP proxy
that routes incoming web requests to the appropriate tunnels.`,
	Example: `  # Start the server
  p0rt server start

  # Check server status
  p0rt server status

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
		cfg, err := config.Load()
		if err != nil {
			log.Printf("Failed to load config file, using defaults: %v", err)
			cfg = config.LoadDefault()
		}

		fmt.Println("P0rt Server Status:")
		fmt.Printf("  SSH Port: %s\n", cfg.GetSSHPort())
		fmt.Printf("  HTTP Port: %s\n", cfg.GetHTTPPort())
		fmt.Printf("  Domain Base: %s\n", cfg.GetDomainBase())
		fmt.Printf("  Storage Type: %s\n", cfg.Storage.Type)
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
	},
}

var serverStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the P0rt server",
	Long:  `Stop the running P0rt server (not yet implemented).`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Server stop functionality not yet implemented")
		fmt.Println("Use Ctrl+C to stop the server if running")
	},
}

var serverRestartCmd = &cobra.Command{
	Use:   "restart", 
	Short: "Restart the P0rt server",
	Long:  `Restart the P0rt server (not yet implemented).`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Server restart functionality not yet implemented")
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	
	// Add subcommands
	serverCmd.AddCommand(serverStartCmd)
	serverCmd.AddCommand(serverStatusCmd)
	serverCmd.AddCommand(serverStopCmd)
	serverCmd.AddCommand(serverRestartCmd)
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

func (s *sshServerAdapter) LogConnection(domain, clientIP, requestURL string) {
	s.server.LogConnection(domain, clientIP, requestURL)
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

// startServer starts the P0rt server (moved from main.go)
func startServer(cfg *config.Config) error {
	// Get verbosity flags
	_, _, _, verbose, quiet := GetGlobalFlags()

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