package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/p0rt/p0rt/internal/api"
	"github.com/p0rt/p0rt/internal/auth"
	"github.com/p0rt/p0rt/internal/config"
	"github.com/p0rt/p0rt/internal/domain"
	"github.com/p0rt/p0rt/internal/stats"
)

// CLI represents the interactive command line interface
type CLI struct {
	config             *config.Config
	reservationManager domain.ReservationManagerInterface
	keyStore           *auth.KeyStore // For SSH key management
	rl                 *readline.Instance
	serverStartFunc    func() error   // Function to start the server
	statsManager       *stats.Manager // For displaying runtime stats when server is running
	apiClient          *api.Client    // For remote API access
	useRemoteAPI       bool           // Whether to use remote API instead of local storage
}

// Command represents a CLI command
type Command struct {
	Name        string
	Description string
	Usage       string
	Handler     func(args []string) error
}

// NewCLI creates a new interactive CLI
func NewCLI(cfg *config.Config) (*CLI, error) {
	return NewCLIWithServerFunc(cfg, nil)
}

// NewCLIWithRemoteAPI creates a new interactive CLI that uses remote API
func NewCLIWithRemoteAPI(cfg *config.Config, serverURL, apiKey string) (*CLI, error) {
	apiClient := api.NewClient(serverURL, apiKey)

	// Test connection
	if err := apiClient.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to remote API at %s: %v", serverURL, err)
	}

	cli := &CLI{
		config:             cfg,
		reservationManager: api.NewRemoteReservationManager(serverURL, apiKey),
		keyStore:           auth.NewKeyStore("authorized_keys.json"), // Default key store for local operations
		apiClient:          apiClient,
		useRemoteAPI:       true,
	}

	// Setup readline with autocomplete
	completer := cli.createCompleter()
	rl, err := readline.NewEx(&readline.Config{
		Prompt:            "p0rt> ",
		HistoryFile:       "/tmp/p0rt_history",
		AutoComplete:      completer,
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create readline: %v", err)
	}

	cli.rl = rl
	return cli, nil
}

// NewCLIWithServerFunc creates a new interactive CLI with a server start function
func NewCLIWithServerFunc(cfg *config.Config, serverStartFunc func() error) (*CLI, error) {
	// Initialize reservation manager
	var reservationManager domain.ReservationManagerInterface
	var err error

	storageConfig := cfg.GetStorageConfig()
	switch storageConfig.Type {
	case "redis":
		reservationManager, err = domain.NewRedisReservationManager(
			storageConfig.RedisURL,
			storageConfig.RedisPassword,
			storageConfig.RedisDB,
		)
	case "json", "":
		reservationManager, err = domain.NewReservationManager(storageConfig.DataDir)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storageConfig.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create reservation manager: %v", err)
	}

	cli := &CLI{
		config:             cfg,
		reservationManager: reservationManager,
		keyStore:           auth.NewKeyStore("authorized_keys.json"), // Default key store
		serverStartFunc:    serverStartFunc,
	}

	// Setup readline with autocomplete
	completer := cli.createCompleter()
	rl, err := readline.NewEx(&readline.Config{
		Prompt:            "p0rt> ",
		HistoryFile:       "/tmp/p0rt_history",
		AutoComplete:      completer,
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create readline: %v", err)
	}

	cli.rl = rl
	return cli, nil
}

// Start starts the interactive CLI
func (c *CLI) Start() error {
	defer c.rl.Close()

	fmt.Println("P0rt Interactive CLI")
	fmt.Println("Type 'help' for available commands or 'exit' to quit")
	fmt.Println()

	for {
		line, err := c.rl.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := c.processCommand(line); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	return nil
}

// processCommand processes a command line input
func (c *CLI) processCommand(line string) error {
	args := strings.Fields(line)
	if len(args) == 0 {
		return nil
	}

	command := args[0]
	args = args[1:]

	switch command {
	case "help", "h":
		return c.showHelp(args)
	case "exit", "quit", "q":
		os.Exit(0)
		return nil
	case "server", "srv":
		return c.handleServerCommand(args)
	case "reservation", "res":
		return c.handleReservationCommand(args)
	case "key", "keys":
		return c.handleKeyCommand(args)
	case "stats":
		if len(args) > 0 && args[0] != "" {
			return c.showDomainStats(args[0])
		}
		return c.showStats()
	case "status":
		return c.showStatus()
	case "security", "sec":
		return c.handleSecurityCommand(args)
	case "history", "hist":
		return c.handleHistoryCommand(args)
	case "connections", "conn":
		return c.showActiveConnections()
	case "clear":
		fmt.Print("\033[H\033[2J")
		return nil
	default:
		return fmt.Errorf("unknown command: %s. Type 'help' for available commands", command)
	}
}

// showHelp displays help information
func (c *CLI) showHelp(args []string) error {
	if len(args) == 0 {
		fmt.Println("Available commands:")
		fmt.Println("  help [command]     - Show help information")
		fmt.Println("  server             - Start the P0rt server")
		fmt.Println("  reservation        - Manage domain reservations")
		fmt.Println("  key                - Manage SSH key allowlist")
		fmt.Println("  security           - View security information and bans")
		fmt.Println("  stats [domain]     - Show system statistics (or domain-specific stats)")
		fmt.Println("  history [n]        - Show connection history (last n connections)")
		fmt.Println("  connections        - Show active connections with bandwidth")
		fmt.Println("  status             - Show system status")
		fmt.Println("  clear              - Clear the screen")
		fmt.Println("  exit               - Exit the CLI")
		fmt.Println()
		fmt.Println("Use 'help <command>' for detailed information about a command.")
		return nil
	}

	command := args[0]
	switch command {
	case "server", "srv":
		fmt.Println("server - Start the P0rt server")
		fmt.Println("  Starts the SSH and HTTP servers for tunneling")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  server start    - Start the server (default)")
		fmt.Println("  server stop     - Stop the server (if running)")
		fmt.Println("  server restart  - Restart the server")
		fmt.Println("  server status   - Show server status")
	case "reservation", "res":
		fmt.Println("Reservation commands:")
		fmt.Println("  reservation add <domain> <fingerprint> [comment]")
		fmt.Println("    - Reserve a domain for an SSH key")
		fmt.Println("  reservation remove <domain>")
		fmt.Println("    - Remove a domain reservation")
		fmt.Println("  reservation list")
		fmt.Println("    - List all reservations")
		fmt.Println("  reservation stats")
		fmt.Println("    - Show reservation statistics")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  reservation add happy-cat-jump SHA256:abc123... \"My personal domain\"")
		fmt.Println("  reservation remove happy-cat-jump")
		fmt.Println("  reservation list")
	case "key", "keys":
		fmt.Println("SSH Key Management commands:")
		fmt.Println("  key add <fingerprint> [tier] [comment]")
		fmt.Println("    - Add an SSH key by fingerprint (easiest)")
		fmt.Println("  key remove <fingerprint>")
		fmt.Println("    - Remove an SSH key from allowlist")
		fmt.Println("  key list")
		fmt.Println("    - List all authorized SSH keys")
		fmt.Println("  key activate <fingerprint>")
		fmt.Println("    - Activate a deactivated key")
		fmt.Println("  key deactivate <fingerprint>")
		fmt.Println("    - Temporarily deactivate a key")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  key add SHA256:abc123... beta \"John Doe\"")
		fmt.Println("  key list")
		fmt.Println("  key remove SHA256:abc123...")
		fmt.Println("  key deactivate SHA256:abc123...")
	case "stats":
		fmt.Println("stats - Show system statistics")
		fmt.Println("Usage: stats [domain]")
		fmt.Println("  Displays system statistics including:")
		fmt.Println("  - Configuration information")
		fmt.Println("  - Server runtime statistics (if running)")
		fmt.Println("  - Domain reservation statistics")
		fmt.Println("  - Traffic and tunnel statistics")
		fmt.Println("  If domain is specified, shows detailed stats for that domain")
	case "status":
		fmt.Println("status - Show system status")
		fmt.Println("  Displays current system configuration and status")
	case "security", "sec":
		fmt.Println("security - View security information")
		fmt.Println("  security stats    - Show security statistics")
		fmt.Println("  security bans     - Show banned IP addresses")
		fmt.Println()
		fmt.Println("Displays security information including:")
		fmt.Println("  - Authentication failures")
		fmt.Println("  - Blocked IP addresses")
		fmt.Println("  - Scanning attempts")
		fmt.Println("  - Ban reasons and expiration times")
	case "history", "hist":
		fmt.Println("history [n] - Show connection history")
		fmt.Println("  n - Number of connections to show (default: 20)")
		fmt.Println()
		fmt.Println("Displays historical connection information including:")
		fmt.Println("  - Connection time and duration")
		fmt.Println("  - Domain and trigram (first 3 chars)")
		fmt.Println("  - Client IP address")
		fmt.Println("  - Bandwidth usage (in/out)")
		fmt.Println("  - Number of HTTP requests")
		fmt.Println()
		fmt.Println("Also shows aggregated statistics:")
		fmt.Println("  - Top domain trigrams")
		fmt.Println("  - Top client IPs")
		fmt.Println("  - Total traffic")
	case "connections", "conn":
		fmt.Println("connections - Show active connections")
		fmt.Println()
		fmt.Println("Displays all currently active SSH tunnels with:")
		fmt.Println("  - Domain and trigram")
		fmt.Println("  - Client IP address")
		fmt.Println("  - Connection duration")
		fmt.Println("  - Real-time bandwidth usage")
		fmt.Println("  - HTTP request count")
	default:
		return fmt.Errorf("no help available for command: %s", command)
	}

	return nil
}

// handleReservationCommand handles reservation subcommands
func (c *CLI) handleReservationCommand(args []string) error {
	if len(args) == 0 {
		fmt.Println("Reservation subcommands:")
		fmt.Println("  add <domain> <fingerprint> [comment] - Reserve a domain")
		fmt.Println("  remove <domain>                      - Remove a reservation")
		fmt.Println("  list                                 - List all reservations")
		fmt.Println("  stats                                - Show reservation statistics")
		return nil
	}

	subcommand := args[0]
	args = args[1:]

	switch subcommand {
	case "add":
		return c.addReservation(args)
	case "remove", "rm":
		return c.removeReservation(args)
	case "list", "ls":
		return c.listReservations()
	case "stats":
		return c.showReservationStats()
	default:
		return fmt.Errorf("unknown reservation subcommand: %s", subcommand)
	}
}

// addReservation adds a new domain reservation
func (c *CLI) addReservation(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: reservation add <domain> <fingerprint> [comment]")
	}

	domain := args[0]
	fingerprint := args[1]
	comment := ""
	if len(args) > 2 {
		comment = strings.Join(args[2:], " ")
		// Remove quotes if present
		comment = strings.Trim(comment, "\"'")
	}

	err := c.reservationManager.AddReservation(domain, fingerprint, comment)
	if err != nil {
		return fmt.Errorf("failed to add reservation: %v", err)
	}

	fmt.Printf("✓ Successfully reserved domain '%s' for SSH key fingerprint '%s'\n", domain, fingerprint)
	if comment != "" {
		fmt.Printf("  Comment: %s\n", comment)
	}

	return nil
}

// removeReservation removes a domain reservation
func (c *CLI) removeReservation(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: reservation remove <domain>")
	}

	domain := args[0]
	err := c.reservationManager.RemoveReservation(domain)
	if err != nil {
		return fmt.Errorf("failed to remove reservation: %v", err)
	}

	fmt.Printf("✓ Successfully removed reservation for domain '%s'\n", domain)
	return nil
}

// listReservations lists all domain reservations
func (c *CLI) listReservations() error {
	reservations := c.reservationManager.ListReservations()
	if len(reservations) == 0 {
		fmt.Println("No reservations found")
		return nil
	}

	fmt.Printf("Found %d reservation(s):\n\n", len(reservations))
	for i, res := range reservations {
		fmt.Printf("%d. Domain: %s\n", i+1, res.Domain)
		fmt.Printf("   Fingerprint: %s\n", res.Fingerprint)
		if res.Comment != "" {
			fmt.Printf("   Comment: %s\n", res.Comment)
		}
		fmt.Printf("   Created: %s\n", res.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("   Updated: %s\n", res.UpdatedAt.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}

	return nil
}

// showReservationStats shows reservation statistics
func (c *CLI) showReservationStats() error {
	stats := c.reservationManager.GetStats()
	fmt.Println("Reservation Statistics:")
	for key, value := range stats {
		fmt.Printf("  %s: %v\n", strings.ReplaceAll(key, "_", " "), value)
	}
	return nil
}

// showStats shows system statistics
func (c *CLI) showStats() error {
	fmt.Println("=== P0rt System Statistics ===")
	fmt.Println()

	if c.useRemoteAPI {
		// Get stats from remote API
		statsResponse, err := c.apiClient.GetStats()
		if err != nil {
			fmt.Printf("Failed to get remote stats: %v\n", err)
			return err
		}

		fmt.Println("Connection:")
		fmt.Printf("  Remote API: Connected\n")
		fmt.Println()

		// Global statistics from API
		if statsResponse.GlobalStats != nil {
			globalStats := statsResponse.GlobalStats
			fmt.Println("Server Statistics:")
			fmt.Printf("  Uptime: %s\n", globalStats.Uptime)
			fmt.Printf("  Active Tunnels: %d\n", globalStats.ActiveTunnels)
			fmt.Printf("  Total Tunnels: %d\n", globalStats.TotalTunnels)
			fmt.Printf("  Total Connections: %d\n", globalStats.TotalConnections)
			fmt.Printf("  HTTP Requests: %d\n", globalStats.HTTPRequests)
			fmt.Printf("  WebSocket Connections: %d\n", globalStats.WebSocketConnections)
			fmt.Printf("  Bytes Transferred: %s\n", stats.FormatBytes(globalStats.BytesTransferred))
			fmt.Println()

			// Top domains by traffic
			if len(globalStats.TopDomains) > 0 {
				fmt.Println("Top Domains by Requests:")
				for i, domain := range globalStats.TopDomains {
					if i >= 5 { // Limit to top 5
						break
					}
					fmt.Printf("  %d. %s - %d requests (%s in, %s out)\n",
						i+1, domain.Domain, domain.TotalRequests,
						stats.FormatBytes(domain.BytesIn), stats.FormatBytes(domain.BytesOut))
				}
				fmt.Println()
			}
		} else {
			fmt.Println("Server Statistics: Not available")
			fmt.Println()
		}

		// Reservation statistics from API
		fmt.Println("Domain Reservations:")
		if statsResponse.ReservationStats != nil {
			for key, value := range statsResponse.ReservationStats {
				fmt.Printf("  %s: %v\n", strings.ReplaceAll(key, "_", " "), value)
			}
		}
		return nil
	}

	// Local mode
	// Configuration Statistics
	fmt.Println("Configuration:")
	fmt.Printf("  Storage Type: %s\n", c.config.Storage.Type)
	if c.config.Storage.Type == "json" {
		fmt.Printf("  Data Directory: %s\n", c.config.Storage.DataDir)
	} else if c.config.Storage.Type == "redis" {
		fmt.Printf("  Redis URL: %s\n", c.config.Storage.RedisURL)
		fmt.Printf("  Redis DB: %d\n", c.config.Storage.RedisDB)
	}
	fmt.Printf("  SSH Port: %s\n", c.config.GetSSHPort())
	fmt.Printf("  HTTP Port: %s\n", c.config.GetHTTPPort())
	fmt.Printf("  Domain Base: %s\n", c.config.GetDomainBase())
	fmt.Println()

	// Runtime Statistics (only if server is running and statsManager is available)
	if c.statsManager != nil {
		globalStats := c.statsManager.GetGlobalStats()

		fmt.Println("Server Statistics:")
		fmt.Printf("  Uptime: %s\n", globalStats.Uptime)
		fmt.Printf("  Active Tunnels: %d\n", globalStats.ActiveTunnels)
		fmt.Printf("  Total Tunnels: %d\n", globalStats.TotalTunnels)
		fmt.Printf("  Total Connections: %d\n", globalStats.TotalConnections)
		fmt.Printf("  HTTP Requests: %d\n", globalStats.HTTPRequests)
		fmt.Printf("  WebSocket Connections: %d\n", globalStats.WebSocketConnections)
		fmt.Printf("  Bytes Transferred: %s\n", stats.FormatBytes(globalStats.BytesTransferred))
		fmt.Println()

		// Top domains by traffic
		if len(globalStats.TopDomains) > 0 {
			fmt.Println("Top Domains by Requests:")
			for i, domain := range globalStats.TopDomains {
				if i >= 5 { // Limit to top 5
					break
				}
				fmt.Printf("  %d. %s - %d requests (%s in, %s out)\n",
					i+1, domain.Domain, domain.TotalRequests,
					stats.FormatBytes(domain.BytesIn), stats.FormatBytes(domain.BytesOut))
			}
			fmt.Println()
		}
	} else {
		fmt.Println("Server Statistics: Not available (server not running)")
		fmt.Println()
	}

	// Reservation Statistics
	fmt.Println("Domain Reservations:")
	return c.showReservationStats()
}

// showDomainStats shows statistics for a specific domain
func (c *CLI) showDomainStats(domain string) error {
	fmt.Printf("=== Statistics for Domain: %s ===\n", domain)
	fmt.Println()

	if c.useRemoteAPI {
		// Get tunnel stats from remote API
		tunnelStats, err := c.apiClient.GetTunnelStats(domain)
		if err != nil {
			fmt.Printf("Failed to get tunnel stats: %v\n", err)
			return err
		}

		if tunnelStats != nil {
			fmt.Println("Tunnel Statistics:")
			fmt.Printf("  Domain: %s\n", tunnelStats.Domain)
			fmt.Printf("  Created: %s\n", tunnelStats.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Last Activity: %s\n", tunnelStats.LastActivity.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Total Requests: %d\n", tunnelStats.TotalRequests)
			fmt.Printf("  Bytes In: %s\n", stats.FormatBytes(tunnelStats.BytesIn))
			fmt.Printf("  Bytes Out: %s\n", stats.FormatBytes(tunnelStats.BytesOut))
			fmt.Printf("  WebSocket Upgrades: %d\n", tunnelStats.WebSocketUpgrades)
			fmt.Printf("  Active Connections: %d\n", tunnelStats.ActiveConnections)
		} else {
			fmt.Printf("No statistics found for domain '%s'\n", domain)
			fmt.Println("This domain may not have any recent activity or may not exist.")
		}
	} else if c.statsManager != nil {
		tunnelStats := c.statsManager.GetTunnelStats(domain)
		if tunnelStats != nil {
			fmt.Println("Tunnel Statistics:")
			fmt.Printf("  Domain: %s\n", tunnelStats.Domain)
			fmt.Printf("  Created: %s\n", tunnelStats.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Last Activity: %s\n", tunnelStats.LastActivity.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Total Requests: %d\n", tunnelStats.TotalRequests)
			fmt.Printf("  Bytes In: %s\n", stats.FormatBytes(tunnelStats.BytesIn))
			fmt.Printf("  Bytes Out: %s\n", stats.FormatBytes(tunnelStats.BytesOut))
			fmt.Printf("  WebSocket Upgrades: %d\n", tunnelStats.WebSocketUpgrades)
			fmt.Printf("  Active Connections: %d\n", tunnelStats.ActiveConnections)
		} else {
			fmt.Printf("No statistics found for domain '%s'\n", domain)
			fmt.Println("This domain may not have any recent activity or may not exist.")
		}
	} else {
		fmt.Println("Statistics not available (server not running)")
	}

	fmt.Println()
	return nil
}

// showStatus shows system status
func (c *CLI) showStatus() error {
	fmt.Println("System Status:")
	fmt.Printf("  SSH Port: %s\n", c.config.GetSSHPort())
	fmt.Printf("  HTTP Port: %s\n", c.config.GetHTTPPort())
	fmt.Printf("  Domain Base: %s\n", c.config.GetDomainBase())
	fmt.Printf("  Reservations Enabled: %t\n", c.config.Domain.ReservationsEnabled)
	fmt.Printf("  Storage Type: %s\n", c.config.Storage.Type)
	return nil
}

// createCompleter creates an autocomplete function
func (c *CLI) createCompleter() readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("help",
			readline.PcItem("server"),
			readline.PcItem("reservation"),
			readline.PcItem("key"),
			readline.PcItem("stats"),
			readline.PcItem("status"),
		),
		readline.PcItem("server",
			readline.PcItem("start"),
			readline.PcItem("stop"),
			readline.PcItem("restart"),
			readline.PcItem("status"),
		),
		readline.PcItem("srv",
			readline.PcItem("start"),
			readline.PcItem("stop"),
			readline.PcItem("restart"),
			readline.PcItem("status"),
		),
		readline.PcItem("reservation",
			readline.PcItem("add"),
			readline.PcItem("remove", readline.PcItemDynamic(c.getDomainCompletions)),
			readline.PcItem("list"),
			readline.PcItem("stats"),
		),
		readline.PcItem("res",
			readline.PcItem("add"),
			readline.PcItem("remove", readline.PcItemDynamic(c.getDomainCompletions)),
			readline.PcItem("list"),
			readline.PcItem("stats"),
		),
		readline.PcItem("key",
			readline.PcItem("add"),
			readline.PcItem("remove"),
			readline.PcItem("list"),
			readline.PcItem("activate"),
			readline.PcItem("deactivate"),
		),
		readline.PcItem("keys",
			readline.PcItem("add"),
			readline.PcItem("remove"),
			readline.PcItem("list"),
			readline.PcItem("activate"),
			readline.PcItem("deactivate"),
		),
		readline.PcItem("security",
			readline.PcItem("stats"),
			readline.PcItem("bans"),
		),
		readline.PcItem("sec",
			readline.PcItem("stats"),
			readline.PcItem("bans"),
		),
		readline.PcItem("stats"),
		readline.PcItem("status"),
		readline.PcItem("clear"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}

// handleSecurityCommand handles security-related commands
func (c *CLI) handleSecurityCommand(args []string) error {
	if len(args) == 0 {
		fmt.Println("Security subcommands:")
		fmt.Println("  stats    - Show security statistics")
		fmt.Println("  bans     - Show banned IP addresses")
		return nil
	}

	switch args[0] {
	case "stats":
		return c.showSecurityStats()
	case "bans":
		return c.showSecurityBans()
	default:
		return fmt.Errorf("unknown security subcommand: %s", args[0])
	}
}

// showSecurityStats displays security statistics
func (c *CLI) showSecurityStats() error {
	if c.useRemoteAPI {
		// Get security stats from remote API
		securityStats, err := c.apiClient.GetSecurityStats()
		if err != nil {
			return fmt.Errorf("failed to get security stats: %v", err)
		}

		fmt.Println("=== Security Statistics ===")
		fmt.Println()

		if authFailures, ok := securityStats["authentication_failures"].(float64); ok {
			fmt.Printf("Authentication Failures: %.0f\n", authFailures)
		}
		if blockedIPs, ok := securityStats["blocked_ips_count"].(float64); ok {
			fmt.Printf("Blocked IP Addresses: %.0f\n", blockedIPs)
		}
		if scanningAttempts, ok := securityStats["scanning_attempts"].(float64); ok {
			fmt.Printf("Scanning Attempts: %.0f\n", scanningAttempts)
		}
		if abuseReports, ok := securityStats["abuse_reports"].(float64); ok {
			fmt.Printf("Abuse Reports: %.0f\n", abuseReports)
		}
		if last24h, ok := securityStats["last_24h_failures"].(float64); ok {
			fmt.Printf("Failures (24h): %.0f\n", last24h)
		}
		fmt.Println()

		if banReasons, ok := securityStats["ban_reasons"].(map[string]interface{}); ok && len(banReasons) > 0 {
			fmt.Println("Ban Reasons:")
			for reason, count := range banReasons {
				if countFloat, ok := count.(float64); ok && countFloat > 0 {
					fmt.Printf("  %s: %.0f\n", reason, countFloat)
				}
			}
		}
	} else {
		fmt.Println("Security statistics require a running server.")
		fmt.Println("Use remote mode to connect to a running server:")
		fmt.Printf("  p0rt --remote http://localhost:%s cli\n", c.config.GetHTTPPort())
	}

	return nil
}

// showSecurityBans displays banned IP addresses
func (c *CLI) showSecurityBans() error {
	if c.useRemoteAPI {
		// Get bans from remote API
		bannedIPs, err := c.apiClient.GetSecurityBans()
		if err != nil {
			return fmt.Errorf("failed to get security bans: %v", err)
		}

		fmt.Println("=== Banned IP Addresses ===")
		fmt.Println()

		if len(bannedIPs) == 0 {
			fmt.Println("No IP addresses are currently banned.")
		} else {
			fmt.Printf("Total banned IPs: %d\n\n", len(bannedIPs))
			for _, banInfo := range bannedIPs {
				if ip, ok := banInfo["ip"].(string); ok {
					fmt.Printf("IP: %s\n", ip)
					if reason, ok := banInfo["reason"].(string); ok {
						fmt.Printf("  Reason: %s\n", reason)
					}
					if bannedAt, ok := banInfo["banned_at"].(string); ok {
						fmt.Printf("  Banned: %s\n", bannedAt)
					}
					if expiresAt, ok := banInfo["expires_at"].(string); ok {
						fmt.Printf("  Expires: %s\n", expiresAt)
					}
					fmt.Println()
				}
			}
		}
	} else {
		fmt.Println("Ban information requires a running server.")
		fmt.Println("Use remote mode to connect to a running server:")
		fmt.Printf("  p0rt --remote http://localhost:%s cli\n", c.config.GetHTTPPort())
	}

	return nil
}

// handleServerCommand handles server management commands
func (c *CLI) handleServerCommand(args []string) error {
	if len(args) == 0 {
		// Default action is to start the server
		args = []string{"start"}
	}

	subcommand := args[0]
	switch subcommand {
	case "start":
		return c.startServer()
	case "stop":
		return c.stopServer()
	case "restart":
		return c.restartServer()
	case "status":
		return c.serverStatus()
	default:
		return fmt.Errorf("unknown server subcommand: %s. Available: start, stop, restart, status", subcommand)
	}
}

// startServer starts the P0rt server
func (c *CLI) startServer() error {
	if c.serverStartFunc == nil {
		return fmt.Errorf("server start function not available in CLI mode")
	}

	fmt.Println("Starting P0rt server...")
	fmt.Printf("SSH Port: %s\n", c.config.GetSSHPort())
	fmt.Printf("HTTP Port: %s\n", c.config.GetHTTPPort())
	fmt.Printf("Domain Base: %s\n", c.config.GetDomainBase())
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop the server")

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := c.serverStartFunc(); err != nil {
			errChan <- err
		}
	}()

	// Wait for signal or error
	select {
	case err := <-errChan:
		return fmt.Errorf("server error: %v", err)
	case sig := <-sigChan:
		fmt.Printf("\nReceived signal %v, stopping server...\n", sig)
		return nil
	}
}

// stopServer stops the P0rt server (placeholder for future implementation)
func (c *CLI) stopServer() error {
	fmt.Println("Server stop functionality not yet implemented")
	fmt.Println("Use Ctrl+C to stop the server if running")
	return nil
}

// restartServer restarts the P0rt server (placeholder for future implementation)
func (c *CLI) restartServer() error {
	fmt.Println("Server restart functionality not yet implemented")
	return nil
}

// serverStatus shows the server status (placeholder for future implementation)
func (c *CLI) serverStatus() error {
	fmt.Println("Server Status:")
	fmt.Printf("  Configuration loaded: ✓\n")
	fmt.Printf("  SSH Port: %s\n", c.config.GetSSHPort())
	fmt.Printf("  HTTP Port: %s\n", c.config.GetHTTPPort())
	fmt.Printf("  Domain Base: %s\n", c.config.GetDomainBase())
	fmt.Printf("  Storage Type: %s\n", c.config.Storage.Type)
	fmt.Printf("  Reservations Enabled: %t\n", c.config.Domain.ReservationsEnabled)
	fmt.Println("  Server Status: Use 'server start' to launch")
	return nil
}

// handleKeyCommand handles SSH key management commands
func (c *CLI) handleKeyCommand(args []string) error {
	if len(args) == 0 {
		fmt.Println("SSH Key Management subcommands:")
		fmt.Println("  add <fingerprint> [tier] [comment] - Add an SSH key by fingerprint")
		fmt.Println("  remove <fingerprint>               - Remove an SSH key")
		fmt.Println("  list                               - List all authorized SSH keys")
		fmt.Println("  activate <fingerprint>             - Activate a deactivated key")
		fmt.Println("  deactivate <fingerprint>           - Deactivate a key temporarily")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  key add SHA256:abc123... beta \"John Doe\"")
		fmt.Println("  key list")
		fmt.Println("  key remove SHA256:abc123...")
		return nil
	}

	subcommand := args[0]
	args = args[1:]

	switch subcommand {
	case "add":
		return c.addKey(args)
	case "remove", "rm":
		return c.removeKey(args)
	case "list", "ls":
		return c.listKeys()
	case "activate":
		return c.activateKey(args)
	case "deactivate":
		return c.deactivateKey(args)
	default:
		return fmt.Errorf("unknown key subcommand: %s", subcommand)
	}
}

// addKey adds a new SSH key to the allowlist
func (c *CLI) addKey(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: key add <fingerprint> [tier] [comment]")
	}

	fingerprint := args[0]
	tier := "free" // default tier
	comment := ""

	if len(args) > 1 {
		tier = args[1]
	}
	if len(args) > 2 {
		comment = strings.Join(args[2:], " ")
		// Remove quotes if present
		comment = strings.Trim(comment, "\"'")
	}

	err := c.keyStore.AddKeyByFingerprint(fingerprint, comment, tier, nil)
	if err != nil {
		return fmt.Errorf("failed to add key: %v", err)
	}

	fmt.Printf("✅ Successfully added SSH key\n")
	fmt.Printf("📋 Fingerprint: %s\n", fingerprint)
	fmt.Printf("🎯 Tier: %s\n", tier)
	if comment != "" {
		fmt.Printf("💬 Comment: %s\n", comment)
	}

	return nil
}

// removeKey removes an SSH key from the allowlist
func (c *CLI) removeKey(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: key remove <fingerprint>")
	}

	fingerprint := args[0]
	err := c.keyStore.RemoveKey(fingerprint)
	if err != nil {
		return fmt.Errorf("failed to remove key: %v", err)
	}

	fmt.Printf("✅ Successfully removed SSH key: %s\n", fingerprint)
	return nil
}

// listKeys lists all authorized SSH keys
func (c *CLI) listKeys() error {
	keys := c.keyStore.ListKeys()

	if len(keys) == 0 {
		fmt.Println("No authorized SSH keys found")
		fmt.Println()
		fmt.Println("Add a key with:")
		fmt.Println("  key add SHA256:abc123... beta \"User Name\"")
		return nil
	}

	fmt.Printf("Found %d authorized SSH key(s):\n\n", len(keys))
	fmt.Printf("%-50s %-10s %-10s %-20s %s\n", "Fingerprint", "Tier", "Status", "Added", "Comment")
	fmt.Println(strings.Repeat("-", 120))

	for _, access := range keys {
		status := "✅ Active"
		if !access.Active {
			status = "❌ Inactive"
		}
		if access.ExpiresAt != nil && time.Now().After(*access.ExpiresAt) {
			status = "⏰ Expired"
		}

		// Truncate long fingerprints for display
		displayFingerprint := access.Fingerprint
		if len(displayFingerprint) > 47 {
			displayFingerprint = displayFingerprint[:44] + "..."
		}

		fmt.Printf("%-50s %-10s %-10s %-20s %s\n",
			displayFingerprint,
			access.Tier,
			status,
			access.AddedAt.Format("2006-01-02 15:04:05"),
			access.Comment,
		)
	}

	fmt.Println()
	
	// Show access mode
	accessMode := "RESTRICTED"
	if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
		accessMode = "OPEN ACCESS"
	}
	fmt.Printf("🔒 Server is in %s mode\n", accessMode)

	return nil
}

// activateKey activates a deactivated SSH key
func (c *CLI) activateKey(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: key activate <fingerprint>")
	}

	fingerprint := args[0]
	err := c.keyStore.ActivateKey(fingerprint)
	if err != nil {
		return fmt.Errorf("failed to activate key: %v", err)
	}

	fmt.Printf("✅ Successfully activated SSH key: %s\n", fingerprint)
	return nil
}

// deactivateKey deactivates an SSH key temporarily
func (c *CLI) deactivateKey(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: key deactivate <fingerprint>")
	}

	fingerprint := args[0]
	err := c.keyStore.DeactivateKey(fingerprint)
	if err != nil {
		return fmt.Errorf("failed to deactivate key: %v", err)
	}

	fmt.Printf("✅ Successfully deactivated SSH key: %s\n", fingerprint)
	return nil
}

// handleHistoryCommand handles connection history commands
func (c *CLI) handleHistoryCommand(args []string) error {
	if c.statsManager == nil {
		return fmt.Errorf("statistics manager not available")
	}
	
	limit := 20
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			limit = n
		}
	}
	
	fmt.Printf("=== Connection History (Last %d) ===\n", limit)
	fmt.Println()
	
	history := c.statsManager.GetConnectionHistory(limit)
	if len(history) == 0 {
		fmt.Println("No connection history available.")
		return nil
	}
	
	// Table header
	fmt.Printf("%-20s %-15s %-15s %-15s %-10s %-10s %-8s\n", 
		"Time", "Domain", "Trigram", "Client IP", "Duration", "Traffic", "Requests")
	fmt.Println(strings.Repeat("-", 100))
	
	for _, conn := range history {
		timestamp := conn.ConnectedAt.Format("2006-01-02 15:04:05")
		duration := "Active"
		if conn.DisconnectedAt != nil {
			duration = conn.Duration
		}
		
		traffic := fmt.Sprintf("%s/%s", 
			stats.FormatBytes(conn.BytesIn), 
			stats.FormatBytes(conn.BytesOut))
		
		fmt.Printf("%-20s %-15s %-15s %-15s %-10s %-10s %-8d\n",
			timestamp,
			truncateString(conn.Domain, 15),
			conn.Trigram,
			conn.ClientIP,
			truncateString(duration, 10),
			traffic,
			conn.RequestCount,
		)
	}
	
	fmt.Println()
	
	// Show aggregated stats
	connStats := c.statsManager.GetConnectionStats()
	fmt.Println("=== Aggregated Statistics ===")
	fmt.Printf("Total Connections: %v\n", connStats["total_connections"])
	fmt.Printf("Active Connections: %v\n", connStats["active_connections"])
	fmt.Printf("Total Traffic: %s in / %s out\n", 
		stats.FormatBytes(connStats["total_bytes_in"].(int64)),
		stats.FormatBytes(connStats["total_bytes_out"].(int64)))
	fmt.Printf("Total Requests: %v\n", connStats["total_requests"])
	fmt.Println()
	
	// Top trigrams
	if topTrigrams, ok := connStats["top_trigrams"].([]map[string]interface{}); ok && len(topTrigrams) > 0 {
		fmt.Println("Top Domain Trigrams:")
		for i, item := range topTrigrams {
			if i >= 5 {
				break
			}
			fmt.Printf("  %s: %v connections\n", item["value"], item["count"])
		}
		fmt.Println()
	}
	
	// Top client IPs
	if topIPs, ok := connStats["top_client_ips"].([]map[string]interface{}); ok && len(topIPs) > 0 {
		fmt.Println("Top Client IPs:")
		for i, item := range topIPs {
			if i >= 5 {
				break
			}
			fmt.Printf("  %s: %v connections\n", item["value"], item["count"])
		}
	}
	
	return nil
}

// showActiveConnections shows currently active connections
func (c *CLI) showActiveConnections() error {
	if c.statsManager == nil {
		return fmt.Errorf("statistics manager not available")
	}
	
	fmt.Println("=== Active Connections ===")
	fmt.Println()
	
	active := c.statsManager.GetActiveConnections()
	if len(active) == 0 {
		fmt.Println("No active connections.")
		return nil
	}
	
	// Table header
	fmt.Printf("%-15s %-15s %-15s %-20s %-10s %-10s %-8s\n", 
		"Domain", "Trigram", "Client IP", "Connected Since", "Duration", "Traffic", "Requests")
	fmt.Println(strings.Repeat("-", 100))
	
	for _, conn := range active {
		duration := time.Since(conn.ConnectedAt).Truncate(time.Second).String()
		traffic := fmt.Sprintf("%s/%s", 
			stats.FormatBytes(conn.BytesIn), 
			stats.FormatBytes(conn.BytesOut))
		
		fmt.Printf("%-15s %-15s %-15s %-20s %-10s %-10s %-8d\n",
			truncateString(conn.Domain, 15),
			conn.Trigram,
			conn.ClientIP,
			conn.ConnectedAt.Format("2006-01-02 15:04:05"),
			duration,
			traffic,
			conn.RequestCount,
		)
	}
	
	fmt.Printf("\nTotal active connections: %d\n", len(active))
	
	return nil
}

// truncateString truncates a string to max length
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// getDomainCompletions returns domain completions for autocomplete
func (c *CLI) getDomainCompletions(line string) []string {
	reservations := c.reservationManager.ListReservations()
	var domains []string
	for _, res := range reservations {
		domains = append(domains, res.Domain)
	}
	return domains
}
