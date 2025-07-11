package cli

import (
	"encoding/json"
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
	"github.com/p0rt/p0rt/internal/security"
	"github.com/p0rt/p0rt/internal/stats"
)

// CLI represents the interactive command line interface
type CLI struct {
	config             *config.Config
	reservationManager domain.ReservationManagerInterface
	keyStore           auth.KeyStoreInterface // For SSH key management
	rl                 *readline.Instance
	serverStartFunc    func() error   // Function to start the server
	statsManager       *stats.Manager // For displaying runtime stats when server is running
	apiClient          *api.Client    // For remote API access
	useRemoteAPI       bool           // Whether to use remote API instead of local storage
	jsonOutput         bool           // Whether to output in JSON format
}

// Command represents a CLI command
type Command struct {
	Name        string
	Description string
	Usage       string
	Handler     func(args []string) error
}

// OutputFormat represents different output formats
type OutputFormat struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// SetJSONOutput enables JSON output format
func (c *CLI) SetJSONOutput(enabled bool) {
	c.jsonOutput = enabled
}

// output prints data in the appropriate format (human-readable or JSON)
func (c *CLI) output(data interface{}, message string, isError bool) {
	if c.jsonOutput {
		result := OutputFormat{
			Success: !isError,
			Data:    data,
		}
		if message != "" {
			if isError {
				result.Error = message
			} else {
				result.Message = message
			}
		}

		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Printf(`{"success":false,"error":"Failed to marshal JSON: %v"}`, err)
			return
		}
		fmt.Println(string(jsonData))
	} else {
		// Human-readable format
		if message != "" {
			if isError {
				fmt.Printf("Error: %s\n", message)
			} else {
				fmt.Println(message)
			}
		}
		if data != nil {
			fmt.Printf("%+v\n", data)
		}
	}
}

// outputSuccess prints successful results
func (c *CLI) outputSuccess(data interface{}, message string) {
	c.output(data, message, false)
}

// outputError prints error results
func (c *CLI) outputError(message string) {
	c.output(nil, message, true)
}

// outputList prints a list of items with appropriate formatting
func (c *CLI) outputList(items interface{}, title string) {
	if c.jsonOutput {
		c.outputSuccess(items, title)
	} else {
		if title != "" {
			fmt.Printf("%s:\n", title)
		}
		switch v := items.(type) {
		case []interface{}:
			for i, item := range v {
				fmt.Printf("  %d. %+v\n", i+1, item)
			}
		default:
			fmt.Printf("%+v\n", items)
		}
	}
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

	// Create key store for local operations
	keyStore, err := auth.NewKeyStoreFromConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %v", err)
	}

	cli := &CLI{
		config:             cfg,
		reservationManager: api.NewRemoteReservationManager(serverURL, apiKey),
		keyStore:           keyStore,
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

	// Create key store based on configuration
	keyStore, err := auth.NewKeyStoreFromConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %v", err)
	}

	cli := &CLI{
		config:             cfg,
		reservationManager: reservationManager,
		keyStore:           keyStore,
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
	case "server":
		return c.handleServerCommand(args)
	case "reservation":
		return c.handleReservationCommand(args)
	case "keys":
		return c.handleKeyCommand(args)
	case "stats":
		if len(args) > 0 && args[0] != "" {
			return c.showDomainStats(args[0])
		}
		return c.showStats()
	case "status":
		return c.showStatus()
	case "security":
		return c.handleSecurityCommand(args)
	case "history":
		return c.handleHistoryCommand(args)
	case "connections":
		return c.showActiveConnections()
	case "domains":
		return c.handleDomainsCommand(args)
	case "access":
		return c.handleAccessCommand(args)
	case "abuse":
		return c.handleAbuseCommand(args)
	case "notify":
		return c.handleNotifyCommand(args)
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
		fmt.Println("  server             - Manage P0rt server (start, reload, status)")
		fmt.Println("  reservation        - Manage domain reservations")
		fmt.Println("  keys               - Manage SSH key allowlist")
		fmt.Println("  security           - View security information and bans")
		fmt.Println("  stats [domain]     - Show system statistics")
		fmt.Println("  history [n]        - Show connection history")
		fmt.Println("  connections        - Show active connections")
		fmt.Println("  domains            - List all domains with SSH keys and usage")
		fmt.Println("  access             - Manage server access mode")
		fmt.Println("  abuse              - Manage abuse reports")
		fmt.Println("  notify             - Send notifications to SSH clients")
		fmt.Println("  status             - Show system status")
		fmt.Println("  clear              - Clear the screen")
		fmt.Println("  exit               - Exit the CLI")
		fmt.Println()
		fmt.Println("Use 'help <command>' for detailed information about a command.")
		return nil
	}

	command := args[0]
	switch command {
	case "server":
		fmt.Println("server - Manage the P0rt server")
		fmt.Println("  Control and monitor the SSH and HTTP servers")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  server start    - Start the server (local only)")
		fmt.Println("  server reload   - Reload configuration (local or remote)")
		fmt.Println("  server status   - Show detailed server status (local or remote)")
	case "reservation":
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
	case "keys":
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
	case "security":
		fmt.Println("security - View and manage security information")
		fmt.Println("  security stats    - Show security statistics")
		fmt.Println("  security bans     - Show banned IP addresses")
		fmt.Println("  security unban    - Unban an IP address")
		fmt.Println()
		fmt.Println("Displays security information including:")
		fmt.Println("  - Authentication failures")
		fmt.Println("  - Blocked IP addresses")
		fmt.Println("  - Scanning attempts")
		fmt.Println("  - Ban reasons and expiration times")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  security stats")
		fmt.Println("  security bans")
		fmt.Println("  security unban 192.168.1.100")
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
	case "domains", "domain":
		fmt.Println("domains - List all domains with SSH keys and usage information")
		fmt.Println()
		fmt.Println("Shows paginated list of all domains with comprehensive information:")
		fmt.Println("  - Domain name and SSH key hash")
		fmt.Println("  - SSH key fingerprint")
		fmt.Println("  - First and last seen dates")
		fmt.Println("  - Last connection IP address")
		fmt.Println("  - Usage statistics (requests, traffic)")
		fmt.Println("  - Active status")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  domains             - Show first page (20 items)")
		fmt.Println("  domains [page]      - Show specific page number")
		fmt.Println("  domains --page=N    - Show specific page")
		fmt.Println("  domains --per-page=N - Set items per page (max: 100)")
	case "access", "mode":
		fmt.Println("access - Manage server access mode")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  access status     - Show current access mode")
		fmt.Println("  access open       - Switch to open access (allow all SSH keys)")
		fmt.Println("  access restricted - Switch to restricted access (allowlist only)")
		fmt.Println()
		fmt.Println("Access modes:")
		fmt.Println("  Open       - Any SSH key can create tunnels")
		fmt.Println("  Restricted - Only pre-authorized keys allowed")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  access status")
		fmt.Println("  access open")
		fmt.Println("  access restricted")
	case "abuse":
		fmt.Println("abuse - Manage abuse reports")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  abuse list                       - List pending abuse reports")
		fmt.Println("  abuse list --all                 - List all reports (including processed)")
		fmt.Println("  abuse report <domain> [reason]   - Submit new abuse report")
		fmt.Println("  abuse process [report-id] ban    - Ban domain based on abuse report")
		fmt.Println("  abuse process [report-id] accept - Accept domain (dismiss report)")
		fmt.Println("  abuse delete [report-id]         - Delete report and unban domain/IP")
		fmt.Println("  abuse stats                      - Show abuse report statistics")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  abuse report happy-cat-123.p0rt.xyz \"Testing ban notifications\"")
		fmt.Println("  abuse list")
		fmt.Println("  abuse process abc-123 ban")
		fmt.Println("  abuse delete abc-123")
		fmt.Println()
		fmt.Println("Description:")
		fmt.Println("  Submit, view and process abuse reports for domains.")
		fmt.Println("  Reports are stored in Redis and can be banned or accepted.")
	case "notify":
		fmt.Println("notify - Send notifications to SSH clients")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  notify test [message]                    - Send test notification")
		fmt.Println("  notify domain <domain> [options]         - Send notification to specific domain")
		fmt.Println()
		fmt.Println("Domain notification options:")
		fmt.Println("  --type ban --reason <reason>             - Send ban notification")
		fmt.Println("  --type warning --message <message>       - Send warning notification")
		fmt.Println("  --message <message>                      - Send custom message")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  notify test")
		fmt.Println("  notify test \"Custom test message\"")
		fmt.Println("  notify domain happy-cat-123 --type ban --reason \"spam\"")
		fmt.Println("  notify domain happy-cat-123 --message \"Maintenance in 5 minutes\"")
		fmt.Println()
		fmt.Println("Description:")
		fmt.Println("  Send real-time notifications to active SSH clients.")
		fmt.Println("  Requires remote API connection to work.")
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

	if c.useRemoteAPI && c.apiClient != nil {
		// Use remote API
		err := c.apiClient.AddReservation(domain, fingerprint, comment)
		if err != nil {
			return fmt.Errorf("failed to add reservation via remote API: %v", err)
		}
	} else {
		// Use local reservation manager
		err := c.reservationManager.AddReservation(domain, fingerprint, comment)
		if err != nil {
			return fmt.Errorf("failed to add reservation: %v", err)
		}
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
	if c.useRemoteAPI && c.apiClient != nil {
		// Use remote API
		err := c.apiClient.RemoveReservation(domain)
		if err != nil {
			return fmt.Errorf("failed to remove reservation via remote API: %v", err)
		}
	} else {
		// Use local reservation manager
		err := c.reservationManager.RemoveReservation(domain)
		if err != nil {
			return fmt.Errorf("failed to remove reservation: %v", err)
		}
	}

	fmt.Printf("✓ Successfully removed reservation for domain '%s'\n", domain)
	return nil
}

// listReservations lists all domain reservations
func (c *CLI) listReservations() error {
	var reservations []domain.Reservation
	var err error

	if c.useRemoteAPI && c.apiClient != nil {
		// Use remote API
		reservations, err = c.apiClient.ListReservations()
		if err != nil {
			return fmt.Errorf("failed to list reservations via remote API: %v", err)
		}
	} else {
		// Use local reservation manager
		reservations = c.reservationManager.ListReservations()
	}

	if len(reservations) == 0 {
		c.outputSuccess([]interface{}{}, "No reservations found")
		return nil
	}

	if c.jsonOutput {
		c.outputSuccess(reservations, fmt.Sprintf("Found %d reservation(s)", len(reservations)))
	} else {
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
	}

	return nil
}

// showReservationStats shows reservation statistics
func (c *CLI) showReservationStats() error {
	if c.useRemoteAPI && c.apiClient != nil {
		// For remote API, we can generate basic stats from the reservation list
		reservations, err := c.apiClient.ListReservations()
		if err != nil {
			return fmt.Errorf("failed to get reservations from remote API: %v", err)
		}

		// Generate basic stats
		stats := map[string]interface{}{
			"total_reservations": len(reservations),
		}

		if c.jsonOutput {
			c.outputSuccess(stats, "Reservation statistics")
		} else {
			fmt.Println("Reservation Statistics:")
			for key, value := range stats {
				fmt.Printf("  %s: %v\n", strings.ReplaceAll(key, "_", " "), value)
			}
		}
	} else {
		// Use local reservation manager
		stats := c.reservationManager.GetStats()

		if c.jsonOutput {
			c.outputSuccess(stats, "Reservation statistics")
		} else {
			fmt.Println("Reservation Statistics:")
			for key, value := range stats {
				fmt.Printf("  %s: %v\n", strings.ReplaceAll(key, "_", " "), value)
			}
		}
	}
	return nil
}

// showStats shows system statistics
func (c *CLI) showStats() error {
	if c.useRemoteAPI {
		// Get stats from remote API
		if os.Getenv("P0RT_VERBOSE") == "true" {
			fmt.Printf("Debug: Fetching stats from API...\n")
		}
		statsResponse, err := c.apiClient.GetStats()
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to get remote stats: %v", err))
			return err
		}

		if c.jsonOutput {
			statsData := map[string]interface{}{
				"connection":        "Remote API Connected",
				"global_stats":      statsResponse.GlobalStats,
				"reservation_stats": statsResponse.ReservationStats,
			}
			c.outputSuccess(statsData, "P0rt system statistics")
		} else {
			fmt.Println("=== P0rt System Statistics ===")
			fmt.Println()
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
		}
		return nil
	}

	// Local mode
	if c.jsonOutput {
		// Build JSON stats data
		storageType := c.getStorageType()
		configStats := map[string]interface{}{
			"storage_type": storageType,
			"ssh_port":     c.config.GetSSHPort(),
			"http_port":    c.config.GetHTTPPort(),
			"domain_base":  c.config.GetDomainBase(),
		}
		if storageType == "json" {
			configStats["data_directory"] = c.config.Storage.DataDir
		} else if storageType == "redis" {
			if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
				configStats["redis_url"] = redisURL
			} else if c.config.Storage.RedisURL != "" {
				configStats["redis_url"] = c.config.Storage.RedisURL
			}
			if c.config.Storage.RedisDB != 0 {
				configStats["redis_db"] = c.config.Storage.RedisDB
			}
		}

		statsData := map[string]interface{}{
			"configuration": configStats,
		}

		// Add server stats if available
		if c.statsManager != nil {
			statsData["server_stats"] = c.statsManager.GetGlobalStats()
			statsData["server_running"] = true
		} else {
			statsData["server_running"] = false
		}

		// Add reservation stats
		statsData["reservation_stats"] = c.reservationManager.GetStats()

		c.outputSuccess(statsData, "P0rt system statistics")
	} else {
		fmt.Println("=== P0rt System Statistics ===")
		fmt.Println()

		// Configuration Statistics
		fmt.Println("Configuration:")
		storageType := c.getStorageType()
		fmt.Printf("  Storage Type: %s\n", storageType)
		if storageType == "json" {
			fmt.Printf("  Data Directory: %s\n", c.config.Storage.DataDir)
		} else if storageType == "redis" {
			if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
				fmt.Printf("  Redis URL: %s\n", redisURL)
			} else if c.config.Storage.RedisURL != "" {
				fmt.Printf("  Redis URL: %s\n", c.config.Storage.RedisURL)
			}
			if c.config.Storage.RedisDB != 0 {
				fmt.Printf("  Redis DB: %d\n", c.config.Storage.RedisDB)
			}
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
	return nil
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
	if c.useRemoteAPI && c.apiClient != nil {
		// Use remote API for status
		status, err := c.apiClient.GetServerStatus()
		if err != nil {
			return fmt.Errorf("failed to get remote server status: %v", err)
		}

		if c.jsonOutput {
			c.outputSuccess(status, "Remote server status")
		} else {
			fmt.Println("Remote Server Status:")
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
		// Use local configuration
		fmt.Println("Local Configuration:")
		fmt.Printf("  SSH Port: %s\n", c.config.GetSSHPort())
		fmt.Printf("  HTTP Port: %s\n", c.config.GetHTTPPort())
		fmt.Printf("  Domain Base: %s\n", c.config.GetDomainBase())
		fmt.Printf("  Reservations Enabled: %t\n", c.config.Domain.ReservationsEnabled)
		fmt.Printf("  Storage Type: %s\n", c.config.Storage.Type)
	}
	return nil
}

// createCompleter creates an autocomplete function
func (c *CLI) createCompleter() readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("help",
			readline.PcItem("server"),
			readline.PcItem("reservation"),
			readline.PcItem("key"),
			readline.PcItem("security"),
			readline.PcItem("access"),
			readline.PcItem("abuse"),
			readline.PcItem("history"),
			readline.PcItem("connections"),
			readline.PcItem("domains"),
			readline.PcItem("stats"),
			readline.PcItem("status"),
		),
		readline.PcItem("h",
			readline.PcItem("server"),
			readline.PcItem("reservation"),
			readline.PcItem("key"),
			readline.PcItem("security"),
			readline.PcItem("access"),
			readline.PcItem("history"),
			readline.PcItem("connections"),
			readline.PcItem("domains"),
			readline.PcItem("stats"),
			readline.PcItem("status"),
		),
		readline.PcItem("server",
			readline.PcItem("start"),
			readline.PcItem("reload"),
			readline.PcItem("status"),
		),
		readline.PcItem("reservation",
			readline.PcItem("add"),
			readline.PcItem("remove", readline.PcItemDynamic(c.getDomainCompletions)),
			readline.PcItem("list"),
			readline.PcItem("stats"),
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
			readline.PcItem("unban"),
		),
		readline.PcItem("access",
			readline.PcItem("status"),
			readline.PcItem("open"),
			readline.PcItem("restricted"),
		),
		readline.PcItem("abuse",
			readline.PcItem("list"),
			readline.PcItem("report"),
			readline.PcItem("process"),
			readline.PcItem("delete"),
			readline.PcItem("stats"),
		),
		readline.PcItem("notify",
			readline.PcItem("test"),
			readline.PcItem("domain"),
		),
		readline.PcItem("history"),
		readline.PcItem("connections"),
		readline.PcItem("domains"),
		readline.PcItem("stats"),
		readline.PcItem("status"),
		readline.PcItem("clear"),
		readline.PcItem("exit"),
	)
}

// handleSecurityCommand handles security-related commands
func (c *CLI) handleSecurityCommand(args []string) error {
	if len(args) == 0 {
		fmt.Println("Security subcommands:")
		fmt.Println("  stats    - Show security statistics")
		fmt.Println("  bans     - Show banned IP addresses")
		fmt.Println("  unban    - Unban an IP address")
		return nil
	}

	switch args[0] {
	case "stats":
		return c.showSecurityStats()
	case "bans":
		return c.showSecurityBans()
	case "unban":
		return c.handleSecurityUnban(args[1:])
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
		// Get bans from remote API (use legacy method for CLI simplicity)
		bannedIPs, err := c.apiClient.GetSecurityBansLegacy()
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

// handleSecurityUnban handles IP unbanning via remote API
func (c *CLI) handleSecurityUnban(args []string) error {
	if len(args) != 1 {
		c.outputError("Usage: security unban <ip-address>")
		return nil
	}

	ip := args[0]

	if !c.useRemoteAPI {
		c.outputError("IP unbanning requires remote API access. Use remote mode:")
		fmt.Printf("  p0rt --remote http://localhost:%s cli\n", c.config.GetHTTPPort())
		return nil
	}

	// Unban via remote API
	err := c.apiClient.UnbanIP(ip)
	if err != nil {
		c.outputError(fmt.Sprintf("Failed to unban IP %s: %v", ip, err))
		return nil
	}

	if c.jsonOutput {
		data := map[string]interface{}{
			"ip":     ip,
			"action": "unbanned",
		}
		c.outputSuccess(data, fmt.Sprintf("IP %s has been unbanned", ip))
	} else {
		fmt.Printf("✅ Successfully unbanned IP: %s\n", ip)
		fmt.Printf("   The IP should now be able to connect to the server.\n")
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
	case "reload":
		return c.reloadServer()
	case "status":
		return c.serverStatus()
	default:
		return fmt.Errorf("unknown server subcommand: %s. Available: start, reload, status", subcommand)
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

// reloadServer reloads the server configuration
func (c *CLI) reloadServer() error {
	if c.useRemoteAPI && c.apiClient != nil {
		// Use remote API
		if !c.jsonOutput {
			fmt.Println("🔄 Reloading server configuration via API...")
		}

		details, err := c.apiClient.ReloadServer()
		if err != nil {
			if c.jsonOutput {
				c.outputError(fmt.Sprintf("Failed to reload server: %v", err))
			} else {
				fmt.Printf("❌ Error: %v\n", err)
			}
			return err
		}

		if c.jsonOutput {
			c.outputSuccess(details, "Server configuration reloaded")
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
		// Local mode
		if c.jsonOutput {
			c.outputError("Server reload requires remote API access or running server")
		} else {
			fmt.Println("🔄 Server reload in local mode...")
			fmt.Println("Note: Configuration reload requires the server to be running")
			fmt.Println("Use remote mode to reload a running server:")
			fmt.Printf("  p0rt --remote http://localhost:%s cli\n", c.config.GetHTTPPort())
		}
	}

	return nil
}

// serverStatus shows the server status
func (c *CLI) serverStatus() error {
	if c.useRemoteAPI && c.apiClient != nil {
		// Use remote API like the cmd/server.go implementation
		status, err := c.apiClient.GetServerStatus()
		if err != nil {
			return fmt.Errorf("failed to get server status: %v", err)
		}

		if c.jsonOutput {
			c.outputSuccess(status, "Remote server status")
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
		return nil
	}

	// Local mode
	fmt.Println("Server Status:")
	fmt.Printf("  Configuration loaded: ✓\n")
	fmt.Printf("  SSH Port: %s\n", c.config.GetSSHPort())
	fmt.Printf("  HTTP Port: %s\n", c.config.GetHTTPPort())
	fmt.Printf("  Domain Base: %s\n", c.config.GetDomainBase())
	storageType := c.getStorageType()
	fmt.Printf("  Storage Type: %s\n", storageType)
	fmt.Printf("  Reservations Enabled: %t\n", c.config.Domain.ReservationsEnabled)
	fmt.Println("  Server Status: Use 'server start' to launch")
	return nil
}

// getStorageType determines the actual storage type being used
func (c *CLI) getStorageType() string {
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
	if c.config.Storage.Type == "redis" || c.config.Storage.RedisURL != "" {
		return "redis"
	}

	// Default to JSON
	return "json"
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

	// Use API client if in remote mode
	if c.useRemoteAPI && c.apiClient != nil {
		err := c.apiClient.AddKey(fingerprint, "", comment, tier, nil)
		if err != nil {
			return fmt.Errorf("failed to add key: %v", err)
		}
	} else {
		err := c.keyStore.AddKeyByFingerprint(fingerprint, comment, tier, nil)
		if err != nil {
			return fmt.Errorf("failed to add key: %v", err)
		}
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

	// Use API client if in remote mode
	if c.useRemoteAPI && c.apiClient != nil {
		err := c.apiClient.RemoveKey(fingerprint)
		if err != nil {
			return fmt.Errorf("failed to remove key: %v", err)
		}
	} else {
		err := c.keyStore.RemoveKey(fingerprint)
		if err != nil {
			return fmt.Errorf("failed to remove key: %v", err)
		}
	}

	fmt.Printf("✅ Successfully removed SSH key: %s\n", fingerprint)
	return nil
}

// listKeys lists all authorized SSH keys
func (c *CLI) listKeys() error {
	// Use API client if in remote mode
	if c.useRemoteAPI && c.apiClient != nil {
		keys, err := c.apiClient.ListKeys()
		if err != nil {
			return fmt.Errorf("failed to list keys: %v", err)
		}

		if len(keys) == 0 {
			if c.jsonOutput {
				c.outputSuccess([]interface{}{}, "No authorized SSH keys found")
			} else {
				fmt.Println("No authorized SSH keys found")
				fmt.Println()
				fmt.Println("Add a key with:")
				fmt.Println("  key add SHA256:abc123... beta \"User Name\"")
			}
			return nil
		}

		// Convert API response to match local format
		if c.jsonOutput {
			c.outputSuccess(keys, fmt.Sprintf("Found %d authorized SSH key(s)", len(keys)))
		} else {
			fmt.Printf("Found %d authorized SSH key(s):\n\n", len(keys))
			fmt.Printf("%-55s %-10s %-11s %-20s %s\n", "Fingerprint", "Tier", "Status", "Added", "Comment")
			fmt.Println(strings.Repeat("-", 120))

			for _, key := range keys {
				status := "✅ Active"
				if !key.Active {
					status = "❌ Inactive"
				}
				if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
					status = "⏰ Expired"
				}

				fingerprint := key.Fingerprint
				if len(fingerprint) > 50 {
					fingerprint = fingerprint[:47] + "..."
				}

				fmt.Printf("%-55s %-10s %-11s %-20s %s\n",
					fingerprint,
					key.Tier,
					status,
					key.AddedAt.Format("2006-01-02 15:04:05"),
					key.Comment,
				)
			}
		}

		return nil
	}

	// Local mode - use keyStore
	keys := c.keyStore.ListKeys()

	if len(keys) == 0 {
		if c.jsonOutput {
			c.outputSuccess([]interface{}{}, "No authorized SSH keys found")
		} else {
			fmt.Println("No authorized SSH keys found")
			fmt.Println()
			fmt.Println("Add a key with:")
			fmt.Println("  key add SHA256:abc123... beta \"User Name\"")
		}
		return nil
	}

	// Convert to structured data for JSON output
	type KeyInfo struct {
		Fingerprint string     `json:"fingerprint"`
		Tier        string     `json:"tier"`
		Status      string     `json:"status"`
		Active      bool       `json:"active"`
		Expired     bool       `json:"expired"`
		AddedAt     time.Time  `json:"added_at"`
		ExpiresAt   *time.Time `json:"expires_at,omitempty"`
		Comment     string     `json:"comment"`
	}

	var keyList []KeyInfo
	for _, access := range keys {
		status := "active"
		expired := false
		if !access.Active {
			status = "inactive"
		}
		if access.ExpiresAt != nil && time.Now().After(*access.ExpiresAt) {
			status = "expired"
			expired = true
		}

		keyList = append(keyList, KeyInfo{
			Fingerprint: access.Fingerprint,
			Tier:        access.Tier,
			Status:      status,
			Active:      access.Active,
			Expired:     expired,
			AddedAt:     access.AddedAt,
			ExpiresAt:   access.ExpiresAt,
			Comment:     access.Comment,
		})
	}

	if c.jsonOutput {
		// Add metadata for JSON output
		accessMode := "restricted"
		if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
			accessMode = "open"
		}

		result := map[string]interface{}{
			"keys":        keyList,
			"total":       len(keyList),
			"access_mode": accessMode,
		}
		c.outputSuccess(result, "SSH key list")
	} else {
		// Human-readable format
		fmt.Printf("Found %d authorized SSH key(s):\n\n", len(keys))
		fmt.Printf("%-50s %-10s %-10s %-20s %s\n", "Fingerprint", "Tier", "Status", "Added", "Comment")
		fmt.Println(strings.Repeat("-", 120))

		for _, keyInfo := range keyList {
			displayStatus := "✅ Active"
			if keyInfo.Status == "inactive" {
				displayStatus = "❌ Inactive"
			} else if keyInfo.Status == "expired" {
				displayStatus = "⏰ Expired"
			}

			// Truncate long fingerprints for display
			displayFingerprint := keyInfo.Fingerprint
			if len(displayFingerprint) > 47 {
				displayFingerprint = displayFingerprint[:44] + "..."
			}

			fmt.Printf("%-50s %-10s %-10s %-20s %s\n",
				displayFingerprint,
				keyInfo.Tier,
				displayStatus,
				keyInfo.AddedAt.Format("2006-01-02 15:04:05"),
				keyInfo.Comment,
			)
		}

		fmt.Println()

		// Show access mode
		accessMode := "RESTRICTED"
		if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
			accessMode = "OPEN ACCESS"
		}
		fmt.Printf("🔒 Server is in %s mode\n", accessMode)
	}

	return nil
}

// activateKey activates a deactivated SSH key
func (c *CLI) activateKey(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: key activate <fingerprint>")
	}

	fingerprint := args[0]

	// Use API client if in remote mode
	if c.useRemoteAPI && c.apiClient != nil {
		err := c.apiClient.ActivateKey(fingerprint)
		if err != nil {
			return fmt.Errorf("failed to activate key: %v", err)
		}
	} else {
		err := c.keyStore.ActivateKey(fingerprint)
		if err != nil {
			return fmt.Errorf("failed to activate key: %v", err)
		}
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

	// Use API client if in remote mode
	if c.useRemoteAPI && c.apiClient != nil {
		err := c.apiClient.DeactivateKey(fingerprint)
		if err != nil {
			return fmt.Errorf("failed to deactivate key: %v", err)
		}
	} else {
		err := c.keyStore.DeactivateKey(fingerprint)
		if err != nil {
			return fmt.Errorf("failed to deactivate key: %v", err)
		}
	}

	fmt.Printf("✅ Successfully deactivated SSH key: %s\n", fingerprint)
	return nil
}

// handleHistoryCommand handles connection history commands
func (c *CLI) handleHistoryCommand(args []string) error {
	// Check if we're using remote API
	if c.useRemoteAPI {
		return c.handleRemoteHistory(args)
	}

	if c.statsManager == nil {
		if c.jsonOutput {
			c.outputError("History is only available when the server is running. Start the server with 'server start'")
		} else {
			fmt.Println("📊 History is only available when the server is running")
			fmt.Println("   Start the server with: server start")
		}
		return nil
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
	// Check if we're using remote API
	if c.useRemoteAPI {
		return c.showRemoteConnections()
	}

	if c.statsManager == nil {
		if c.jsonOutput {
			c.outputError("Connections view is only available when the server is running. Start the server with 'server start'")
		} else {
			fmt.Println("🔌 Connections view is only available when the server is running")
			fmt.Println("   Start the server with: server start")
		}
		return nil
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

// handleAccessCommand handles access mode management
func (c *CLI) handleAccessCommand(args []string) error {
	if len(args) == 0 {
		fmt.Println("Access subcommands:")
		fmt.Println("  status      - Show current access mode")
		fmt.Println("  open        - Switch to open access (allow all SSH keys)")
		fmt.Println("  restricted  - Switch to restricted access (allowlist only)")
		return nil
	}

	subcommand := args[0]
	switch subcommand {
	case "status":
		return c.showAccessStatus()
	case "open":
		return c.setAccessMode("open")
	case "restricted":
		return c.setAccessMode("restricted")
	default:
		return fmt.Errorf("unknown access subcommand: %s", subcommand)
	}
}

// showAccessStatus shows the current access mode
func (c *CLI) showAccessStatus() error {
	var currentMode string
	var err error

	if c.useRemoteAPI && c.apiClient != nil {
		// Use remote API
		currentMode, err = c.apiClient.GetAccessMode()
		if err != nil {
			return fmt.Errorf("failed to get access mode from remote API: %v", err)
		}
	} else {
		// Use local environment variable
		currentMode = "restricted"
		if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
			currentMode = "open"
		}
	}

	if c.jsonOutput {
		data := map[string]interface{}{
			"access_mode": currentMode,
			"open_access": currentMode == "open",
		}
		c.outputSuccess(data, "Current access mode")
	} else {
		fmt.Printf("🔒 Current access mode: %s\n", strings.ToUpper(currentMode))
		if currentMode == "open" {
			fmt.Println("   - Any SSH key can create tunnels")
		} else {
			fmt.Println("   - Only pre-authorized keys allowed")
		}
	}
	return nil
}

// setAccessMode changes the server access mode
func (c *CLI) setAccessMode(mode string) error {
	if c.useRemoteAPI {
		// Use remote API
		oldMode, err := c.apiClient.GetAccessMode()
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to get current access mode: %v", err))
			return err
		}

		if oldMode == mode {
			if c.jsonOutput {
				data := map[string]interface{}{
					"access_mode": mode,
					"changed":     false,
				}
				c.outputSuccess(data, fmt.Sprintf("Access mode already set to %s", mode))
			} else {
				fmt.Printf("✅ Access mode is already set to %s\n", strings.ToUpper(mode))
			}
			return nil
		}

		err = c.apiClient.SetAccessMode(mode)
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to change access mode: %v", err))
			return err
		}

		if c.jsonOutput {
			data := map[string]interface{}{
				"access_mode": mode,
				"changed":     true,
				"old_mode":    oldMode,
			}
			c.outputSuccess(data, fmt.Sprintf("Access mode changed from %s to %s", oldMode, mode))
		} else {
			fmt.Printf("✅ Access mode changed from %s to %s\n", strings.ToUpper(oldMode), strings.ToUpper(mode))
			fmt.Println()
			if mode == "open" {
				fmt.Println("⚠️  WARNING: Server is now in OPEN ACCESS mode")
				fmt.Println("   Any SSH key can now create tunnels")
			} else {
				fmt.Println("🔒 Server is now in RESTRICTED ACCESS mode")
				fmt.Println("   Only pre-authorized keys can create tunnels")
			}
		}
		return nil
	}

	// Local mode
	oldMode := "restricted"
	if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
		oldMode = "open"
	}

	if oldMode == mode {
		if c.jsonOutput {
			data := map[string]interface{}{
				"access_mode": mode,
				"changed":     false,
			}
			c.outputSuccess(data, fmt.Sprintf("Access mode already set to %s", mode))
		} else {
			fmt.Printf("✅ Access mode is already set to %s\n", strings.ToUpper(mode))
		}
		return nil
	}

	// Set the environment variable for the current session
	if mode == "open" {
		os.Setenv("P0RT_OPEN_ACCESS", "true")
	} else {
		os.Setenv("P0RT_OPEN_ACCESS", "false")
	}

	// Update stats manager if available
	if c.statsManager != nil {
		c.statsManager.SetAccessMode(mode)
	}

	if c.jsonOutput {
		data := map[string]interface{}{
			"access_mode": mode,
			"changed":     true,
			"old_mode":    oldMode,
		}
		c.outputSuccess(data, fmt.Sprintf("Access mode changed from %s to %s", oldMode, mode))
	} else {
		fmt.Printf("✅ Access mode changed from %s to %s\n", strings.ToUpper(oldMode), strings.ToUpper(mode))
		fmt.Println()
		if mode == "open" {
			fmt.Println("⚠️  WARNING: Server is now in OPEN ACCESS mode")
			fmt.Println("   Any SSH key can now create tunnels")
		} else {
			fmt.Println("🔒 Server is now in RESTRICTED ACCESS mode")
			fmt.Println("   Only pre-authorized keys can create tunnels")
		}
		fmt.Println()
		fmt.Println("💡 Note: This change applies to the current session only.")
		fmt.Println("   To make it permanent, update your .env file or environment variables.")
	}

	return nil
}

// handleAbuseCommand handles abuse subcommands
func (c *CLI) handleAbuseCommand(args []string) error {
	if len(args) == 0 {
		c.outputError("Abuse command requires a subcommand. Use 'help abuse' for details")
		return nil
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "list":
		return c.handleAbuseList(subArgs)
	case "report":
		return c.handleAbuseReport(subArgs)
	case "process":
		return c.handleAbuseProcess(subArgs)
	case "delete", "del":
		return c.handleAbuseDelete(subArgs)
	case "stats":
		return c.handleAbuseStats()
	default:
		c.outputError(fmt.Sprintf("Unknown abuse subcommand: %s", subcommand))
		return nil
	}
}

// handleAbuseList lists abuse reports
func (c *CLI) handleAbuseList(args []string) error {
	status := "pending"
	showAll := false

	// Parse basic flags
	for i, arg := range args {
		if arg == "--all" || arg == "-a" {
			status = ""
			showAll = true
		} else if arg == "--status" || arg == "-s" {
			if i+1 < len(args) {
				status = args[i+1]
				if status == "all" {
					status = ""
					showAll = true
				}
			}
		} else if arg == "all" && len(args) == 1 {
			// Allow "abuse list all" shortcut
			status = ""
			showAll = true
		} else if (arg == "accepted" || arg == "banned" || arg == "pending") && len(args) == 1 {
			// Allow "abuse list accepted" shortcut
			status = arg
		}
	}

	var reports interface{}
	var err error

	if c.useRemoteAPI {
		// Use remote API
		reports, err = c.apiClient.GetAbuseReports(status, showAll)
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to get abuse reports: %v", err))
			return nil
		}
	} else {
		// Use local access with proper Redis configuration
		var reportManager *security.AbuseReportManager
		storageConfig := c.config.GetStorageConfig()
		if storageConfig.Type == "redis" && storageConfig.RedisURL != "" {
			reportManager = security.NewAbuseReportManagerWithRedis(storageConfig.RedisURL)
		} else {
			reportManager = security.NewAbuseReportManager()
		}

		localReports, err := reportManager.ListReports(status)
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to get abuse reports: %v", err))
			return nil
		}
		reports = localReports
	}

	// Handle different return types from API vs local
	var reportsList []*security.AbuseReport
	var count int

	if c.useRemoteAPI {
		// reports is []interface{} from API
		if apiReports, ok := reports.([]interface{}); ok {
			count = len(apiReports)
			// Convert to display format for consistency
			reportsList = make([]*security.AbuseReport, 0, count)
			// For remote API, we'll display differently since we can't convert to struct easily
		} else {
			count = 0
		}
	} else {
		// reports is []*security.AbuseReport from local
		if localReports, ok := reports.([]*security.AbuseReport); ok {
			reportsList = localReports
			count = len(reportsList)
		} else {
			count = 0
		}
	}

	if c.jsonOutput {
		data := map[string]interface{}{
			"reports": reports,
			"count":   count,
			"status":  status,
		}
		c.outputSuccess(data, "Abuse reports")
		return nil
	}

	if count == 0 {
		if status == "" {
			fmt.Println("No abuse reports found")
		} else {
			fmt.Printf("No %s abuse reports found\n", status)
		}
		return nil
	}

	statusLabel := status
	if statusLabel == "" {
		statusLabel = "all"
	}
	fmt.Printf("=== Abuse Reports (%s) ===\n\n", strings.Title(statusLabel))

	if c.useRemoteAPI {
		// Display API results (simpler format)
		if apiReports, ok := reports.([]interface{}); ok {
			for i, item := range apiReports {
				if report, ok := item.(map[string]interface{}); ok {
					fmt.Printf("%d. ID: %s\n", i+1, getString(report, "id"))
					fmt.Printf("   Domain: %s\n", getString(report, "domain"))
					fmt.Printf("   Reporter: %s\n", getString(report, "reporter_ip"))
					fmt.Printf("   Reason: %s\n", getString(report, "reason"))
					fmt.Printf("   Status: %s\n", getString(report, "status"))
					fmt.Printf("   Reported: %s\n", getTimeString(report, "reported_at"))
					fmt.Println()
				}
			}
		}
	} else {
		// Display local results
		for i, report := range reportsList {
			fmt.Printf("%d. ID: %s\n", i+1, report.ID)
			fmt.Printf("   Domain: %s\n", report.Domain)
			fmt.Printf("   Reporter: %s\n", report.ReporterIP)
			fmt.Printf("   Reason: %s\n", report.Reason)
			fmt.Printf("   Status: %s\n", report.Status)
			fmt.Printf("   Reported: %s\n", report.ReportedAt.Format("2006-01-02 15:04:05"))
			if report.ProcessedAt != nil {
				fmt.Printf("   Processed: %s\n", report.ProcessedAt.Format("2006-01-02 15:04:05"))
			}
			fmt.Println()
		}
	}

	fmt.Printf("Total: %d reports\n", count)
	return nil
}

// handleAbuseReport submits a new abuse report
func (c *CLI) handleAbuseReport(args []string) error {
	if len(args) < 1 {
		c.outputError("Usage: abuse report <domain> [reason]")
		return nil
	}

	domain := args[0]
	reason := "Testing - submitted via CLI"
	if len(args) > 1 {
		reason = strings.Join(args[1:], " ")
		// Remove quotes if present
		reason = strings.Trim(reason, "\"'")
	}

	// Create abuse report manager with proper Redis configuration
	var reportManager *security.AbuseReportManager
	if c.useRemoteAPI {
		c.outputError("Report submission via remote API not yet implemented. Use local CLI mode.")
		return nil
	} else {
		storageConfig := c.config.GetStorageConfig()
		if storageConfig.Type == "redis" && storageConfig.RedisURL != "" {
			reportManager = security.NewAbuseReportManagerWithRedis(storageConfig.RedisURL)
		} else {
			reportManager = security.NewAbuseReportManager()
		}
	}

	// Use current client IP or a default testing IP
	reporterIP := "127.0.0.1" // Default for local testing

	report, err := reportManager.SubmitReport(domain, reporterIP, reason, "Submitted via CLI for testing")
	if err != nil {
		c.outputError(fmt.Sprintf("Failed to submit abuse report: %v", err))
		return nil
	}

	if c.jsonOutput {
		data := map[string]interface{}{
			"report_id": report.ID,
			"domain":    report.Domain,
			"reason":    report.Reason,
			"status":    report.Status,
		}
		c.outputSuccess(data, "Abuse report submitted")
	} else {
		fmt.Printf("✅ Abuse report submitted successfully\n")
		fmt.Printf("   Report ID: %s\n", report.ID)
		fmt.Printf("   Domain: %s\n", report.Domain)
		fmt.Printf("   Reason: %s\n", report.Reason)
		fmt.Printf("   Status: %s\n", report.Status)
		fmt.Printf("\n💡 Process this report with:\n")
		fmt.Printf("   abuse process %s ban\n", report.ID)
	}

	return nil
}

// handleAbuseDelete deletes/archives an abuse report and performs cleanup
func (c *CLI) handleAbuseDelete(args []string) error {
	if len(args) != 1 {
		c.outputError("Usage: abuse delete <report-id>")
		return nil
	}

	reportID := args[0]

	// Get report details first
	var report map[string]interface{}

	if c.useRemoteAPI {
		// Get report via API first
		reports, err := c.apiClient.GetAbuseReports("", true)
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to get abuse reports: %v", err))
			return nil
		}

		// Find the report
		var found bool
		if reportsList, ok := reports.([]interface{}); ok {
			for _, r := range reportsList {
				if reportMap, ok := r.(map[string]interface{}); ok {
					if id, ok := reportMap["id"].(string); ok && id == reportID {
						report = reportMap
						found = true
						break
					}
				}
			}
		}

		if !found {
			c.outputError(fmt.Sprintf("Report not found: %s", reportID))
			return nil
		}

		// Delete via API
		err = c.apiClient.DeleteAbuseReport(reportID)
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to archive report: %v", err))
			return nil
		}
	} else {
		// Create report manager with proper Redis configuration
		var reportManager *security.AbuseReportManager
		storageConfig := c.config.GetStorageConfig()
		if storageConfig.Type == "redis" && storageConfig.RedisURL != "" {
			reportManager = security.NewAbuseReportManagerWithRedis(storageConfig.RedisURL)
		} else {
			reportManager = security.NewAbuseReportManager()
		}

		actualReport, err := reportManager.GetReport(reportID)
		if err != nil {
			c.outputError(fmt.Sprintf("Report not found: %v", err))
			return nil
		}

		// Convert to map for consistent display
		report = map[string]interface{}{
			"domain":      actualReport.Domain,
			"status":      actualReport.Status,
			"reporter_ip": actualReport.ReporterIP,
		}

		// Archive the report (this will perform cleanup if it was banned)
		err = reportManager.ArchiveReport(reportID, "cli-admin")
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to archive report: %v", err))
			return nil
		}
	}

	if c.jsonOutput {
		data := map[string]interface{}{
			"report_id": reportID,
			"action":    "archived",
			"domain":    getString(report, "domain"),
			"status":    getString(report, "status"),
		}
		c.outputSuccess(data, "Report archived and cleanup performed")
	} else {
		fmt.Printf("✅ Report %s has been archived\n", reportID)
		fmt.Printf("   Domain: %s\n", getString(report, "domain"))
		fmt.Printf("   Previous Status: %s\n", getString(report, "status"))

		if getString(report, "status") == "banned" {
			fmt.Printf("   🔄 Cleanup performed:\n")
			fmt.Printf("     - IP %s has been unbanned\n", getString(report, "reporter_ip"))
			fmt.Printf("     - Domain %s is no longer banned\n", getString(report, "domain"))
			fmt.Printf("     - Redis ban keys cleared\n")
		}

		fmt.Printf("   📁 Report marked as 'archived' for record keeping\n")
	}

	return nil
}

// handleAbuseProcess processes an abuse report
func (c *CLI) handleAbuseProcess(args []string) error {
	if len(args) != 2 {
		c.outputError("Usage: abuse process [report-id] [ban|accept]")
		return nil
	}

	reportID := args[0]
	action := args[1]

	if action != "ban" && action != "accept" {
		c.outputError("Action must be 'ban' or 'accept'")
		return nil
	}

	var err error

	if c.useRemoteAPI {
		// Use remote API
		err = c.apiClient.ProcessAbuseReport(reportID, action)
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to process report: %v", err))
			return nil
		}
	} else {
		// Use local access
		reportManager := security.NewAbuseReportManager()

		// Get the report first to show details
		report, err := reportManager.GetReport(reportID)
		if err != nil {
			c.outputError(fmt.Sprintf("Report not found: %v", err))
			return nil
		}

		if report.Status != "pending" {
			c.outputError(fmt.Sprintf("Report already processed (status: %s)", report.Status))
			return nil
		}

		err = reportManager.ProcessReport(reportID, action, "admin")
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to process report: %v", err))
			return nil
		}
	}

	if c.jsonOutput {
		data := map[string]interface{}{
			"report_id": reportID,
			"action":    action,
		}
		c.outputSuccess(data, fmt.Sprintf("Report %s processed", action))
	} else {
		fmt.Printf("✅ Report %s processed: %s\n", reportID, action)

		if action == "ban" {
			fmt.Printf("   🚫 Domain has been banned\n")
		} else {
			fmt.Printf("   ✅ Report dismissed - domain accepted\n")
		}
	}

	return nil
}

// handleAbuseStats shows abuse report statistics
func (c *CLI) handleAbuseStats() error {
	var stats interface{}
	var err error

	if c.useRemoteAPI {
		// Use remote API
		stats, err = c.apiClient.GetAbuseStats()
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to get abuse statistics: %v", err))
			return nil
		}
	} else {
		// Use local access
		reportManager := security.NewAbuseReportManager()
		stats = reportManager.GetStats()
	}

	if c.jsonOutput {
		c.outputSuccess(stats, "Abuse report statistics")
		return nil
	}

	statsMap, ok := stats.(map[string]interface{})
	if !ok {
		c.outputError("Invalid statistics format")
		return nil
	}

	fmt.Println("=== Abuse Report Statistics ===")
	fmt.Printf("Total Reports: %v\n", statsMap["total_reports"])
	fmt.Printf("Pending: %v\n", statsMap["pending_reports"])
	fmt.Printf("Banned: %v\n", statsMap["banned_reports"])
	fmt.Printf("Accepted: %v\n", statsMap["accepted_reports"])
	fmt.Printf("Redis Available: %v\n", statsMap["redis_available"])

	return nil
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

// Helper functions for parsing API responses
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getTimeString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		// Parse and reformat the time
		if t, err := time.Parse(time.RFC3339, val); err == nil {
			return t.Format("2006-01-02 15:04")
		}
		return val
	}
	return ""
}

// handleRemoteHistory handles history command via remote API
func (c *CLI) handleRemoteHistory(args []string) error {
	limit := 20
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			limit = n
		}
	}

	history, err := c.apiClient.GetHistory(limit)
	if err != nil {
		c.outputError(fmt.Sprintf("Failed to get history from remote server: %v", err))
		return nil
	}

	if len(history) == 0 {
		if c.jsonOutput {
			c.outputSuccess([]interface{}{}, "No connection history found")
		} else {
			fmt.Println("No connection history found")
		}
		return nil
	}

	if c.jsonOutput {
		c.outputSuccess(history, fmt.Sprintf("Connection history (last %d)", limit))
		return nil
	}

	// Human-readable format
	fmt.Printf("=== Connection History (Last %d) ===\n\n", limit)

	for i, record := range history {
		fmt.Printf("%d. Domain: %s\n", i+1, record.Domain)
		fmt.Printf("   Client IP: %s\n", record.ClientIP)
		fmt.Printf("   Connected: %s\n", record.ConnectedAt.Format("2006-01-02 15:04:05"))

		if record.DisconnectedAt != nil {
			fmt.Printf("   Disconnected: %s\n", record.DisconnectedAt.Format("2006-01-02 15:04:05"))
			duration := record.DisconnectedAt.Sub(record.ConnectedAt)
			fmt.Printf("   Duration: %s\n", duration.Round(time.Second))
		} else {
			// Still connected
			fmt.Printf("   Status: Still connected\n")
			duration := time.Since(record.ConnectedAt)
			fmt.Printf("   Duration: %s\n", duration.Round(time.Second))
		}

		fmt.Printf("   Bytes In: %s\n", stats.FormatBytes(record.BytesIn))
		fmt.Printf("   Bytes Out: %s\n", stats.FormatBytes(record.BytesOut))
		fmt.Printf("   Requests: %d\n", record.RequestCount)
		fmt.Println()
	}

	return nil
}

// showRemoteConnections shows connections via remote API
func (c *CLI) showRemoteConnections() error {
	connections, err := c.apiClient.GetConnections()
	if err != nil {
		c.outputError(fmt.Sprintf("Failed to get connections from remote server: %v", err))
		return nil
	}

	if len(connections) == 0 {
		if c.jsonOutput {
			c.outputSuccess([]interface{}{}, "No active connections")
		} else {
			fmt.Println("No active connections")
		}
		return nil
	}

	if c.jsonOutput {
		c.outputSuccess(connections, fmt.Sprintf("Active connections (%d)", len(connections)))
		return nil
	}

	// Human-readable format
	fmt.Printf("=== Active Connections (%d) ===\n\n", len(connections))

	for i, conn := range connections {
		fmt.Printf("%d. Domain: %s\n", i+1, conn.Domain)
		fmt.Printf("   Client IP: %s\n", conn.ClientIP)
		fmt.Printf("   Connected: %s\n", conn.ConnectedAt.Format("2006-01-02 15:04:05"))

		duration := time.Since(conn.ConnectedAt)
		fmt.Printf("   Duration: %s\n", duration.Round(time.Second))

		fmt.Printf("   Bandwidth In: %s\n", stats.FormatBytes(conn.BytesIn))
		fmt.Printf("   Bandwidth Out: %s\n", stats.FormatBytes(conn.BytesOut))
		fmt.Printf("   Requests: %d\n", conn.RequestCount)
		fmt.Println()
	}

	return nil
}

// handleNotifyCommand handles notify subcommands
func (c *CLI) handleNotifyCommand(args []string) error {
	if len(args) == 0 {
		fmt.Println("📨 Notify subcommands:")
		fmt.Println("  test [message]                           - Send test notification")
		fmt.Println("  domain <domain> [--type <type>] [--message <msg>] [--reason <reason>]")
		fmt.Println("                                           - Send notification to specific domain")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  notify test")
		fmt.Println("  notify test \"Custom test message\"")
		fmt.Println("  notify domain happy-cat-123 --type ban --reason \"spam\"")
		fmt.Println("  notify domain happy-cat-123 --message \"Maintenance in 5 minutes\"")
		return nil
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "test":
		return c.handleNotifyTest(subArgs)
	case "domain":
		return c.handleNotifyDomain(subArgs)
	default:
		return fmt.Errorf("unknown notify subcommand: %s. Use 'help notify' for available commands", subcommand)
	}
}

// handleNotifyTest sends a test notification
func (c *CLI) handleNotifyTest(args []string) error {
	if !c.useRemoteAPI || c.apiClient == nil {
		c.outputError("Notify commands require remote API connection. Use --remote flag or configure remote API")
		return nil
	}

	message := "Test notification from P0rt CLI"
	if len(args) > 0 {
		message = strings.Join(args, " ")
	}

	notification, err := c.apiClient.TestNotification(message)
	if err != nil {
		c.outputError(fmt.Sprintf("Failed to send test notification: %v", err))
		return nil
	}

	if c.jsonOutput {
		c.outputSuccess(notification, "Test notification sent")
		return nil
	}

	fmt.Printf("✅ Test notification sent successfully!\n")
	fmt.Printf("📋 Message: %s\n", message)
	fmt.Printf("⏰ Sent at: %s\n", notification.Timestamp)
	return nil
}

// handleNotifyDomain sends a notification to a specific domain
func (c *CLI) handleNotifyDomain(args []string) error {
	if !c.useRemoteAPI || c.apiClient == nil {
		c.outputError("Notify commands require remote API connection. Use --remote flag or configure remote API")
		return nil
	}

	if len(args) == 0 {
		c.outputError("Usage: notify domain <domain> [options]")
		return nil
	}

	domain := args[0]

	// Parse simple flags from remaining args
	var notifyType, message, reason string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--type":
			if i+1 < len(args) {
				notifyType = args[i+1]
				i++
			}
		case "--message":
			if i+1 < len(args) {
				// Join all remaining args as the message
				message = strings.Join(args[i+1:], " ")
				i = len(args) // Skip to end
			}
		case "--reason":
			if i+1 < len(args) {
				// Join all remaining args as the reason
				reason = strings.Join(args[i+1:], " ")
				i = len(args) // Skip to end
			}
		}
	}

	// Determine notification type and send appropriate notification
	if notifyType == "ban" || (notifyType == "" && reason != "") {
		// Send ban notification
		notification, err := c.apiClient.BanDomainNotification(domain, reason)
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to send ban notification: %v", err))
			return nil
		}

		if c.jsonOutput {
			c.outputSuccess(notification, "Ban notification sent")
			return nil
		}

		fmt.Printf("🚫 Ban notification sent successfully!\n")
		fmt.Printf("📋 Domain: %s\n", domain)
		if reason != "" {
			fmt.Printf("💬 Reason: %s\n", reason)
		}
		fmt.Printf("⏰ Sent at: %s\n", notification.Timestamp)
	} else {
		// Send general notification via ban API with custom message as reason
		if message == "" {
			message = fmt.Sprintf("Notification for domain %s", domain)
		}

		// Use BanDomainNotification API which actually sends to SSH clients
		notification, err := c.apiClient.BanDomainNotification(domain, message)
		if err != nil {
			c.outputError(fmt.Sprintf("Failed to send notification: %v", err))
			return nil
		}

		if c.jsonOutput {
			c.outputSuccess(notification, "Notification sent")
			return nil
		}

		fmt.Printf("📨 Notification sent successfully!\n")
		fmt.Printf("📋 Domain: %s\n", domain)
		fmt.Printf("💬 Message: %s\n", message)
		fmt.Printf("⏰ Sent at: %s\n", notification.Timestamp)
	}

	return nil
}

// handleDomainsCommand handles the domains command
func (c *CLI) handleDomainsCommand(args []string) error {
	page := 1
	perPage := 20

	// Parse arguments
	for _, arg := range args {
		if strings.HasPrefix(arg, "--page=") {
			if p, err := strconv.Atoi(strings.TrimPrefix(arg, "--page=")); err == nil && p > 0 {
				page = p
			}
		} else if strings.HasPrefix(arg, "--per-page=") {
			if pp, err := strconv.Atoi(strings.TrimPrefix(arg, "--per-page=")); err == nil && pp > 0 && pp <= 100 {
				perPage = pp
			}
		} else if arg != "" {
			// Try to parse as page number
			if p, err := strconv.Atoi(arg); err == nil && p > 0 {
				page = p
			}
		}
	}

	// Check if we should use remote API
	if !c.useRemoteAPI || c.apiClient == nil {
		c.outputError("Domains command requires remote API access. Use remote mode:")
		fmt.Printf("  p0rt --remote http://localhost:%s domains\n", c.config.GetHTTPPort())
		return nil
	}

	// Make request using apiClient
	response, err := c.apiClient.GetDomains(page, perPage)
	if err != nil {
		return fmt.Errorf("failed to fetch domains: %v", err)
	}

	if c.jsonOutput {
		c.outputSuccess(response, "Domains listed")
		return nil
	}

	// Display results
	fmt.Printf("🌐 Domains (Page %d/%d, Total: %d)\n", response.Page, response.TotalPages, response.Total)
	fmt.Println()

	if len(response.Domains) == 0 {
		fmt.Println("No domains found.")
		return nil
	}

	// Table header with better spacing
	fmt.Printf("%-22s %-3s %-20s %-6s %-8s %-10s %s\n",
		"DOMAIN", "TRI", "LAST IP", "ACTIVE", "REQUESTS", "TRAFFIC", "LAST SEEN")
	fmt.Println(strings.Repeat("-", 85))

	// Display each domain
	for _, domain := range response.Domains {
		trigram := domain.Domain[:3]
		if len(domain.Domain) < 3 {
			trigram = domain.Domain
		}

		active := "❌"
		if domain.IsActive {
			active = "✅"
		}

		traffic := formatBytes(domain.BytesTransferred)
		lastSeen := formatTimeAgoFromTime(domain.LastSeen)

		lastIP := domain.LastConnectionIP
		if lastIP == "" {
			lastIP = "N/A"
		} else {
			// Truncate very long IPv6 addresses for better display
			if len(lastIP) > 18 {
				lastIP = lastIP[:15] + "..."
			}
		}

		// Truncate domain name if too long
		displayDomain := domain.Domain
		if len(displayDomain) > 20 {
			displayDomain = displayDomain[:17] + "..."
		}

		fmt.Printf("%-22s %-3s %-20s %-6s %-8d %-10s %s\n",
			displayDomain, trigram, lastIP, active, domain.RequestCount, traffic, lastSeen)

		// Show SSH key fingerprint on second line with better formatting
		fingerprint := domain.SSHKeyFingerprint
		if fingerprint == "" {
			fingerprint = domain.SSHKeyHash[:12] + "..."
		} else {
			// Truncate long fingerprints
			if len(fingerprint) > 50 {
				fingerprint = fingerprint[:47] + "..."
			}
		}
		fmt.Printf("  🔑 %s (used %d times)\n", fingerprint, domain.UseCount)
		fmt.Println()
	}

	// Pagination info
	if response.TotalPages > 1 {
		fmt.Printf("Page %d of %d", response.Page, response.TotalPages)
		if response.HasPrev {
			fmt.Printf(" | Previous: domains %d", response.Page-1)
		}
		if response.HasNext {
			fmt.Printf(" | Next: domains %d", response.Page+1)
		}
		fmt.Println()
	}

	return nil
}

// formatBytes formats bytes into human readable format
func formatBytes(bytes int64) string {
	if bytes == 0 {
		return "0 B"
	}

	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatTimeAgo formats a time string into relative time
func formatTimeAgo(timeStr string) string {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return timeStr
	}

	duration := time.Since(t)
	if duration < time.Minute {
		return "just now"
	} else if duration < time.Hour {
		return fmt.Sprintf("%dm ago", int(duration.Minutes()))
	} else if duration < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(duration.Hours()))
	} else {
		return fmt.Sprintf("%dd ago", int(duration.Hours()/24))
	}
}

// formatTimeAgoFromTime formats a time.Time into relative time
func formatTimeAgoFromTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}

	duration := time.Since(t)
	
	// Handle negative durations (future dates) or very large durations
	if duration < 0 {
		return "future"
	}
	
	// Handle very old dates (more than 10 years ago)
	if duration > 365*24*10*time.Hour {
		return "very old"
	}
	
	if duration < time.Minute {
		return "just now"
	} else if duration < time.Hour {
		return fmt.Sprintf("%dm ago", int(duration.Minutes()))
	} else if duration < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(duration.Hours()))
	} else if duration < 30*24*time.Hour {
		return fmt.Sprintf("%dd ago", int(duration.Hours()/24))
	} else if duration < 365*24*time.Hour {
		return fmt.Sprintf("%d months ago", int(duration.Hours()/(24*30)))
	} else {
		return fmt.Sprintf("%d years ago", int(duration.Hours()/(24*365)))
	}
}
