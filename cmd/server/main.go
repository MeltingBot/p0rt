package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/p0rt/p0rt/internal/api"
	"github.com/p0rt/p0rt/internal/auth"
	"github.com/p0rt/p0rt/internal/cli"
	"github.com/p0rt/p0rt/internal/config"
	"github.com/p0rt/p0rt/internal/domain"
	"github.com/p0rt/p0rt/internal/proxy"
	"github.com/p0rt/p0rt/internal/ssh"
	"github.com/p0rt/p0rt/internal/tcp"

	cryptossh "golang.org/x/crypto/ssh"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Parse command line flags
	var (
		serverAction      = flag.String("server", "", "Server action: start, stop, restart, status")
		reservationAction = flag.String("reservation", "", "Reservation action: add, remove, list, stats")
		keyAction         = flag.String("key", "", "SSH key management: add, remove, list, import, activate, deactivate")
		domainName        = flag.String("domain", "", "Domain name for reservation operations")
		fingerprint       = flag.String("fingerprint", "", "SSH key fingerprint for reservations")
		comment           = flag.String("comment", "", "Comment for reservation")
		configFile        = flag.String("config", "", "Path to configuration file")
		interactive       = flag.Bool("cli", false, "Start interactive CLI mode")
		remoteURL         = flag.String("remote", "", "Remote server URL for API access (e.g., http://localhost:80)")
		apiKey            = flag.String("api-key", "", "API key for remote server authentication")
		
		// SSH key management specific flags
		keyFile           = flag.String("key-file", "", "SSH public key file to add")
		keyString         = flag.String("key-string", "", "SSH public key string")
		keyFingerprint    = flag.String("key-fingerprint", "", "SSH key fingerprint to add (simpler than key file)")
		tier              = flag.String("tier", "free", "Access tier: beta, free, premium, vip")
		importFile        = flag.String("import-file", "", "File to import keys from (authorized_keys format)")
		expires           = flag.String("expires", "", "Expiration date (RFC3339 format)")
		keysFile          = flag.String("keys-file", "", "Path to authorized keys file")

		// Short form aliases for common options
		serverShort      = flag.String("s", "", "Short form of -server")
		reservationShort = flag.String("r", "", "Short form of -reservation")
		keyShort         = flag.String("K", "", "Short form of -key")
		domainShort      = flag.String("d", "", "Short form of -domain")
		fingerprintShort = flag.String("f", "", "Short form of -fingerprint")
		commentShort     = flag.String("c", "", "Short form of -comment")
		configShort      = flag.String("C", "", "Short form of -config")
		interactiveShort = flag.Bool("i", false, "Short form of -cli")
		remoteShort      = flag.String("R", "", "Short form of -remote")
		apiKeyShort      = flag.String("k", "", "Short form of -api-key")
	)
	flag.Parse()

	// Merge short and long form flags (short form takes precedence if both are provided)
	if *serverShort != "" {
		*serverAction = *serverShort
	}
	if *reservationShort != "" {
		*reservationAction = *reservationShort
	}
	if *keyShort != "" {
		*keyAction = *keyShort
	}
	if *domainShort != "" {
		*domainName = *domainShort
	}
	if *fingerprintShort != "" {
		*fingerprint = *fingerprintShort
	}
	if *commentShort != "" {
		*comment = *commentShort
	}
	if *configShort != "" {
		*configFile = *configShort
	}
	if *interactiveShort {
		*interactive = *interactiveShort
	}
	if *remoteShort != "" {
		*remoteURL = *remoteShort
	}
	if *apiKeyShort != "" {
		*apiKey = *apiKeyShort
	}

	// Set config file environment variable if provided
	if *configFile != "" {
		os.Setenv("CONFIG_FILE", *configFile)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Printf("Failed to load config file, using defaults: %v", err)
		cfg = config.LoadDefault()
	}

	// Create server start function for CLI
	serverStartFunc := func() error {
		return startServer(cfg)
	}

	// Handle interactive CLI mode
	if *interactive {
		var cliInstance *cli.CLI
		var err error

		if *remoteURL != "" {
			// Use remote API
			fmt.Printf("Connecting to remote P0rt server at %s...\n", *remoteURL)
			cliInstance, err = cli.NewCLIWithRemoteAPI(cfg, *remoteURL, *apiKey)
			if err != nil {
				log.Fatalf("Failed to connect to remote API: %v", err)
			}
			fmt.Println("Connected! You can now manage the remote server.")
		} else {
			// Use local mode
			cliInstance, err = cli.NewCLIWithServerFunc(cfg, serverStartFunc)
			if err != nil {
				log.Fatalf("Failed to create CLI: %v", err)
			}
		}

		if err := cliInstance.Start(); err != nil {
			log.Fatalf("CLI error: %v", err)
		}
		return
	}

	// Handle server commands
	if *serverAction != "" {
		handleServerCommand(cfg, *serverAction)
		return
	}

	// Handle reservation commands
	if *reservationAction != "" {
		if *remoteURL != "" {
			// Use remote API for reservation commands
			handleRemoteReservationCommand(*remoteURL, *apiKey, *reservationAction, *domainName, *fingerprint, *comment)
		} else {
			// Use local storage for reservation commands
			handleReservationCommand(cfg, *reservationAction, *domainName, *fingerprint, *comment)
		}
		return
	}

	// Handle SSH key commands
	if *keyAction != "" {
		handleKeyCommand(*keyAction, *keyFile, *keyString, *keyFingerprint, *comment, *tier, *fingerprint, *importFile, *expires, *keysFile)
		return
	}

	// Default action: show help
	showHelp()
}

// showHelp displays usage information
func showHelp() {
	fmt.Println("P0rt - SSH tunneling service")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  p0rt [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -s, -server <action>        Server management (start, stop, restart, status)")
	fmt.Println("  -r, -reservation <action>   Domain reservation management (add, remove, list, stats)")
	fmt.Println("  -K, -key <action>           SSH key management (add, remove, list, import, activate, deactivate)")
	fmt.Println("  -d, -domain <name>          Domain name for reservation operations")
	fmt.Println("  -f, -fingerprint <fp>       SSH key fingerprint for reservations/keys")
	fmt.Println("  -c, -comment <text>         Comment for reservation/key")
	fmt.Println("  -C, -config <file>          Path to configuration file")
	fmt.Println("  -i, -cli                    Start interactive CLI mode")
	fmt.Println("  -R, -remote <url>           Remote server URL for API access")
	fmt.Println("  -k, -api-key <key>          API key for remote server authentication")
	fmt.Println()
	fmt.Println("SSH Key Management Options:")
	fmt.Println("  --key-file <file>           SSH public key file to add")
	fmt.Println("  --key-string <key>          SSH public key string")
	fmt.Println("  --key-fingerprint <fp>      SSH key fingerprint to add (simpler)")
	fmt.Println("  --tier <tier>               Access tier (beta, free, premium, vip)")
	fmt.Println("  --import-file <file>        File to import keys from (authorized_keys format)")
	fmt.Println("  --expires <date>            Expiration date (RFC3339 format)")
	fmt.Println("  --keys-file <file>          Path to authorized keys file")
	fmt.Println()
	fmt.Println("Local Examples:")
	fmt.Println("  p0rt -s start                           # Start the server")
	fmt.Println("  p0rt -server status                     # Show server status")
	fmt.Println("  p0rt -i                                 # Interactive mode (local)")
	fmt.Println("  p0rt -r list                            # List domain reservations (local)")
	fmt.Println("  p0rt -r add -d happy-cat-jump -f SHA256:abc123...")
	fmt.Println("  p0rt -K add --key-file ~/.ssh/id_rsa.pub --tier beta")
	fmt.Println("  p0rt -K add --key-fingerprint SHA256:abc123... --tier beta  # Simpler")
	fmt.Println("  p0rt -K list                            # List authorized SSH keys")
	fmt.Println("  p0rt -K import --import-file keys.txt --tier free")
	fmt.Println()
	fmt.Println("Remote Examples:")
	fmt.Println("  p0rt -i -R http://localhost:80                      # Interactive mode (remote)")
	fmt.Println("  p0rt -R http://localhost:80 -r list                 # List reservations (remote)")
	fmt.Println("  p0rt -R http://localhost:80 -k secret -r add -d my-domain -f SHA256:abc123...")
	fmt.Println()
	fmt.Println("Long form examples:")
	fmt.Println("  p0rt -server start")
	fmt.Println("  p0rt -reservation list -remote http://localhost:80 -api-key secret")
	fmt.Println()
	fmt.Println("For more information, visit: https://p0rt.xyz")
}

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

// handleReservationCommand handles domain reservation management commands
func handleReservationCommand(cfg *config.Config, action, domainName, fingerprint, comment string) {
	// Create reservation manager based on storage configuration
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
		log.Fatalf("Unsupported storage type: %s", storageConfig.Type)
	}

	if err != nil {
		log.Fatalf("Failed to create reservation manager: %v", err)
	}

	// Execute the requested action
	switch action {
	case "add":
		if domainName == "" || fingerprint == "" {
			fmt.Println("Usage: p0rt -reservation add -domain <domain> -fingerprint <fingerprint> [-comment <comment>]")
			fmt.Println("Example: p0rt -reservation add -domain happy-cat-jump -fingerprint SHA256:abc123... -comment 'My personal domain'")
			os.Exit(1)
		}
		err = reservationManager.AddReservation(domainName, fingerprint, comment)
		if err != nil {
			log.Fatalf("Failed to add reservation: %v", err)
		}
		fmt.Printf("✓ Successfully reserved domain '%s' for SSH key fingerprint '%s'\n", domainName, fingerprint)

	case "remove":
		if domainName == "" {
			fmt.Println("Usage: p0rt -reservation remove -domain <domain>")
			fmt.Println("Example: p0rt -reservation remove -domain happy-cat-jump")
			os.Exit(1)
		}
		err = reservationManager.RemoveReservation(domainName)
		if err != nil {
			log.Fatalf("Failed to remove reservation: %v", err)
		}
		fmt.Printf("✓ Successfully removed reservation for domain '%s'\n", domainName)

	case "list":
		reservations := reservationManager.ListReservations()
		if len(reservations) == 0 {
			fmt.Println("No reservations found")
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

	case "stats":
		stats := reservationManager.GetStats()
		fmt.Println("Reservation Statistics:")
		for key, value := range stats {
			fmt.Printf("  %s: %v\n", strings.ReplaceAll(key, "_", " "), value)
		}

	default:
		fmt.Println("Available reservation actions:")
		fmt.Println("  add     - Reserve a domain for an SSH key")
		fmt.Println("  remove  - Remove a domain reservation")
		fmt.Println("  list    - List all reservations")
		fmt.Println("  stats   - Show reservation statistics")
		fmt.Println("\nExamples:")
		fmt.Println("  p0rt -reservation add -domain happy-cat-jump -fingerprint SHA256:abc123...")
		fmt.Println("  p0rt -reservation list")
		fmt.Println("  p0rt -reservation remove -domain happy-cat-jump")
		fmt.Println("  p0rt -reservation stats")
		os.Exit(1)
	}
}

// startServer starts the P0rt server with the given configuration
func startServer(cfg *config.Config) error {
	log.Println("Starting P0rt...")
	log.Printf("SSH Port: %s", cfg.GetSSHPort())
	log.Printf("HTTP Port: %s", cfg.GetHTTPPort())
	log.Printf("Domain Base: %s", cfg.GetDomainBase())

	// Create domain generator with storage configuration
	storageConfig := cfg.GetStorageConfig()
	log.Printf("Storage Type: %s", storageConfig.Type)
	if storageConfig.Type == "redis" {
		log.Printf("Redis URL: %s", storageConfig.RedisURL)
	} else {
		log.Printf("Data Dir: %s", storageConfig.DataDir)
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
	if apiKey != "" {
		log.Printf("API Key configured for authentication")
	} else {
		log.Printf("No API Key configured - API will accept all requests")
	}
	httpProxy := proxy.NewHTTPProxyWithAPI(sshServerAdapter, domainGen.GetReservationManager(), sshServer.GetStats(), apiKey)

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
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		return nil
	}
}

// handleServerCommand handles server management commands
func handleServerCommand(cfg *config.Config, action string) {
	switch action {
	case "start":
		fmt.Println("Starting P0rt server...")
		if err := startServer(cfg); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	case "stop":
		fmt.Println("Server stop functionality not yet implemented")
		fmt.Println("Use Ctrl+C to stop the server if running")
	case "restart":
		fmt.Println("Server restart functionality not yet implemented")
	case "status":
		fmt.Println("Server Status:")
		fmt.Printf("  SSH Port: %s\n", cfg.GetSSHPort())
		fmt.Printf("  HTTP Port: %s\n", cfg.GetHTTPPort())
		fmt.Printf("  Domain Base: %s\n", cfg.GetDomainBase())
		fmt.Printf("  Storage Type: %s\n", cfg.Storage.Type)
		fmt.Printf("  Reservations Enabled: %t\n", cfg.Domain.ReservationsEnabled)
		fmt.Println("  Server Status: Use 'p0rt -server start' to launch")
	default:
		fmt.Printf("Unknown server action: %s\n", action)
		fmt.Println("Available actions: start, stop, restart, status")
		fmt.Println("Examples:")
		fmt.Println("  p0rt -server start")
		fmt.Println("  p0rt -server status")
		os.Exit(1)
	}
}

// handleRemoteReservationCommand handles domain reservation management commands via API
func handleRemoteReservationCommand(serverURL, apiKey, action, domainName, fingerprint, comment string) {
	client := api.NewClient(serverURL, apiKey)

	// Test connection first
	if err := client.Ping(); err != nil {
		log.Fatalf("Failed to connect to remote server at %s: %v", serverURL, err)
	}

	// Execute the requested action
	switch action {
	case "add":
		if domainName == "" || fingerprint == "" {
			fmt.Println("Usage: p0rt -remote <url> -reservation add -domain <domain> -fingerprint <fingerprint> [-comment <comment>]")
			fmt.Println("Example: p0rt -remote http://localhost:80 -reservation add -domain happy-cat-jump -fingerprint SHA256:abc123... -comment 'My personal domain'")
			os.Exit(1)
		}
		if err := client.AddReservation(domainName, fingerprint, comment); err != nil {
			log.Fatalf("Failed to add reservation: %v", err)
		}
		fmt.Printf("✓ Successfully reserved domain '%s' for SSH key fingerprint '%s'\n", domainName, fingerprint)

	case "remove":
		if domainName == "" {
			fmt.Println("Usage: p0rt -remote <url> -reservation remove -domain <domain>")
			fmt.Println("Example: p0rt -remote http://localhost:80 -reservation remove -domain happy-cat-jump")
			os.Exit(1)
		}
		if err := client.RemoveReservation(domainName); err != nil {
			log.Fatalf("Failed to remove reservation: %v", err)
		}
		fmt.Printf("✓ Successfully removed reservation for domain '%s'\n", domainName)

	case "list":
		reservations, err := client.ListReservations()
		if err != nil {
			log.Fatalf("Failed to list reservations: %v", err)
		}
		if len(reservations) == 0 {
			fmt.Println("No reservations found")
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

	case "stats":
		statsResponse, err := client.GetStats()
		if err != nil {
			log.Fatalf("Failed to get stats: %v", err)
		}
		fmt.Println("Reservation Statistics:")
		if statsResponse.ReservationStats != nil {
			for key, value := range statsResponse.ReservationStats {
				fmt.Printf("  %s: %v\n", strings.ReplaceAll(key, "_", " "), value)
			}
		}

	default:
		fmt.Println("Available reservation actions:")
		fmt.Println("  add     - Reserve a domain for an SSH key")
		fmt.Println("  remove  - Remove a domain reservation")
		fmt.Println("  list    - List all reservations")
		fmt.Println("  stats   - Show reservation statistics")
		fmt.Println("\nExamples:")
		fmt.Printf("  p0rt -remote %s -reservation add -domain happy-cat-jump -fingerprint SHA256:abc123...\n", serverURL)
		fmt.Printf("  p0rt -remote %s -reservation list\n", serverURL)
		fmt.Printf("  p0rt -remote %s -reservation remove -domain happy-cat-jump\n", serverURL)
		fmt.Printf("  p0rt -remote %s -reservation stats\n", serverURL)
		os.Exit(1)
	}
}

// handleKeyCommand handles SSH key management commands
func handleKeyCommand(action, keyFile, keyString, keyFingerprint, comment, tier, fingerprint, importFile, expiresStr, keysFile string) {
	// Use default keys file if not specified
	if keysFile == "" {
		keysFile = "authorized_keys.json"
	}
	
	keyStore := auth.NewKeyStore(keysFile)
	
	switch action {
	case "add":
		if err := addKey(keyStore, keyFile, keyString, keyFingerprint, comment, tier, expiresStr); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Key added successfully")
		
	case "remove":
		if fingerprint == "" {
			fmt.Fprintln(os.Stderr, "Fingerprint required for remove action")
			fmt.Println("Usage: p0rt -key remove -fingerprint SHA256:xxxxx")
			os.Exit(1)
		}
		if err := keyStore.RemoveKey(fingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "Error removing key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Key removed successfully")
		
	case "activate":
		if fingerprint == "" {
			fmt.Fprintln(os.Stderr, "Fingerprint required for activate action")
			fmt.Println("Usage: p0rt -key activate -fingerprint SHA256:xxxxx")
			os.Exit(1)
		}
		if err := keyStore.ActivateKey(fingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "Error activating key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Key activated successfully")
		
	case "deactivate":
		if fingerprint == "" {
			fmt.Fprintln(os.Stderr, "Fingerprint required for deactivate action")
			fmt.Println("Usage: p0rt -key deactivate -fingerprint SHA256:xxxxx")
			os.Exit(1)
		}
		if err := keyStore.DeactivateKey(fingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "Error deactivating key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Key deactivated successfully")
		
	case "list":
		listKeys(keyStore)
		
	case "import":
		if importFile == "" {
			fmt.Fprintln(os.Stderr, "Import file required for import action")
			fmt.Println("Usage: p0rt -key import --import-file keys.txt --tier beta")
			os.Exit(1)
		}
		if err := keyStore.ImportFromFile(importFile, tier); err != nil {
			fmt.Fprintf(os.Stderr, "Error importing keys: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Keys imported successfully")
		
	default:
		fmt.Println("Available SSH key actions:")
		fmt.Println("  add        - Add a new authorized SSH key")
		fmt.Println("  remove     - Remove an SSH key")
		fmt.Println("  list       - List all authorized SSH keys")
		fmt.Println("  import     - Import keys from authorized_keys file")
		fmt.Println("  activate   - Activate a deactivated key")
		fmt.Println("  deactivate - Deactivate a key temporarily")
		fmt.Println("\nExamples:")
		fmt.Println("  p0rt -key add --key-file ~/.ssh/id_rsa.pub --tier beta --comment 'John Doe'")
		fmt.Println("  p0rt -key add --key-fingerprint SHA256:abc123... --tier beta --comment 'John Doe'")
		fmt.Println("  p0rt -key list")
		fmt.Println("  p0rt -key import --import-file ~/.ssh/authorized_keys --tier free")
		fmt.Println("  p0rt -key remove -fingerprint SHA256:xxxxx")
		fmt.Println("  p0rt -key deactivate -fingerprint SHA256:xxxxx")
		os.Exit(1)
	}
}

// addKey adds a new SSH key to the allowlist
func addKey(keyStore *auth.KeyStore, keyFile, keyString, keyFingerprint, comment, tier, expiresStr string) error {
	// Parse expiration if provided
	var expiresAt *time.Time
	if expiresStr != "" {
		t, err := time.Parse(time.RFC3339, expiresStr)
		if err != nil {
			return fmt.Errorf("invalid expiration date format (use RFC3339, e.g., 2024-12-31T23:59:59Z): %w", err)
		}
		expiresAt = &t
	}
	
	// Check if user provided a fingerprint directly (simplest option)
	if keyFingerprint != "" {
		// Add key by fingerprint only
		if err := keyStore.AddKeyByFingerprint(keyFingerprint, comment, tier, expiresAt); err != nil {
			return err
		}
		
		fmt.Printf("📋 Added key with fingerprint: %s\n", keyFingerprint)
		fmt.Printf("🎯 Tier: %s\n", tier)
		if comment != "" {
			fmt.Printf("💬 Comment: %s\n", comment)
		}
		if expiresAt != nil {
			fmt.Printf("⏰ Expires: %s\n", expiresAt.Format("2006-01-02 15:04:05"))
		}
		
		return nil
	}
	
	// Otherwise, handle traditional key file/string approach
	var pubKey string
	
	if keyFile != "" {
		// Read from file
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}
		pubKey = strings.TrimSpace(string(data))
	} else if keyString != "" {
		pubKey = keyString
	} else {
		// Read from stdin
		fmt.Print("Enter SSH public key (paste and press Enter): ")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		pubKey = strings.TrimSpace(line)
	}
	
	// Generate fingerprint for display
	fingerprint, err := auth.GenerateKeyFingerprint(pubKey)
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %w", err)
	}
	
	if err := keyStore.AddKey(pubKey, comment, tier, expiresAt); err != nil {
		return err
	}
	
	fmt.Printf("📋 Added key with fingerprint: %s\n", fingerprint)
	fmt.Printf("🎯 Tier: %s\n", tier)
	if comment != "" {
		fmt.Printf("💬 Comment: %s\n", comment)
	}
	if expiresAt != nil {
		fmt.Printf("⏰ Expires: %s\n", expiresAt.Format("2006-01-02 15:04:05"))
	}
	
	return nil
}

// listKeys lists all authorized SSH keys
func listKeys(keyStore *auth.KeyStore) {
	keys := keyStore.ListKeys()
	
	if len(keys) == 0 {
		fmt.Println("No authorized SSH keys found")
		fmt.Println()
		fmt.Println("Add a key with:")
		fmt.Println("  p0rt -key add --key-file ~/.ssh/id_rsa.pub --tier beta")
		return
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
	fmt.Printf("🔒 Server is in %s mode\n", getAccessMode())
}

// getAccessMode returns the current access mode
func getAccessMode() string {
	if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
		return "OPEN ACCESS"
	}
	return "RESTRICTED"
}
