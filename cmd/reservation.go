package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/p0rt/p0rt/internal/api"
	"github.com/p0rt/p0rt/internal/config"
	"github.com/p0rt/p0rt/internal/domain"
	"github.com/spf13/cobra"
)

var (
	// Flags for reservation commands
	domainName  string
	fingerprint string
	comment     string
)

// OutputFormat represents different output formats for CLI commands
type OutputFormat struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// outputResult prints data in the appropriate format (human-readable or JSON)
func outputResult(data interface{}, message string, isError bool) {
	_, _, _, _, _, useJSON := GetGlobalFlags()

	if useJSON {
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
func outputSuccess(data interface{}, message string) {
	outputResult(data, message, false)
}

// outputError prints error results
func outputError(message string) {
	outputResult(nil, message, true)
}

// reservationCmd represents the reservation command
var reservationCmd = &cobra.Command{
	Use:     "reservation",
	Aliases: []string{"res", "r"},
	Short:   "Manage domain reservations",
	Long: `Manage domain reservations for SSH key fingerprints.

Reservations allow you to permanently associate a specific domain name with
your SSH key, ensuring you always get the same domain when connecting.`,
	Example: `  # List all reservations
  p0rt reservation list

  # Add a new reservation
  p0rt reservation add happy-cat-jump SHA256:abc123... "My personal domain"

  # Remove a reservation
  p0rt reservation remove happy-cat-jump

  # Show reservation statistics
  p0rt reservation stats

  # Remote server management
  p0rt --remote http://localhost:80 reservation list
  p0rt --remote http://localhost:80 --api-key secret reservation add test-domain SHA256:def456...`,
}

var reservationListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls", "l"},
	Short:   "List all domain reservations",
	Long:    `Display all current domain reservations with their details.`,
	Run: func(cmd *cobra.Command, args []string) {
		_, remoteURL, apiKey, _, _, _ := GetGlobalFlags()

		if remoteURL != "" {
			// Use remote API
			listRemoteReservations(remoteURL, apiKey)
		} else {
			// Use local storage
			listLocalReservations()
		}
	},
}

var reservationAddCmd = &cobra.Command{
	Use:   "add [domain] [fingerprint] [comment]",
	Short: "Add a domain reservation",
	Long: `Reserve a domain name for a specific SSH key fingerprint.

The domain will be permanently associated with the provided SSH key fingerprint.
When connecting with that key, you will always receive the reserved domain.

You can provide arguments either as positional parameters or using flags.`,
	Example: `  # Add with positional arguments
  p0rt reservation add happy-cat-jump SHA256:abc123... "My personal development domain"

  # Add with flags (short form)
  p0rt r add -d happy-cat-jump -f SHA256:abc123... -c "My domain"

  # Add with flags (long form)
  p0rt reservation add --domain happy-cat-jump --fingerprint SHA256:abc123... --comment "My domain"

  # Mixed approach
  p0rt r add happy-cat-jump -f SHA256:abc123... --comment "Mixed style"

  # Add to remote server
  p0rt --remote http://localhost:80 reservation add my-domain SHA256:ghi789...`,
	Args: cobra.MaximumNArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		var domain, fingerprint, comment string

		// Start with positional arguments
		if len(args) >= 1 {
			domain = args[0]
		}
		if len(args) >= 2 {
			fingerprint = args[1]
		}
		if len(args) >= 3 {
			comment = args[2]
		}

		// Override with flags if provided (flags take precedence)
		if cmd.Flags().Changed("domain") {
			domain = domainName
		}
		if cmd.Flags().Changed("fingerprint") {
			fingerprint = cmd.Flag("fingerprint").Value.String()
		}
		if cmd.Flags().Changed("comment") {
			comment = cmd.Flag("comment").Value.String()
		}

		// Validate required fields
		if domain == "" {
			cmd.PrintErrln("Error: domain is required (provide as argument or use --domain flag)")
			cmd.Usage()
			return
		}
		if fingerprint == "" {
			cmd.PrintErrln("Error: fingerprint is required (provide as argument or use --fingerprint flag)")
			cmd.Usage()
			return
		}

		_, remoteURL, apiKey, _, _, _ := GetGlobalFlags()

		if remoteURL != "" {
			// Use remote API
			addRemoteReservation(remoteURL, apiKey, domain, fingerprint, comment)
		} else {
			// Use local storage
			addLocalReservation(domain, fingerprint, comment)
		}
	},
}

var reservationRemoveCmd = &cobra.Command{
	Use:     "remove <domain>",
	Aliases: []string{"rm", "del", "delete"},
	Short:   "Remove a domain reservation",
	Long:    `Remove an existing domain reservation, making the domain available for general use.`,
	Example: `  # Remove a reservation
  p0rt reservation remove happy-cat-jump

  # Remove from remote server
  p0rt --remote http://localhost:80 reservation remove test-domain`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]

		// Override with flag if provided
		if domainName != "" {
			domain = domainName
		}

		_, remoteURL, apiKey, _, _, _ := GetGlobalFlags()

		if remoteURL != "" {
			// Use remote API
			removeRemoteReservation(remoteURL, apiKey, domain)
		} else {
			// Use local storage
			removeLocalReservation(domain)
		}
	},
}

var reservationStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show reservation statistics",
	Long:  `Display statistics about domain reservations.`,
	Run: func(cmd *cobra.Command, args []string) {
		_, remoteURL, apiKey, _, _, _ := GetGlobalFlags()

		if remoteURL != "" {
			// Use remote API
			showRemoteReservationStats(remoteURL, apiKey)
		} else {
			// Use local storage
			showLocalReservationStats()
		}
	},
}

func init() {
	rootCmd.AddCommand(reservationCmd)

	// Add subcommands
	reservationCmd.AddCommand(reservationListCmd)
	reservationCmd.AddCommand(reservationAddCmd)
	reservationCmd.AddCommand(reservationRemoveCmd)
	reservationCmd.AddCommand(reservationStatsCmd)

	// Add flags to reservation add command
	reservationAddCmd.Flags().StringVarP(&domainName, "domain", "d", "", "domain name to reserve")
	reservationAddCmd.Flags().StringVarP(&fingerprint, "fingerprint", "f", "", "SSH key fingerprint")
	reservationAddCmd.Flags().StringVarP(&comment, "comment", "c", "", "comment for the reservation")

	// Add flags to reservation remove command
	reservationRemoveCmd.Flags().StringVarP(&domainName, "domain", "d", "", "domain name to remove")
}

// Local reservation functions
func listLocalReservations() {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.LoadDefault()
	}

	reservationManager, err := createLocalReservationManager(cfg)
	if err != nil {
		outputError(fmt.Sprintf("Failed to create reservation manager: %v", err))
		return
	}

	reservations := reservationManager.ListReservations()
	if len(reservations) == 0 {
		outputSuccess([]interface{}{}, "No reservations found")
		return
	}

	_, _, _, _, _, useJSON := GetGlobalFlags()
	if useJSON {
		outputSuccess(reservations, fmt.Sprintf("Found %d reservation(s)", len(reservations)))
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
}

func addLocalReservation(domain, fingerprint, comment string) {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.LoadDefault()
	}

	reservationManager, err := createLocalReservationManager(cfg)
	if err != nil {
		fmt.Printf("Error: Failed to create reservation manager: %v\n", err)
		return
	}

	if err := reservationManager.AddReservation(domain, fingerprint, comment); err != nil {
		fmt.Printf("Error: Failed to add reservation: %v\n", err)
		return
	}

	fmt.Printf("✓ Successfully reserved domain '%s' for SSH key fingerprint '%s'\n", domain, fingerprint)
	if comment != "" {
		fmt.Printf("  Comment: %s\n", comment)
	}
}

func removeLocalReservation(domain string) {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.LoadDefault()
	}

	reservationManager, err := createLocalReservationManager(cfg)
	if err != nil {
		fmt.Printf("Error: Failed to create reservation manager: %v\n", err)
		return
	}

	if err := reservationManager.RemoveReservation(domain); err != nil {
		fmt.Printf("Error: Failed to remove reservation: %v\n", err)
		return
	}

	fmt.Printf("✓ Successfully removed reservation for domain '%s'\n", domain)
}

func showLocalReservationStats() {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.LoadDefault()
	}

	reservationManager, err := createLocalReservationManager(cfg)
	if err != nil {
		fmt.Printf("Error: Failed to create reservation manager: %v\n", err)
		return
	}

	stats := reservationManager.GetStats()
	fmt.Println("Reservation Statistics:")
	for key, value := range stats {
		fmt.Printf("  %s: %v\n", strings.ReplaceAll(key, "_", " "), value)
	}
}

// Remote reservation functions
func listRemoteReservations(serverURL, apiKey string) {
	client := api.NewClient(serverURL, apiKey)

	if err := client.Ping(); err != nil {
		outputError(fmt.Sprintf("Failed to connect to remote server at %s: %v", serverURL, err))
		return
	}

	reservations, err := client.ListReservations()
	if err != nil {
		outputError(fmt.Sprintf("Failed to list reservations: %v", err))
		return
	}

	if len(reservations) == 0 {
		outputSuccess([]interface{}{}, "No reservations found")
		return
	}

	_, _, _, _, _, useJSON := GetGlobalFlags()
	if useJSON {
		outputSuccess(reservations, fmt.Sprintf("Found %d reservation(s) on remote server", len(reservations)))
	} else {
		fmt.Printf("Found %d reservation(s) on remote server:\n\n", len(reservations))
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
}

func addRemoteReservation(serverURL, apiKey, domain, fingerprint, comment string) {
	client := api.NewClient(serverURL, apiKey)

	if err := client.Ping(); err != nil {
		fmt.Printf("Error: Failed to connect to remote server at %s: %v\n", serverURL, err)
		return
	}

	if err := client.AddReservation(domain, fingerprint, comment); err != nil {
		fmt.Printf("Error: Failed to add reservation: %v\n", err)
		return
	}

	fmt.Printf("✓ Successfully reserved domain '%s' for SSH key fingerprint '%s' on remote server\n", domain, fingerprint)
	if comment != "" {
		fmt.Printf("  Comment: %s\n", comment)
	}
}

func removeRemoteReservation(serverURL, apiKey, domain string) {
	client := api.NewClient(serverURL, apiKey)

	if err := client.Ping(); err != nil {
		fmt.Printf("Error: Failed to connect to remote server at %s: %v\n", serverURL, err)
		return
	}

	if err := client.RemoveReservation(domain); err != nil {
		fmt.Printf("Error: Failed to remove reservation: %v\n", err)
		return
	}

	fmt.Printf("✓ Successfully removed reservation for domain '%s' from remote server\n", domain)
}

func showRemoteReservationStats(serverURL, apiKey string) {
	client := api.NewClient(serverURL, apiKey)

	if err := client.Ping(); err != nil {
		fmt.Printf("Error: Failed to connect to remote server at %s: %v\n", serverURL, err)
		return
	}

	statsResponse, err := client.GetStats()
	if err != nil {
		fmt.Printf("Error: Failed to get stats: %v\n", err)
		return
	}

	fmt.Println("Reservation Statistics (Remote Server):")
	if statsResponse.ReservationStats != nil {
		for key, value := range statsResponse.ReservationStats {
			fmt.Printf("  %s: %v\n", strings.ReplaceAll(key, "_", " "), value)
		}
	}
}

// Helper function to create local reservation manager
func createLocalReservationManager(cfg *config.Config) (domain.ReservationManagerInterface, error) {
	storageConfig := cfg.GetStorageConfig()

	switch storageConfig.Type {
	case "redis":
		return domain.NewRedisReservationManager(
			storageConfig.RedisURL,
			storageConfig.RedisPassword,
			storageConfig.RedisDB,
		)
	case "json", "":
		return domain.NewReservationManager(storageConfig.DataDir)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storageConfig.Type)
	}
}
