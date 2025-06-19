package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/p0rt/p0rt/internal/api"
	"github.com/p0rt/p0rt/internal/config"
	"github.com/p0rt/p0rt/internal/stats"
)

// statsCmd represents the stats command
var statsCmd = &cobra.Command{
	Use:   "stats [domain]",
	Short: "Show system statistics",
	Long: `Display system statistics including server uptime, active tunnels,
traffic information, and domain reservation statistics.

If a domain is specified, shows detailed statistics for that specific tunnel.`,
	Example: `  # Show global statistics
  p0rt stats

  # Show statistics for a specific domain
  p0rt stats happy-cat-jump

  # Show remote server statistics
  p0rt --remote http://localhost:80 stats

  # Show remote domain statistics
  p0rt --remote http://localhost:80 stats test-domain`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, remoteURL, apiKey, _, _ := GetGlobalFlags()
		
		var domain string
		if len(args) > 0 {
			domain = args[0]
		}

		if remoteURL != "" {
			// Use remote API
			if domain != "" {
				showRemoteDomainStats(remoteURL, apiKey, domain)
			} else {
				showRemoteStats(remoteURL, apiKey)
			}
		} else {
			// Local mode - limited stats without running server
			if domain != "" {
				fmt.Printf("Domain-specific statistics require a running server.\n")
				fmt.Printf("Start the server with: p0rt server start\n")
				fmt.Printf("Then use: p0rt --remote http://localhost:80 stats %s\n", domain)
			} else {
				showLocalStats()
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(statsCmd)
}

func showLocalStats() {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.LoadDefault()
	}

	fmt.Println("=== P0rt System Statistics ===")
	fmt.Println()
	
	// Configuration Statistics
	fmt.Println("Configuration:")
	fmt.Printf("  Storage Type: %s\n", cfg.Storage.Type)
	if cfg.Storage.Type == "json" {
		fmt.Printf("  Data Directory: %s\n", cfg.Storage.DataDir)
	} else if cfg.Storage.Type == "redis" {
		fmt.Printf("  Redis URL: %s\n", cfg.Storage.RedisURL)
		fmt.Printf("  Redis DB: %d\n", cfg.Storage.RedisDB)
	}
	fmt.Printf("  SSH Port: %s\n", cfg.GetSSHPort())
	fmt.Printf("  HTTP Port: %s\n", cfg.GetHTTPPort())
	fmt.Printf("  Domain Base: %s\n", cfg.GetDomainBase())
	fmt.Printf("  Reservations Enabled: %t\n", cfg.Domain.ReservationsEnabled)
	fmt.Println()

	fmt.Println("Server Statistics: Not available (server not running)")
	fmt.Println("  To get runtime statistics, start the server and use:")
	fmt.Printf("  p0rt --remote http://localhost:%s stats\n", cfg.GetHTTPPort())
	fmt.Println()

	// Reservation Statistics
	fmt.Println("Domain Reservations:")
	showLocalReservationStats()
}

func showRemoteStats(serverURL, apiKey string) {
	client := api.NewClient(serverURL, apiKey)
	
	if err := client.Ping(); err != nil {
		fmt.Printf("Error: Failed to connect to remote server at %s: %v\n", serverURL, err)
		return
	}

	statsResponse, err := client.GetStats()
	if err != nil {
		fmt.Printf("Error: Failed to get remote stats: %v\n", err)
		return
	}

	fmt.Println("=== P0rt System Statistics (Remote Server) ===")
	fmt.Println()

	fmt.Println("Connection:")
	fmt.Printf("  Remote API: ✓ Connected to %s\n", serverURL)
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

func showRemoteDomainStats(serverURL, apiKey, domain string) {
	client := api.NewClient(serverURL, apiKey)
	
	if err := client.Ping(); err != nil {
		fmt.Printf("Error: Failed to connect to remote server at %s: %v\n", serverURL, err)
		return
	}

	tunnelStats, err := client.GetTunnelStats(domain)
	if err != nil {
		fmt.Printf("Error: Failed to get tunnel stats: %v\n", err)
		return
	}

	fmt.Printf("=== Statistics for Domain: %s ===\n", domain)
	fmt.Println()

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

	fmt.Println()
}