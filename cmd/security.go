package cmd

import (
	"fmt"

	"github.com/p0rt/p0rt/internal/api"
	"github.com/spf13/cobra"
)

// securityCmd represents the security command
var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Show security information and statistics",
	Long: `Display security-related information including:
- Blocked IPs and ban statistics
- Authentication failures  
- Abuse reports
- Scanning attempts

This information helps monitor the security status of your P0rt server.`,
	Example: `  # Show security stats from local files
  p0rt security stats

  # Show security stats from remote server
  p0rt --remote http://localhost:80 security stats

  # Show banned IPs
  p0rt security bans`,
}

var securityStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show security statistics",
	Long:  `Display security statistics including authentication failures, blocked IPs, and abuse reports.`,
	Run: func(cmd *cobra.Command, args []string) {
		_, remoteURL, apiKey, _, _, _ := GetGlobalFlags()

		if remoteURL != "" {
			showRemoteSecurityStats(remoteURL, apiKey)
		} else {
			fmt.Println("Security statistics require a running server.")
			fmt.Println("Start the server with: p0rt server start")
			fmt.Printf("Then use: p0rt --remote http://localhost:80 security stats\n")
		}
	},
}

var securityBansCmd = &cobra.Command{
	Use:   "bans",
	Short: "Show banned IPs and blocking information",
	Long: `Display currently banned IP addresses and blocking statistics.
	
Supports pagination for large ban lists:
  --limit: Maximum number of IPs to show (default: 50, max: 1000)  
  --offset: Number of IPs to skip (default: 0)
  --page: Page number to show (alternative to offset)`,
	Run: func(cmd *cobra.Command, args []string) {
		_, remoteURL, apiKey, _, _, _ := GetGlobalFlags()

		// Get pagination flags
		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")
		page, _ := cmd.Flags().GetInt("page")

		// Convert page to offset if page is specified
		if page > 0 {
			offset = (page - 1) * limit
		}

		if remoteURL != "" {
			showRemoteBanInfo(remoteURL, apiKey, limit, offset)
		} else {
			fmt.Println("Ban information requires a running server.")
			fmt.Println("Start the server with: p0rt server start")
			fmt.Printf("Then use: p0rt --remote http://localhost:80 security bans\n")
		}
	},
}

var securityUnbanCmd = &cobra.Command{
	Use:   "unban [ip]",
	Short: "Unban an IP address from security blocks",
	Long: `Remove an IP address from all security ban lists.

This command will:
- Remove the IP from local banned IPs cache
- Clear the IP from Redis security tracker
- Reset brute force attempt counters
- Allow the IP to connect immediately

This is useful for removing false positive bans or unbanning legitimate IPs
that were blocked due to authentication failures.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ip := args[0]
		_, remoteURL, apiKey, _, _, _ := GetGlobalFlags()

		fmt.Printf("🔓 Unbanning IP address: %s\n", ip)

		if remoteURL != "" {
			unbanRemoteIP(remoteURL, apiKey, ip)
		} else {
			fmt.Println("IP unbanning requires a running server.")
			fmt.Println("Start the server with: p0rt server start")
			fmt.Printf("Then use: p0rt --remote http://localhost:80 security unban %s\n", ip)
		}
	},
}

func init() {
	rootCmd.AddCommand(securityCmd)

	// Add subcommands
	securityCmd.AddCommand(securityStatsCmd)
	securityCmd.AddCommand(securityBansCmd)
	securityCmd.AddCommand(securityUnbanCmd)

	// Add pagination flags to bans command
	securityBansCmd.Flags().Int("limit", 50, "Maximum number of banned IPs to show (1-1000)")
	securityBansCmd.Flags().Int("offset", 0, "Number of banned IPs to skip")
	securityBansCmd.Flags().Int("page", 0, "Page number to show (alternative to offset)")
}

func showRemoteSecurityStats(serverURL, apiKey string) {
	client := api.NewClient(serverURL, apiKey)

	if err := client.Ping(); err != nil {
		fmt.Printf("Error: Failed to connect to remote server at %s: %v\n", serverURL, err)
		return
	}

	securityStats, err := client.GetSecurityStats()
	if err != nil {
		fmt.Printf("Error: Failed to get security stats: %v\n", err)
		return
	}

	fmt.Println("=== P0rt Security Statistics ===")
	fmt.Println()

	fmt.Println("Connection:")
	fmt.Printf("  Remote API: ✓ Connected to %s\n", serverURL)
	fmt.Println()

	fmt.Println("Authentication & Security:")
	if authFailures, ok := securityStats["authentication_failures"].(float64); ok {
		fmt.Printf("  Authentication Failures: %.0f\n", authFailures)
	}
	if blockedIPs, ok := securityStats["blocked_ips_count"].(float64); ok {
		fmt.Printf("  Blocked IP Addresses: %.0f\n", blockedIPs)
	}
	if scanningAttempts, ok := securityStats["scanning_attempts"].(float64); ok {
		fmt.Printf("  Scanning Attempts: %.0f\n", scanningAttempts)
	}
	if abuseReports, ok := securityStats["abuse_reports"].(float64); ok {
		fmt.Printf("  Abuse Reports: %.0f\n", abuseReports)
	}
	if last24h, ok := securityStats["last_24h_failures"].(float64); ok {
		fmt.Printf("  Failures (24h): %.0f\n", last24h)
	}
	fmt.Println()

	if banReasons, ok := securityStats["ban_reasons"].(map[string]interface{}); ok && len(banReasons) > 0 {
		fmt.Println("Ban Reasons:")
		for reason, count := range banReasons {
			if countFloat, ok := count.(float64); ok && countFloat > 0 {
				fmt.Printf("  %s: %.0f\n", reason, countFloat)
			}
		}
		fmt.Println()
	}

	if geoBlocks, ok := securityStats["geographic_blocks"].(map[string]interface{}); ok && len(geoBlocks) > 0 {
		fmt.Println("Geographic Blocks:")
		for country, count := range geoBlocks {
			if countFloat, ok := count.(float64); ok {
				fmt.Printf("  %s: %.0f\n", country, countFloat)
			}
		}
		fmt.Println()
	}

	fmt.Println("💡 Note: Security monitoring is basic. Enhanced tracking can be")
	fmt.Println("   implemented in the SSH server for more detailed statistics.")
}

func showRemoteBanInfo(serverURL, apiKey string, limit, offset int) {
	client := api.NewClient(serverURL, apiKey)

	if err := client.Ping(); err != nil {
		fmt.Printf("Error: Failed to connect to remote server at %s: %v\n", serverURL, err)
		return
	}

	result, err := client.GetSecurityBans(limit, offset)
	if err != nil {
		fmt.Printf("Error: Failed to get ban information: %v\n", err)
		return
	}

	fmt.Println("=== P0rt Banned IPs ===")
	fmt.Println()

	fmt.Println("Connection:")
	fmt.Printf("  Remote API: ✓ Connected to %s\n", serverURL)
	fmt.Println()

	// Show pagination info
	currentPage := (offset / limit) + 1
	totalPages := (result.TotalBans + limit - 1) / limit // Ceiling division

	if result.TotalBans == 0 {
		fmt.Println("Banned IPs: None currently banned")
		fmt.Println()
		fmt.Println("✓ No blocked IP addresses at this time.")
		fmt.Println("  The server is accepting connections from all IPs.")
	} else {
		fmt.Printf("Banned IPs: %d total", result.TotalBans)
		if totalPages > 1 {
			fmt.Printf(" (Page %d of %d)", currentPage, totalPages)
		}
		fmt.Println()
		fmt.Printf("Showing: %d of %d IPs\n", result.Count, result.TotalBans)
		fmt.Println()

		for _, banInfo := range result.BannedIPs {
			if ip, ok := banInfo["ip"].(string); ok {
				fmt.Printf("  %s", ip)
				if reason, ok := banInfo["reason"].(string); ok {
					fmt.Printf(" (reason: %s)", reason)
				}
				if expires, ok := banInfo["expires_at"].(string); ok && expires != "" {
					fmt.Printf(" expires: %s", expires)
				} else {
					fmt.Printf(" (permanent)")
				}
				fmt.Println()
			}
		}

		// Show navigation hints
		if totalPages > 1 {
			fmt.Println()
			if result.HasPrev {
				fmt.Printf("  Previous page: --page %d\n", currentPage-1)
			}
			if result.HasNext {
				fmt.Printf("  Next page: --page %d\n", currentPage+1)
			}
		}
	}

	fmt.Println()
	fmt.Println("💡 Use --limit and --page flags to navigate through large ban lists")
	fmt.Println("   Example: p0rt security bans --limit 25 --page 2")
}

func unbanRemoteIP(serverURL, apiKey, ip string) {
	client := api.NewClient(serverURL, apiKey)

	if err := client.Ping(); err != nil {
		fmt.Printf("Error: Failed to connect to remote server at %s: %v\n", serverURL, err)
		return
	}

	// Try to unban the IP via API
	err := client.UnbanIP(ip)
	if err != nil {
		fmt.Printf("Error: Failed to unban IP %s: %v\n", ip, err)
		return
	}

	fmt.Printf("✅ Successfully unbanned IP: %s\n", ip)
	fmt.Printf("The IP should now be able to connect to the server.\n")
}
