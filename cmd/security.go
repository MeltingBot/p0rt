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
	Long:  `Display currently banned IP addresses and blocking statistics.`,
	Run: func(cmd *cobra.Command, args []string) {
		_, remoteURL, apiKey, _, _, _ := GetGlobalFlags()

		if remoteURL != "" {
			showRemoteBanInfo(remoteURL, apiKey)
		} else {
			fmt.Println("Ban information requires a running server.")
			fmt.Println("Start the server with: p0rt server start")
			fmt.Printf("Then use: p0rt --remote http://localhost:80 security bans\n")
		}
	},
}

func init() {
	rootCmd.AddCommand(securityCmd)

	// Add subcommands
	securityCmd.AddCommand(securityStatsCmd)
	securityCmd.AddCommand(securityBansCmd)
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

func showRemoteBanInfo(serverURL, apiKey string) {
	client := api.NewClient(serverURL, apiKey)

	if err := client.Ping(); err != nil {
		fmt.Printf("Error: Failed to connect to remote server at %s: %v\n", serverURL, err)
		return
	}

	bannedIPs, err := client.GetSecurityBans()
	if err != nil {
		fmt.Printf("Error: Failed to get ban information: %v\n", err)
		return
	}

	fmt.Println("=== P0rt Banned IPs ===")
	fmt.Println()

	fmt.Println("Connection:")
	fmt.Printf("  Remote API: ✓ Connected to %s\n", serverURL)
	fmt.Println()

	if len(bannedIPs) == 0 {
		fmt.Println("Banned IPs: None currently banned")
		fmt.Println()
		fmt.Println("✓ No blocked IP addresses at this time.")
		fmt.Println("  The server is accepting connections from all IPs.")
	} else {
		fmt.Printf("Banned IPs: %d total\n", len(bannedIPs))
		fmt.Println()

		for i, banInfo := range bannedIPs {
			if i >= 10 { // Limit display to 10 most recent
				fmt.Printf("... and %d more banned IPs\n", len(bannedIPs)-10)
				break
			}

			if ip, ok := banInfo["ip"].(string); ok {
				fmt.Printf("  %s", ip)
				if reason, ok := banInfo["reason"].(string); ok {
					fmt.Printf(" (reason: %s)", reason)
				}
				if expires, ok := banInfo["expires"].(string); ok {
					fmt.Printf(" expires: %s", expires)
				}
				fmt.Println()
			}
		}
	}

	fmt.Println()
	fmt.Println("💡 Note: Ban tracking is basic. Enhanced security monitoring")
	fmt.Println("   can be implemented in the SSH server for automatic blocking.")
}
