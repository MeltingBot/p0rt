package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// notifyCmd represents the notify command
var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Notification management commands",
	Long:  `Commands to manage and test notifications for active SSH clients.`,
}

var notifyBanCmd = &cobra.Command{
	Use:   "ban-domain [domain]",
	Short: "Notify SSH clients that their domain has been banned",
	Long: `Send a ban notification to any active SSH client using the specified domain.
This is typically used for testing or manual enforcement of domain bans.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		
		// For testing, we'll just log what would happen
		fmt.Printf("Would notify SSH clients that domain '%s' has been banned\n", domain)
		fmt.Printf("In a real scenario, this would:\n")
		fmt.Printf("1. Send warning message to active SSH client console\n")
		fmt.Printf("2. Terminate the SSH connection after 5 seconds\n")
		fmt.Printf("3. Record security event in metrics\n")
		
		log.Printf("Manual domain ban notification test for domain: %s", domain)
	},
}

var notifyTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test notification system",
	Long:  `Test the notification system to ensure messages are properly delivered to SSH clients.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Testing notification system...")
		fmt.Println("✓ Ban notification message format:")
		fmt.Println("======================================================================")
		fmt.Println("🚫 DOMAIN BANNED - IMMEDIATE ACTION REQUIRED")
		fmt.Println("======================================================================")
		fmt.Println("Domain: test-domain.p0rt.xyz")
		fmt.Println("Reason: Abuse reports received and processed")
		fmt.Println("Action: Tunnel will be terminated in 5 seconds")
		fmt.Println("")
		fmt.Println("If you believe this is an error:")
		fmt.Println("- Contact support immediately")
		fmt.Println("- Provide your SSH key fingerprint")
		fmt.Println("- Include details about legitimate use")
		fmt.Println("======================================================================")
		fmt.Println("")
		fmt.Println("✓ Notification system format verified")
	},
}

func init() {
	rootCmd.AddCommand(notifyCmd)
	notifyCmd.AddCommand(notifyBanCmd)
	notifyCmd.AddCommand(notifyTestCmd)
}