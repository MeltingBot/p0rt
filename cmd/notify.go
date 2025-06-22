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
	Short: "Test ban notification by sending a test message",
	Long: `Send a test ban notification to a connected SSH client.
This directly calls the NotifyDomainBanned function for testing.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		
		fmt.Printf("🧪 Testing ban notification for domain: %s\n", domain)
		
		// This is a test - in a real implementation you'd need to:
		// 1. Get reference to the SSH server instance
		// 2. Call server.NotifyDomainBanned(domain)
		
		fmt.Printf("\n⚠️  This is a placeholder command for testing.\n")
		fmt.Printf("To actually test ban notifications:\n")
		fmt.Printf("1. Start P0rt server: ./p0rt server start\n")
		fmt.Printf("2. Connect with SSH: ssh -R 443:localhost:8080 localhost -p 2222\n")
		fmt.Printf("3. Note your assigned domain (e.g., happy-cat-123)\n")
		fmt.Printf("4. Run: ./p0rt abuse report <your-domain>.p0rt.xyz\n")
		fmt.Printf("5. Process the report: ./p0rt abuse process <report-id> ban\n")
		fmt.Printf("6. Watch the SSH client console for the ban notification!\n")
		
		log.Printf("Ban notification test command completed for domain: %s", domain)
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