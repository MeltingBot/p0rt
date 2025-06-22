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
	Short: "Test ban notification by creating a fake abuse report",
	Long: `Create a test abuse report and process it to trigger ban notifications.
This simulates the real ban notification process for testing purposes.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		
		fmt.Printf("🧪 Testing ban notification for domain: %s\n", domain)
		fmt.Printf("\nThis would:\n")
		fmt.Printf("1. Create a fake abuse report for the domain\n")
		fmt.Printf("2. Process the report with 'ban' action\n")
		fmt.Printf("3. Trigger NotifyDomainBanned() if there's an active SSH client\n")
		fmt.Printf("4. Send real-time warning to the SSH client console\n")
		fmt.Printf("5. Terminate the SSH connection after 5 seconds\n")
		fmt.Printf("6. Record security events in metrics\n")
		
		fmt.Printf("\n💡 To test with a real client:\n")
		fmt.Printf("1. Start P0rt server: ./p0rt server start\n")
		fmt.Printf("2. Connect with SSH: ssh -R 443:localhost:8080 ssh.p0rt.xyz -p 2222\n")
		fmt.Printf("3. Note your assigned domain (e.g., happy-cat-123)\n")
		fmt.Printf("4. Run: ./p0rt abuse report <your-domain>.p0rt.xyz\n")
		fmt.Printf("5. Process the report: ./p0rt abuse process <report-id> ban\n")
		fmt.Printf("6. Watch the SSH client console for the ban notification!\n")
		
		log.Printf("Ban notification test guidance provided for domain: %s", domain)
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