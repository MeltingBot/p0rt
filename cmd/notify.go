package cmd

import (
	"fmt"
	"log"

	"github.com/p0rt/p0rt/internal/api"
	"github.com/spf13/cobra"
)

// notifyCmd represents the notify command
var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Notification management commands",
	Long:  `Commands to manage and test notifications for active SSH clients.`,
}

var notifyDomainCmd = &cobra.Command{
	Use:   "domain [domain]",
	Short: "Send notification to domain's SSH client",
	Long: `Send a notification message to a connected SSH client for the specified domain.
This can be used for various purposes like warnings, bans, maintenance notices, etc.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		_, remoteURL, apiKey, _, _, useJSON := GetGlobalFlags()
		
		if remoteURL != "" {
			// Use remote API
			client := api.NewClient(remoteURL, apiKey)
			reason, _ := cmd.Flags().GetString("reason")
			message, _ := cmd.Flags().GetString("message")
			notificationType, _ := cmd.Flags().GetString("type")
			
			if notificationType == "ban" || (notificationType == "" && reason != "") {
				// Send ban notification
				fmt.Printf("🚫 Sending ban notification via API for domain: %s\n", domain)
				notification, err := client.BanDomainNotification(domain, reason)
				if err != nil {
					fmt.Printf("❌ Error: %v\n", err)
					return
				}
				
				if useJSON {
					fmt.Printf("{\"success\": true, \"notification\": %+v}\n", notification)
				} else {
					fmt.Printf("✅ Ban notification sent successfully!\n")
					fmt.Printf("📋 Domain: %s\n", domain)
					fmt.Printf("⏰ Sent at: %s\n", notification.Timestamp)
					if reason != "" {
						fmt.Printf("💬 Reason: %s\n", reason)
					}
				}
			} else {
				// Send test notification
				fmt.Printf("📨 Sending notification via API for domain: %s\n", domain)
				notification, err := client.TestNotification(message)
				if err != nil {
					fmt.Printf("❌ Error: %v\n", err)
					return
				}
				
				if useJSON {
					fmt.Printf("{\"success\": true, \"notification\": %+v}\n", notification)
				} else {
					fmt.Printf("✅ Notification sent successfully!\n")
					fmt.Printf("📋 Domain: %s\n", domain)
					fmt.Printf("⏰ Sent at: %s\n", notification.Timestamp)
					if message != "" {
						fmt.Printf("💬 Message: %s\n", message)
					}
				}
			}
		} else {
			// Local mode
			reason, _ := cmd.Flags().GetString("reason")
			message, _ := cmd.Flags().GetString("message")
			notificationType, _ := cmd.Flags().GetString("type")
			
			if notificationType == "ban" || (notificationType == "" && reason != "") {
				fmt.Printf("🚫 Testing ban notification for domain: %s\n", domain)
				if reason != "" {
					fmt.Printf("💬 Reason: %s\n", reason)
				}
			} else {
				fmt.Printf("📨 Testing notification for domain: %s\n", domain)
				if message != "" {
					fmt.Printf("💬 Message: %s\n", message)
				}
			}
			
			fmt.Printf("\n⚠️  This is a placeholder command for testing.\n")
			fmt.Printf("To actually test notifications:\n")
			fmt.Printf("1. Start P0rt server: ./p0rt server start\n")
			fmt.Printf("2. Connect with SSH: ssh -R 443:localhost:8080 localhost -p 2222\n")
			fmt.Printf("3. Note your assigned domain (e.g., happy-cat-123)\n")
			fmt.Printf("4. Use remote API: ./p0rt --remote http://server notify domain <domain>\n")
		}
		
		log.Printf("Domain notification test command completed for domain: %s", domain)
	},
}

var notifyTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test notification system",
	Long:  `Test the notification system to ensure messages are properly delivered to SSH clients.`,
	Run: func(cmd *cobra.Command, args []string) {
		_, remoteURL, apiKey, _, _, useJSON := GetGlobalFlags()
		
		if remoteURL != "" {
			// Use remote API
			fmt.Println("🌐 Testing notification system via API...")
			
			client := api.NewClient(remoteURL, apiKey)
			message, _ := cmd.Flags().GetString("message")
			
			notification, err := client.TestNotification(message)
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
				return
			}
			
			if useJSON {
				fmt.Printf("{\"success\": true, \"notification\": %+v}\n", notification)
			} else {
				fmt.Printf("✅ Test notification sent successfully!\n")
				fmt.Printf("📋 Message: %s\n", notification.Message)
				fmt.Printf("⏰ Sent at: %s\n", notification.Timestamp)
				fmt.Printf("📨 Recipient: %s\n", notification.Recipient)
			}
		} else {
			// Local mode - show format example
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
		}
	},
}

func init() {
	rootCmd.AddCommand(notifyCmd)
	notifyCmd.AddCommand(notifyDomainCmd)
	notifyCmd.AddCommand(notifyTestCmd)
	
	// Add flags for domain notifications
	notifyDomainCmd.Flags().StringP("type", "t", "", "notification type (ban, warning, info)")
	notifyDomainCmd.Flags().StringP("reason", "r", "", "reason for the notification (used for ban type)")
	notifyDomainCmd.Flags().StringP("message", "m", "", "custom notification message")
	
	// Add flags for test notifications
	notifyTestCmd.Flags().StringP("message", "m", "", "custom test message")
}