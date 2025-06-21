package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/p0rt/p0rt/internal/api"
)

// accessCmd represents the access command
var accessCmd = &cobra.Command{
	Use:     "access",
	Aliases: []string{"mode"},
	Short:   "Manage server access mode",
	Long: `Manage the server access mode between open and restricted.

Open mode allows any SSH key to create tunnels.
Restricted mode only allows pre-authorized keys from the allowlist.`,
	Example: `  # Show current access mode
  p0rt access status

  # Switch to open access (allow all SSH keys)
  p0rt access open

  # Switch to restricted access (allowlist only)
  p0rt access restricted

  # JSON output
  p0rt access status --json`,
}

var accessStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current access mode",
	Long:  `Display the current server access mode (open or restricted).`,
	Run: func(cmd *cobra.Command, args []string) {
		showAccessStatus()
	},
}

var accessOpenCmd = &cobra.Command{
	Use:   "open",
	Short: "Switch to open access mode",
	Long:  `Switch the server to open access mode, allowing any SSH key to create tunnels.`,
	Run: func(cmd *cobra.Command, args []string) {
		setAccessMode("open")
	},
}

var accessRestrictedCmd = &cobra.Command{
	Use:   "restricted",
	Short: "Switch to restricted access mode",
	Long:  `Switch the server to restricted access mode, only allowing pre-authorized keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		setAccessMode("restricted")
	},
}

func init() {
	rootCmd.AddCommand(accessCmd)
	accessCmd.AddCommand(accessStatusCmd)
	accessCmd.AddCommand(accessOpenCmd)
	accessCmd.AddCommand(accessRestrictedCmd)
}

// showAccessStatus shows the current access mode
func showAccessStatus() {
	remoteURL, apiKey, _, _, _, useJSON := GetGlobalFlags()
	
	var currentMode string
	var err error
	
	if remoteURL != "" {
		// Use remote API
		client := api.NewClient(remoteURL, apiKey)
		currentMode, err = client.GetAccessMode()
		if err != nil {
			if useJSON {
				outputError(fmt.Sprintf("Failed to get access mode from remote server: %v", err))
			} else {
				fmt.Printf("❌ Failed to get access mode from remote server: %v\n", err)
			}
			return
		}
	} else {
		// Local mode
		currentMode = "restricted"
		if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
			currentMode = "open"
		}
	}

	if useJSON {
		data := map[string]interface{}{
			"access_mode": currentMode,
			"open_access": currentMode == "open",
		}
		outputSuccess(data, "Current access mode")
	} else {
		fmt.Printf("🔒 Current access mode: %s\n", strings.ToUpper(currentMode))
		if currentMode == "open" {
			fmt.Println("   - Any SSH key can create tunnels")
		} else {
			fmt.Println("   - Only pre-authorized keys allowed")
		}
	}
}

// setAccessMode changes the server access mode
func setAccessMode(mode string) {
	remoteURL, apiKey, _, _, _, useJSON := GetGlobalFlags()
	
	if remoteURL != "" {
		// Use remote API
		client := api.NewClient(remoteURL, apiKey)
		
		// Get current mode first
		oldMode, err := client.GetAccessMode()
		if err != nil {
			if useJSON {
				outputError(fmt.Sprintf("Failed to get current access mode: %v", err))
			} else {
				fmt.Printf("❌ Failed to get current access mode: %v\n", err)
			}
			return
		}
		
		if oldMode == mode {
			if useJSON {
				data := map[string]interface{}{
					"access_mode": mode,
					"changed":     false,
				}
				outputSuccess(data, fmt.Sprintf("Access mode already set to %s", mode))
			} else {
				fmt.Printf("✅ Access mode is already set to %s\n", strings.ToUpper(mode))
			}
			return
		}
		
		// Set new mode
		err = client.SetAccessMode(mode)
		if err != nil {
			if useJSON {
				outputError(fmt.Sprintf("Failed to change access mode: %v", err))
			} else {
				fmt.Printf("❌ Failed to change access mode: %v\n", err)
			}
			return
		}
		
		if useJSON {
			data := map[string]interface{}{
				"access_mode": mode,
				"changed":     true,
				"old_mode":    oldMode,
			}
			outputSuccess(data, fmt.Sprintf("Access mode changed from %s to %s", oldMode, mode))
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
	} else {
		// Local mode
		oldMode := "restricted"
		if os.Getenv("P0RT_OPEN_ACCESS") == "true" {
			oldMode = "open"
		}

		if oldMode == mode {
			if useJSON {
				data := map[string]interface{}{
					"access_mode": mode,
					"changed":     false,
				}
				outputSuccess(data, fmt.Sprintf("Access mode already set to %s", mode))
			} else {
				fmt.Printf("✅ Access mode is already set to %s\n", strings.ToUpper(mode))
			}
			return
		}

		// Set the environment variable for the current session
		if mode == "open" {
			os.Setenv("P0RT_OPEN_ACCESS", "true")
		} else {
			os.Setenv("P0RT_OPEN_ACCESS", "false")
		}

		if useJSON {
			data := map[string]interface{}{
				"access_mode": mode,
				"changed":     true,
				"old_mode":    oldMode,
			}
			outputSuccess(data, fmt.Sprintf("Access mode changed from %s to %s", oldMode, mode))
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
	}
}