package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/p0rt/p0rt/internal/cli"
	"github.com/p0rt/p0rt/internal/config"
)

// cliCmd represents the cli command
var cliCmd = &cobra.Command{
	Use:     "cli",
	Aliases: []string{"interactive", "i"},
	Short:   "Start interactive CLI mode",
	Long: `Start the interactive command-line interface for managing P0rt.

The interactive CLI provides a convenient way to manage reservations, view statistics,
and control the server with tab completion, command history, and context-sensitive help.`,
	Example: `  # Local interactive mode
  p0rt cli

  # Remote interactive mode
  p0rt --remote http://localhost:80 cli

  # Remote with authentication
  p0rt --remote http://localhost:80 --api-key secret cli`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.Load()
		if err != nil {
			cfg = config.LoadDefault()
		}

		_, remoteURL, apiKey, _, _ := GetGlobalFlags()

		var cliInstance *cli.CLI

		if remoteURL != "" {
			// Use remote API
			fmt.Printf("Connecting to remote P0rt server at %s...\n", remoteURL)
			cliInstance, err = cli.NewCLIWithRemoteAPI(cfg, remoteURL, apiKey)
			if err != nil {
				fmt.Printf("Error: Failed to connect to remote API: %v\n", err)
				return
			}
			fmt.Println("✓ Connected! You can now manage the remote server.")
		} else {
			// Use local mode with server start capability
			serverStartFunc := func() error {
				return startServer(cfg)
			}
			cliInstance, err = cli.NewCLIWithServerFunc(cfg, serverStartFunc)
			if err != nil {
				fmt.Printf("Error: Failed to create CLI: %v\n", err)
				return
			}
		}

		if err := cliInstance.Start(); err != nil {
			fmt.Printf("Error: CLI error: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(cliCmd)
}