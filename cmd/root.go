package cmd

import (
	"io"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var (
	configFile string
	remoteURL  string
	apiKey     string
	verbose    bool
	quiet      bool
	jsonOutput bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "p0rt",
	Short:   "P0rt - Fast, free SSH tunneling service",
	Version: "1.1.5",
	Long: `P0rt v1.1.5 - Fast, free SSH tunneling service that allows you to expose
local servers to the internet without installation, signup, and free forever.

Key features:
- Deterministic three-word domains from SSH keys
- Real-time connection monitoring in your terminal
- Enterprise-grade security with SSH encryption and abuse prevention
- Built for speed with Go
- Interactive CLI and remote API management
- JSON/Redis dual storage with automatic fallback`,
	Example: `  # Start the server
  p0rt server start

  # Interactive management
  p0rt cli

  # Quick reservation management (long form)
  p0rt reservation list
  p0rt reservation add happy-cat-jump SHA256:abc123... "My domain"

  # Quick reservation management (short form)  
  p0rt r list
  p0rt r add -d happy-cat-jump -f SHA256:abc123... -c "My domain"

  # Remote server management (long form)
  p0rt --remote http://localhost:80 --api-key secret reservation list

  # Remote server management (short form)
  p0rt -R http://localhost:80 -k secret r list`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Global flags available to all commands
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "C", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().StringVarP(&remoteURL, "remote", "R", "", "remote server URL for API access (e.g., http://localhost:80)")
	rootCmd.PersistentFlags().StringVarP(&apiKey, "api-key", "k", "", "API key for remote server authentication")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output (show detailed logs)")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "quiet mode (minimal output)")
	rootCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "output in JSON format for scripting")

	// Set environment variable for config if provided
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if configFile != "" {
			os.Setenv("CONFIG_FILE", configFile)
		}

		// Configure logging based on verbosity flags
		setupLogging()
	}
}

// GetGlobalFlags returns the global flags for use in subcommands
func GetGlobalFlags() (string, string, string, bool, bool, bool) {
	return configFile, remoteURL, apiKey, verbose, quiet, jsonOutput
}

// setupLogging configures logging based on verbosity flags
func setupLogging() {
	if quiet {
		// Quiet mode: disable most logging
		log.SetOutput(io.Discard)
		os.Setenv("P0RT_VERBOSE", "false")
	} else if verbose {
		// Verbose mode: show all logs with file/line info
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.SetOutput(os.Stderr)
		os.Setenv("P0RT_VERBOSE", "true")
	} else {
		// Normal mode: show logs without file/line info
		log.SetFlags(log.LstdFlags)
		log.SetOutput(os.Stderr)
		os.Setenv("P0RT_VERBOSE", "false")
	}
}
