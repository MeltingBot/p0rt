package main

import (
	"fmt"
	"log"
	"os"

	"github.com/p0rt/p0rt/cmd"
)

// Build information (set via ldflags during build)
var (
	Version   = "1.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func init() {
	// Handle version flag directly
	for _, arg := range os.Args {
		if arg == "--version" {
			fmt.Printf("P0rt v%s\n", Version)
			fmt.Printf("Built: %s\n", BuildTime)
			fmt.Printf("Commit: %s\n", GitCommit)
			os.Exit(0)
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	cmd.Execute()
}
