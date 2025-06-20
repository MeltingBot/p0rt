package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/p0rt/p0rt/internal/auth"
)

func main() {
	var (
		keysFile    = flag.String("keys-file", "authorized_keys.json", "Path to authorized keys file")
		action      = flag.String("action", "", "Action: add, remove, list, import, activate, deactivate")
		keyFile     = flag.String("key-file", "", "SSH public key file to add")
		keyString   = flag.String("key", "", "SSH public key string")
		comment     = flag.String("comment", "", "Comment for the key")
		tier        = flag.String("tier", "free", "Access tier: beta, free, premium, vip")
		fingerprint = flag.String("fingerprint", "", "Key fingerprint for remove/activate/deactivate")
		importFile  = flag.String("import-file", "", "File to import keys from (authorized_keys format)")
		expires     = flag.String("expires", "", "Expiration date (RFC3339 format, e.g., 2024-12-31T23:59:59Z)")
	)

	flag.Parse()

	if *action == "" {
		fmt.Println("Usage: keymanager -action [add|remove|list|import|activate|deactivate] [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	keyStore := auth.NewKeyStore(*keysFile)

	switch *action {
	case "add":
		if err := addKey(keyStore, *keyFile, *keyString, *comment, *tier, *expires); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Key added successfully")

	case "remove":
		if *fingerprint == "" {
			fmt.Fprintln(os.Stderr, "Fingerprint required for remove action")
			os.Exit(1)
		}
		if err := keyStore.RemoveKey(*fingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "Error removing key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Key removed successfully")

	case "activate":
		if *fingerprint == "" {
			fmt.Fprintln(os.Stderr, "Fingerprint required for activate action")
			os.Exit(1)
		}
		if err := keyStore.ActivateKey(*fingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "Error activating key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Key activated successfully")

	case "deactivate":
		if *fingerprint == "" {
			fmt.Fprintln(os.Stderr, "Fingerprint required for deactivate action")
			os.Exit(1)
		}
		if err := keyStore.DeactivateKey(*fingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "Error deactivating key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Key deactivated successfully")

	case "list":
		listKeys(keyStore)

	case "import":
		if *importFile == "" {
			fmt.Fprintln(os.Stderr, "Import file required for import action")
			os.Exit(1)
		}
		if err := keyStore.ImportFromFile(*importFile, *tier); err != nil {
			fmt.Fprintf(os.Stderr, "Error importing keys: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Keys imported successfully")

	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", *action)
		os.Exit(1)
	}
}

func addKey(keyStore *auth.KeyStore, keyFile, keyString, comment, tier, expiresStr string) error {
	var pubKey string

	if keyFile != "" {
		// Read from file
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}
		pubKey = strings.TrimSpace(string(data))
	} else if keyString != "" {
		pubKey = keyString
	} else {
		// Read from stdin
		fmt.Println("Enter SSH public key (paste and press Enter):")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		pubKey = strings.TrimSpace(line)
	}

	// Parse expiration if provided
	var expiresAt *time.Time
	if expiresStr != "" {
		t, err := time.Parse(time.RFC3339, expiresStr)
		if err != nil {
			return fmt.Errorf("invalid expiration date format: %w", err)
		}
		expiresAt = &t
	}

	// Generate fingerprint for display
	fingerprint, err := auth.GenerateKeyFingerprint(pubKey)
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %w", err)
	}

	if err := keyStore.AddKey(pubKey, comment, tier, expiresAt); err != nil {
		return err
	}

	fmt.Printf("Added key with fingerprint: %s\n", fingerprint)
	return nil
}

func listKeys(keyStore *auth.KeyStore) {
	keys := keyStore.ListKeys()

	if len(keys) == 0 {
		fmt.Println("No authorized keys found")
		return
	}

	fmt.Printf("%-50s %-10s %-10s %-20s %s\n", "Fingerprint", "Tier", "Status", "Added", "Comment")
	fmt.Println(strings.Repeat("-", 120))

	for _, access := range keys {
		status := "Active"
		if !access.Active {
			status = "Inactive"
		}
		if access.ExpiresAt != nil && time.Now().After(*access.ExpiresAt) {
			status = "Expired"
		}

		fmt.Printf("%-50s %-10s %-10s %-20s %s\n",
			access.Fingerprint,
			access.Tier,
			status,
			access.AddedAt.Format("2006-01-02 15:04:05"),
			access.Comment,
		)
	}
}
