package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--help" {
		printHelp()
		return
	}

	// Try to find SSH key
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot find home directory: %v\n", err)
		os.Exit(1)
	}

	// Common SSH key locations
	keyPaths := []string{
		filepath.Join(home, ".ssh", "id_rsa.pub"),
		filepath.Join(home, ".ssh", "id_ed25519.pub"),
		filepath.Join(home, ".ssh", "id_ecdsa.pub"),
	}

	// Check if a key path was provided as argument
	if len(os.Args) > 1 {
		keyPaths = []string{os.Args[1]}
	}

	var keyData []byte
	var keyPath string
	
	// Try to read the first available key
	for _, path := range keyPaths {
		data, err := ioutil.ReadFile(path)
		if err == nil {
			keyData = data
			keyPath = path
			break
		}
	}

	if keyData == nil {
		fmt.Fprintf(os.Stderr, "Error: No SSH public key found. Tried:\n")
		for _, path := range keyPaths {
			fmt.Fprintf(os.Stderr, "  - %s\n", path)
		}
		fmt.Fprintf(os.Stderr, "\nSpecify your public key path: p0rt-fingerprint /path/to/key.pub\n")
		os.Exit(1)
	}

	// Parse the public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(keyData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to parse SSH key from %s: %v\n", keyPath, err)
		os.Exit(1)
	}

	// Get fingerprint
	fingerprint := ssh.FingerprintSHA256(pubKey)
	cleanFingerprint := strings.TrimPrefix(fingerprint, "SHA256:")

	fmt.Println("SSH Key Fingerprint (SHA256):")
	fmt.Printf("  %s\n\n", cleanFingerprint)
	
	fmt.Println("To use a custom domain with P0rt:")
	fmt.Println("1. Add CNAME record:")
	fmt.Println("   Host: yourdomain.com")
	fmt.Println("   Target: p0rt.xyz")
	fmt.Println("")
	fmt.Println("2. Add TXT record:")
	fmt.Println("   Host: _p0rt-authkey.yourdomain.com")
	fmt.Printf("   Value: p0rt-authkey=%s\n", cleanFingerprint)
	fmt.Println("")
	fmt.Println("3. Connect:")
	fmt.Println("   ssh -R 443:localhost:3000 ssh.p0rt.xyz -o \"SetEnv LC_CUSTOM_DOMAIN=yourdomain.com\"")
}

func printHelp() {
	fmt.Println("p0rt-fingerprint - Get your SSH key fingerprint for custom domain setup")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  p0rt-fingerprint                    # Use default SSH key (~/.ssh/id_*.pub)")
	fmt.Println("  p0rt-fingerprint /path/to/key.pub   # Use specific public key")
	fmt.Println("  p0rt-fingerprint --help             # Show this help")
	fmt.Println("")
	fmt.Println("The fingerprint is used to verify ownership when using custom domains with P0rt.")
}