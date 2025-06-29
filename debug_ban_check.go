package main

import (
	"fmt"
	"log"

	"github.com/p0rt/p0rt/internal/security"
)

func main() {
	// Create abuse report manager
	manager := security.NewAbuseReportManager()

	// Test domain ban checking
	testDomains := []string{
		"happy-cat-123.p0rt.xyz",
		"evil-domain.p0rt.xyz",
		"test.p0rt.xyz",
		"subdomain",
	}

	fmt.Println("=== Testing Domain Ban Logic ===")

	for _, domain := range testDomains {
		isBanned := manager.IsDomainBanned(domain)
		fmt.Printf("Domain: %-25s | Banned: %t\n", domain, isBanned)
	}

	// Test creating a ban
	fmt.Println("\n=== Creating Test Ban ===")
	report, err := manager.SubmitReport("test-ban.p0rt.xyz", "127.0.0.1", "malware", "Testing ban functionality")
	if err != nil {
		log.Printf("Failed to submit report: %v", err)
		return
	}

	fmt.Printf("Created report ID: %s\n", report.ID)

	// Process the report as a ban
	err = manager.ProcessReport(report.ID, "ban", "test-admin")
	if err != nil {
		log.Printf("Failed to process report: %v", err)
		return
	}

	fmt.Println("Processed report as banned")

	// Test checking the banned domain
	isBanned := manager.IsDomainBanned("test-ban.p0rt.xyz")
	fmt.Printf("Domain 'test-ban.p0rt.xyz' is banned: %t\n", isBanned)

	// Test stats
	stats := manager.GetStats()
	fmt.Printf("\nStats: %+v\n", stats)
}
