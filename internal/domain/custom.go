package domain

import (
	"fmt"
	"net"
	"strings"
)

// CustomDomainValidator validates custom domains via DNS records
type CustomDomainValidator struct {
	baseDomain string
}

// NewCustomDomainValidator creates a new validator
func NewCustomDomainValidator(baseDomain string) *CustomDomainValidator {
	return &CustomDomainValidator{
		baseDomain: baseDomain,
	}
}

// ValidateCustomDomain checks if a custom domain is properly configured
func (v *CustomDomainValidator) ValidateCustomDomain(customDomain, sshKeyFingerprint string) error {
	// Step 1: Verify CNAME points to p0rt.xyz
	if err := v.validateCNAME(customDomain); err != nil {
		return fmt.Errorf("CNAME validation failed: %w", err)
	}

	// Step 2: Verify TXT record with SSH key fingerprint
	if err := v.validateTXTRecord(customDomain, sshKeyFingerprint); err != nil {
		return fmt.Errorf("TXT record validation failed: %w", err)
	}

	return nil
}

// validateCNAME checks if the domain has a CNAME pointing to p0rt.xyz
func (v *CustomDomainValidator) validateCNAME(domain string) error {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return fmt.Errorf("failed to lookup CNAME for %s: %w", domain, err)
	}

	// Remove trailing dot if present
	cname = strings.TrimSuffix(cname, ".")
	expectedCNAME := v.baseDomain

	if cname != expectedCNAME && cname != expectedCNAME+"." {
		return fmt.Errorf("CNAME points to %s, expected %s", cname, expectedCNAME)
	}

	return nil
}

// validateTXTRecord checks if the TXT record contains the SSH key fingerprint
func (v *CustomDomainValidator) validateTXTRecord(domain, expectedFingerprint string) error {
	// Construct the TXT record domain: _p0rt-authkey.subdomain.example.com
	txtDomain := fmt.Sprintf("_p0rt-authkey.%s", domain)

	txtRecords, err := net.LookupTXT(txtDomain)
	if err != nil {
		return fmt.Errorf("failed to lookup TXT record for %s: %w", txtDomain, err)
	}

	// Look for the fingerprint in any of the TXT records
	for _, record := range txtRecords {
		// Clean up the record (remove quotes, spaces)
		cleanRecord := strings.TrimSpace(strings.Trim(record, "\""))
		
		// Check if this is our auth key
		if strings.HasPrefix(cleanRecord, "p0rt-authkey=") {
			fingerprint := strings.TrimPrefix(cleanRecord, "p0rt-authkey=")
			if fingerprint == expectedFingerprint {
				return nil
			}
			return fmt.Errorf("fingerprint mismatch: got %s, expected %s", fingerprint, expectedFingerprint)
		}
	}

	return fmt.Errorf("no valid p0rt-authkey TXT record found at %s", txtDomain)
}

// GetCustomDomainInstructions returns instructions for setting up a custom domain
func (v *CustomDomainValidator) GetCustomDomainInstructions(customDomain, sshKeyFingerprint string) string {
	return fmt.Sprintf(`
Custom Domain Setup Instructions for: %s

1. Add a CNAME record:
   Host: %s
   Target: %s

2. Add a TXT record for authentication:
   Host: _p0rt-authkey.%s
   Value: p0rt-authkey=%s

3. Wait for DNS propagation (usually 5-30 minutes)

4. Connect using:
   ssh -R 443:localhost:3000 ssh.%s -o "SetEnv LC_CUSTOM_DOMAIN=%s"

Your service will be available at: https://%s
`, customDomain, customDomain, v.baseDomain, customDomain, sshKeyFingerprint, v.baseDomain, customDomain, customDomain)
}