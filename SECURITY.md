# P0rt Security Features

This document outlines the security measures implemented in P0rt to prevent abuse and protect users.

## Automated Security Monitoring

P0rt includes several automated security features:

### 1. Domain Monitoring
- **Keyword Filtering**: Domains containing suspicious keywords like "phishing", "malware", "spam", "scam", etc. are automatically blocked
- **Pattern Detection**: Domains that match known malicious patterns are rejected during generation

### 2. Connection Rate Limiting
- **Per SSH Key**: Maximum 100 connections per hour per SSH key
- **Auto-Block**: Keys exceeding the limit are blocked for 24 hours
- **IP-based Bruteforce Protection**: Already implemented to prevent SSH bruteforce attacks

### 3. HTTP Request Analysis
- **Content Scanning**: Real-time analysis of HTTP requests for suspicious patterns
- **Phishing Detection**: Automatic detection of common phishing keywords and URLs
- **Spam/Scam Patterns**: Identification of spam and scam-related content

### 4. Abuse Reporting System
- **Public Endpoint**: `/report-abuse` endpoint for reporting malicious tunnels
- **Automated Alerts**: Real-time notifications for security incidents
- **Investigation Tools**: Logging and tracking of reported abuse cases

## Security Patterns Detected

### Phishing Indicators
- Login/signin pages mimicking legitimate services
- Account verification/suspension messages
- Password/credit card collection forms
- Fake bank/payment service pages

### Spam Indicators
- Casino/lottery/prize claiming sites
- Pharmaceutical advertisements
- Cryptocurrency investment schemes
- Get-rich-quick schemes

### Scam Indicators
- Urgent action required messages
- Nigerian prince/inheritance scams
- Wire transfer requests
- Too-good-to-be-true offers

## Response to Security Incidents

When suspicious activity is detected:

1. **Immediate Block**: The tunnel is immediately blocked from serving requests
2. **Security Page**: Visitors see a security warning instead of the malicious content
3. **Logging**: All incidents are logged for analysis
4. **Investigation**: Security team reviews the case
5. **Action**: Appropriate action taken (temporary/permanent block, contact authorities if needed)

## False Positives

If your legitimate service is incorrectly blocked:

1. **Contact**: Email security@p0rt.xyz with details
2. **Review**: Security team reviews the case manually
3. **Whitelist**: Legitimate services are whitelisted
4. **Pattern Update**: Security patterns are refined to reduce false positives

## Best Practices for Users

To avoid triggering security measures:

- **Avoid Suspicious Keywords**: Don't use words like "login", "verify", "urgent" in your app content unnecessarily
- **Clear Documentation**: Provide clear information about what your service does
- **Reasonable Use**: Don't create excessive connections or tunnel high-traffic production services
- **Report Issues**: If blocked incorrectly, contact us promptly

## Rate Limits

Current rate limits:
- **SSH Connections**: 100 per hour per SSH key
- **HTTP Requests**: No hard limit, but monitored for abuse patterns
- **Abuse Reports**: 10 per hour per IP address

## Technical Implementation

Security features are implemented in:
- `internal/security/abuse_monitor.go`: Core security monitoring
- `internal/ssh/server.go`: SSH connection security checks
- `internal/proxy/http.go`: HTTP request analysis and blocking

## Continuous Improvement

P0rt's security system continuously evolves:
- **Pattern Updates**: Regular updates to detection patterns
- **Machine Learning**: Future implementation of ML-based detection
- **Community Reports**: User reports help improve detection accuracy
- **Threat Intelligence**: Integration with security threat feeds

For security inquiries, contact: security@p0rt.xyz