# P0rt Security Features

This document outlines the security measures implemented in P0rt focusing on connection-level protections while respecting user privacy.

## Security Philosophy

P0rt prioritizes **user privacy** and **connection security** over content monitoring:
- **No HTTP content inspection** - We don't analyze what you're serving
- **No domain filtering** - All domain names are allowed
- **SSH-level protection only** - Focus on preventing infrastructure abuse

## Automated Security Monitoring

P0rt includes connection-level security features:

### 1. SSH Connection Rate Limiting
- **Per SSH Key**: Maximum 100 connections per hour per SSH key
- **Auto-Block**: Keys exceeding the limit are blocked for 24 hours
- **Progressive Banning**: 3 attempts=15min, 5=1h, 10+=24h

### 2. SSH Scan Detection
- **Pattern Recognition**: Automatic detection of SSH scanning patterns
- **Immediate Blocking**: Known malicious IPs blocked for 24h
- **Scan Pattern Bans**: 6h automatic bans for scan-like behavior

### 3. Abuse Reporting System
- **Public Endpoint**: `/report-abuse` endpoint for reporting infrastructure abuse
- **Manual Review**: Human review of reported cases
- **SSH-level Actions**: Actions taken at connection level, not content level

## SSH Scan Patterns Detected

### Automated Scanner Behavior
- Immediate disconnection after connection (reason 11)
- Connection attempts without authentication
- Rapid connection/disconnection cycles
- EOF connections (dropped connections)

### Response to SSH Abuse

When SSH-level abuse is detected:

1. **IP Blocking**: The source IP is blocked at connection level
2. **Progressive Bans**: Increasing ban duration for repeat offenders
3. **Logging**: All SSH abuse attempts are logged
4. **No Content Inspection**: Actions are based on connection patterns only

## Privacy-First Approach

P0rt follows a privacy-first security model:

- **No HTTP Monitoring**: We don't inspect HTTP traffic content
- **No Domain Restrictions**: All domain names are allowed
- **No Content Filtering**: You can serve any content you want
- **SSH-Only Protection**: Security measures only apply to SSH connection patterns

## Best Practices for Users

To avoid triggering SSH-level security measures:

- **Reasonable Connections**: Don't create excessive SSH connections
- **Proper SSH Clients**: Use legitimate SSH clients, not automated scanners
- **Report Issues**: If your IP is blocked incorrectly, contact us

## Rate Limits

Current rate limits:
- **SSH Connections**: 100 per hour per SSH key
- **HTTP Requests**: No limits - privacy-first approach
- **Abuse Reports**: 10 per hour per IP address

## Technical Implementation

Privacy-focused security features are implemented in:
- `internal/security/abuse_monitor.go`: SSH connection rate limiting
- `internal/ssh/server.go`: SSH scan detection and IP blocking
- `internal/proxy/http.go`: No content inspection, connection logging only

## What We Don't Do

For privacy reasons, P0rt **does not**:
- Inspect HTTP request content
- Filter domain names based on keywords
- Analyze website content for malicious patterns
- Block tunnels based on what you're serving
- Store or analyze user-generated content

## Contact

For security inquiries about SSH-level issues only: security@p0rt.xyz

**Note**: We cannot and will not take action based on website content - only SSH abuse patterns.