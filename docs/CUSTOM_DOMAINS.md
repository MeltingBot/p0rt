# Custom Domains with P0rt

P0rt supports using your own domain names through DNS validation. This allows you to serve your tunneled services from your own domain (e.g., `api.example.com`) instead of a generated P0rt subdomain.

## How It Works

P0rt uses DNS records to verify domain ownership:
1. **CNAME record**: Points your domain to `p0rt.xyz`
2. **TXT record**: Contains your SSH key fingerprint for authentication

## Setup Instructions

### 1. Get Your SSH Key Fingerprint

Run the helper script:
```bash
./scripts/get-fingerprint.sh
```

Or manually:
```bash
ssh-keygen -lf ~/.ssh/id_rsa.pub | awk '{print $2}' | sed 's/SHA256://'
```

Example output: `uG0kODz5K9vRFfqhWtQBWnMcCDXPr8gQp0LnWGYzLmI`

### 2. Configure DNS Records

Add these records to your domain's DNS settings:

#### CNAME Record
- **Host**: `yourdomain.com` (or `subdomain.yourdomain.com`)
- **Type**: CNAME
- **Target**: `p0rt.xyz`

#### TXT Record
- **Host**: `_p0rt-authkey.yourdomain.com`
- **Type**: TXT
- **Value**: `p0rt-authkey=YOUR_FINGERPRINT`

Example for `dev.example.com`:
```
dev.example.com          CNAME   p0rt.xyz
_p0rt-authkey.dev.example.com  TXT     "p0rt-authkey=uG0kODz5K9vRFfqhWtQBWnMcCDXPr8gQp0LnWGYzLmI"
```

### 3. Wait for DNS Propagation

DNS changes typically take 5-30 minutes to propagate. You can check propagation status at:
- https://dnschecker.org
- https://whatsmydns.net

### 4. Connect Using Your Domain

```bash
ssh -R 443:localhost:3000 ssh.p0rt.xyz -o "SetEnv LC_CUSTOM_DOMAIN=yourdomain.com"
```

Your service will be accessible at `https://yourdomain.com`

## Multiple Custom Domains

You can use multiple custom domains with the same SSH key. Each domain needs:
- Its own CNAME pointing to `p0rt.xyz`
- Its own TXT record with your fingerprint

## Troubleshooting

### "Custom domain validation failed"

If you see this error, check:

1. **DNS Records**: Ensure both CNAME and TXT records are correctly configured
2. **TXT Format**: The value must be exactly `p0rt-authkey=FINGERPRINT` (no extra spaces)
3. **DNS Propagation**: Wait for DNS changes to propagate globally
4. **Fingerprint**: Ensure you're using the correct SSH key fingerprint

### Testing DNS Records

Test CNAME:
```bash
dig yourdomain.com CNAME
```

Test TXT:
```bash
dig _p0rt-authkey.yourdomain.com TXT
```

## Security

- Your SSH key fingerprint is public information (safe to share)
- Only someone with your private SSH key can use your custom domain
- The TXT record proves domain ownership without exposing your private key

## Examples

### API Endpoint
```bash
# DNS Setup:
# api.mycompany.com → p0rt.xyz (CNAME)
# _p0rt-authkey.api.mycompany.com → "p0rt-authkey=ABC123..." (TXT)

ssh -R 443:localhost:8080 ssh.p0rt.xyz -o "SetEnv LC_CUSTOM_DOMAIN=api.mycompany.com"
# → https://api.mycompany.com
```

### Development Environment
```bash
# DNS Setup:
# dev.project.io → p0rt.xyz (CNAME)
# _p0rt-authkey.dev.project.io → "p0rt-authkey=XYZ789..." (TXT)

ssh -R 443:localhost:3000 ssh.p0rt.xyz -o "SetEnv LC_CUSTOM_DOMAIN=dev.project.io"
# → https://dev.project.io
```

## Limitations

- SSL certificates are provided by Cloudflare (not custom certificates)
- The domain must resolve to `p0rt.xyz` via CNAME
- Wildcard domains are not supported (each subdomain needs its own records)

## P0rt Subdomains Policy

P0rt only provides automatically generated three-word subdomains (e.g., `whale-guitar-fox.p0rt.xyz`). Custom subdomains of p0rt.xyz (like `api.p0rt.xyz` or `dev.p0rt.xyz`) are **not available**.

This ensures:
- Fair access to namespace for all users
- Prevents subdomain squatting
- Maintains consistent three-word pattern
- Encourages use of your own domains for branding

If you need a specific domain name, please use your own domain with the DNS validation method described above.