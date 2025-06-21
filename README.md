# P0rt

SSH tunneling service - expose local servers to the internet.

## Quick Start

### Development
```bash
./run.sh dev
```
- SSH port: 2222
- HTTP port: 8080  
- Open access (all SSH keys allowed)

### Production
```bash
./run.sh prod
```
- SSH port: 22
- HTTP port: 80
- Restricted access (authorized keys only)

## Key Management

Add SSH key:
```bash
./p0rt -key add --key-fingerprint SHA256:your_fingerprint --tier beta
```

List keys:
```bash
./p0rt -key list
```

## Usage

Connect with SSH:
```bash
ssh -R 443:localhost:8080 your-server.com
```

Your tunnel will be available at: `https://generated-subdomain.p0rt.xyz`