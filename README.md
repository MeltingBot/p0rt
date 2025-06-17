# P0rt

A fast, free HTTP/S tunneling service with SSH port forwarding.

## Features

- 📡 Instant HTTPS tunnels with valid certificates
- 🔒 SSH public key authentication
- 🌐 WebSocket support
- ⚡ No installation or signup required
- 🆓 Free and open source

## Quick Start

### Server Setup

1. Build the server:
```bash
go build -o p0rt ./cmd/server
```

2. Run with environment variables:
```bash
SSH_SERVER_PORT=2222 HTTP_PORT=80 ./p0rt
```

### Client Usage

Expose your local web server:
```bash
ssh -R 443:localhost:8080 p0rt.xyz
```

Use a custom subdomain (method 1 - via SSH -R):
```bash
ssh -R myapp:80:localhost:8080 p0rt.xyz -p 2222
```

Use a custom subdomain (method 2 - via environment variable):
```bash
ssh -R 443:localhost:8080 -o SendEnv=LC_DOMAIN -o SetEnv=LC_DOMAIN=myapp p0rt.xyz
```

## Configuration

Environment variables:
- `SSH_SERVER_PORT`: SSH server port (default: 2222)
- `HTTP_PORT`: HTTP proxy port (default: 80)
- `SSH_HOST_KEY`: SSH host private key (optional, generates if not provided)
- `DOMAIN_BASE`: Base domain for tunnels (default: skytunnel.run)

## Docker

Build and run with Docker:
```bash
docker build -t p0rt .
docker run -p 2222:2222 -p 80:80 p0rt
```

## Architecture

- **SSH Server**: Handles client connections and port forwarding
- **HTTP/WebSocket Proxy**: Routes requests to appropriate tunnels
- **TCP Manager**: Manages local TCP servers for each connection
- **Domain Generator**: Creates deterministic subdomains from SSH keys

## Development

Run tests:
```bash
go test ./...
```

Format code:
```bash
go fmt ./...
```

## License

MIT