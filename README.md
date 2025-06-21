<div align="center">
  <h1>🚀 p0rt</h1>
  <p>
    <strong>Fast, secure HTTP/S tunneling service</strong><br>
    Expose your localhost to the internet instantly via SSH
  </p>
  
  <p>
    <img src="https://img.shields.io/badge/language-Go-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
    <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License">
    <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-informational?style=for-the-badge" alt="Platform">
  </p>
</div>

---

## ✨ Features

<table>
<tr>
<td>

### 🔒 **Secure by Default**
- SSH public key authentication
- HTTPS with valid certificates
- No passwords, no accounts
- SSH key allowlist for controlled access

</td>
<td>

### ⚡ **Lightning Fast**
- Zero configuration required
- Instant tunnel creation
- WebSocket support included
- < 50ms latency overhead

</td>
</tr>
<tr>
<td>

### 🌍 **Universal Access**
- Works behind firewalls & NATs
- Custom subdomain support
- Cross-platform compatibility
- Automatic key reloading

</td>
<td>

### 🛠️ **Developer Friendly**
- Simple SSH command interface
- Docker & Kubernetes ready
- Open source & self-hostable
- Interactive CLI mode

</td>
</tr>
</table>

## 🚀 Quick Start

### Development Mode

```bash
./run.sh dev
```

**Features:**
- SSH on port 2222
- HTTP on port 8080
- Open access (all SSH keys allowed)
- Perfect for testing

### Production Mode

```bash
./run.sh prod
```

**Features:**
- SSH on port 22
- HTTP on port 80
- Restricted access (SSH key allowlist)
- Docker containerized

## 📦 Installation

### Building from Source

```bash
# Clone repository
git clone https://github.com/MeltingBot/p0rt.git
cd p0rt

# Build
go build -o p0rt cmd/server/main.go

# Run development
./run.sh dev

# Run production
./run.sh prod
```

## 🔑 SSH Key Management

P0rt supports two access modes:

### Open Access Mode (Development)
- Any SSH key can create tunnels
- Enable with: `P0RT_OPEN_ACCESS=true`
- Perfect for development and testing

### Restricted Access Mode (Production)
- Only pre-registered SSH keys allowed
- Ideal for beta programs, freemium, or VIP access
- Support for access tiers: `beta`, `free`, `premium`, `vip`

### Managing Keys

**Add key by fingerprint (easiest):**
```bash
./p0rt -key add --key-fingerprint SHA256:abc123... --tier beta --comment "John Doe"
```

**Add key from file:**
```bash
./p0rt -key add --key-file ~/.ssh/id_rsa.pub --tier premium --comment "Jane Smith"
```

**List all keys:**
```bash
./p0rt -key list
```

**Remove key:**
```bash
./p0rt -key remove --fingerprint SHA256:abc123...
```

**Deactivate/Activate key:**
```bash
./p0rt -key deactivate --fingerprint SHA256:abc123...
./p0rt -key activate --fingerprint SHA256:abc123...
```

### Interactive CLI

```bash
./p0rt -cli
```

Available commands:
- `key add <fingerprint> [tier] [comment]` - Add SSH key
- `key list` - List all authorized keys
- `key remove <fingerprint>` - Remove key
- `server` - Start server
- `stats` - Show statistics
- `help` - Show all commands

## 🌐 Creating Tunnels

### Basic Tunnel

```bash
ssh -R 443:localhost:8080 p0rt.xyz
```

Your app at `http://localhost:8080` is now available at `https://[generated-subdomain].p0rt.xyz`

### Custom Subdomain

```bash
# Method 1: Direct specification
ssh -R myapp:443:localhost:3000 p0rt.xyz

# Method 2: Environment variable
ssh -o SendEnv=LC_DOMAIN -o SetEnv=LC_DOMAIN=myapp -R 443:localhost:3000 p0rt.xyz
```

Your app is now at `https://myapp.p0rt.xyz`

### Multiple Ports

```bash
# Expose both HTTP and a custom port
ssh -R 443:localhost:3000 -R 8080:localhost:8080 p0rt.xyz
```

## 🐳 Docker Deployment

### Production with Docker Compose

```bash
# Start production server
./run.sh prod

# Add your SSH key
docker exec p0rt ./p0rt -key add --key-fingerprint SHA256:your_key --tier beta

# View logs
docker logs -f p0rt

# Interactive CLI in Docker
docker exec -it p0rt ./p0rt -cli
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `P0RT_OPEN_ACCESS` | Allow any SSH key | `false` |
| `SSH_SERVER_PORT` | SSH server port | `22` |
| `HTTP_PORT` | HTTP server port | `80` |
| `P0RT_AUTHORIZED_KEYS` | Path to authorized keys JSON | `authorized_keys.json` |

## 🏗️ Architecture

```mermaid
graph LR
    A[Client] -->|SSH| B[SSH Server]
    B --> C[Key Validator]
    C --> D[TCP Manager]
    E[HTTP Request] --> F[HTTP/WS Proxy]
    F --> D
    D --> G[Client's Local Server]
```

### Core Components

- **SSH Server**: Handles authentication and port forwarding
- **Key Store**: Manages SSH key allowlist with auto-reload
- **HTTP/WebSocket Proxy**: Routes requests based on subdomain
- **TCP Manager**: Manages connection lifecycle
- **Domain Generator**: Creates deterministic subdomains
- **Security Module**: Rate limiting and abuse prevention

## 📊 Performance

- **Concurrent Connections**: 10,000+
- **Throughput**: 1 Gbps+ per tunnel
- **Latency Overhead**: < 50ms
- **Memory Usage**: ~50MB base + 1MB per connection
- **Key Reload**: Automatic, no restart needed

## 🛡️ Security Features

- ✅ SSH public key authentication only
- ✅ Automatic HTTPS with valid certificates
- ✅ Rate limiting and DDoS protection
- ✅ IP-based connection limits
- ✅ Abuse detection and blocking
- ✅ SSH key allowlist with tiers
- ✅ Automatic key expiration support

## 📈 Monitoring

**View statistics:**
```bash
./p0rt -cli
> stats
```

**Check server status:**
```bash
./p0rt -cli
> status
```

**Security events:**
```bash
./p0rt -cli
> security
```

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file.

---

<div align="center">
  <p>
    <a href="https://p0rt.xyz">Website</a> •
    <a href="https://github.com/MeltingBot/p0rt">GitHub</a> •
    <a href="https://github.com/MeltingBot/p0rt/issues">Issues</a>
  </p>
  <p>Made with ❤️ by the p0rt team</p>
</div>