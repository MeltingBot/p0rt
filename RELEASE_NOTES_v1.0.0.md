# 🚀 P0rt v1.0.0 - First Stable Release

We're excited to announce the first stable release of **P0rt** - a fast, free SSH tunneling service that makes exposing local servers to the internet simple and secure!

## 🎉 What is P0rt?

P0rt allows you to expose your localhost to the internet with just one SSH command:

```bash
ssh -R 443:localhost:3000 ssh.p0rt.xyz
```

Your app instantly becomes available at a memorable three-word domain like `whale-guitar-fox.p0rt.xyz`.

## ✨ Key Features

### 🧠 **Smart Domain Generation**
- Deterministic three-word domains from your SSH key fingerprint
- Always get the same domain with the same key
- 304 million unique combinations

### ⚡ **Lightning Fast**
- Written in Go for blazing performance
- < 50ms latency overhead
- Handles thousands of concurrent connections

### 🛡️ **Enterprise-Grade Security**
- SSH public key authentication only
- Automatic HTTPS with valid certificates
- Advanced abuse reporting and prevention system
- Forensic tracking headers for security compliance
- IP-based protection and rate limiting

### 🔍 **Real-Time Monitoring**
- See connections directly in your SSH terminal
- Track visitor IPs, requests, and user agents
- Live traffic statistics

### 🏗️ **Production Ready**
- Docker support with compose files
- Dual storage: Redis for production, JSON for development
- Automatic fallback when Redis unavailable
- Environment-based configuration

## 🚨 Anti-Abuse System

P0rt includes comprehensive protection against malicious use:

- **Public reporting endpoint** (`/report-abuse`) for community moderation
- **Automatic domain banning** with custom 403 pages
- **Forensic headers** linking HTTP requests to SSH users
- **IP tracking and blocking** for security investigations
- **Rate limiting** and DDoS protection

## 📦 Available Downloads

Choose your platform:

### Linux
- **p0rt-v1.0.0-linux-amd64.tar.gz** - 64-bit Linux (Intel/AMD)
- **p0rt-v1.0.0-linux-arm64.tar.gz** - 64-bit Linux (ARM, Raspberry Pi 4+)
- **p0rt-v1.0.0-linux-386.tar.gz** - 32-bit Linux

### macOS
- **p0rt-v1.0.0-darwin-amd64.tar.gz** - Intel Macs
- **p0rt-v1.0.0-darwin-arm64.tar.gz** - Apple Silicon Macs (M1/M2/M3)

### Windows
- **p0rt-v1.0.0-windows-amd64.zip** - 64-bit Windows
- **p0rt-v1.0.0-windows-386.zip** - 32-bit Windows

### FreeBSD
- **p0rt-v1.0.0-freebsd-amd64.tar.gz** - 64-bit FreeBSD

## 🚀 Quick Start

### 1. Download and Extract
```bash
# Linux/macOS example
wget https://github.com/MeltingBot/p0rt/releases/download/v1.0.0/p0rt-v1.0.0-linux-amd64.tar.gz
tar -xzf p0rt-v1.0.0-linux-amd64.tar.gz
chmod +x p0rt-v1.0.0-linux-amd64
```

### 2. Start the Server
```bash
# Development mode (port 2222)
./p0rt-v1.0.0-linux-amd64 server start

# Or use the included run.sh script
./run.sh dev
```

### 3. Connect from Another Machine
```bash
ssh -R 443:localhost:8080 ssh.p0rt.xyz -p 2222
```

Your app is now live at `https://your-three-words.p0rt.xyz`!

## 🐳 Docker Deployment

For production deployment:

```bash
# Clone the repository for docker-compose.yml
git clone https://github.com/MeltingBot/p0rt.git
cd p0rt

# Start production server
./run.sh prod
```

## 💡 Use Cases

Perfect for:
- **Development and testing** - Share work in progress
- **Demos and presentations** - Show prototypes to clients
- **Webhook testing** - Receive webhooks locally
- **IoT and embedded devices** - Remote access without port forwarding
- **Quick file sharing** - Instant web server for files

## 🔧 Management

P0rt includes powerful management tools:

```bash
# Interactive CLI
./p0rt cli

# Check server status
./p0rt server status

# Manage reservations
./p0rt reservation list
./p0rt reservation add happy-cat-jump SHA256:abc123... "My Project"

# View statistics
./p0rt stats

# Security monitoring
./p0rt security
```

## 📋 System Requirements

- **Minimal**: 50MB RAM, any modern CPU
- **Recommended**: 256MB RAM for production use
- **Storage**: < 100MB for binaries, minimal for data
- **Network**: SSH (port 22/2222) and HTTP (port 80/8080) access

## 🤝 Community & Support

- **Documentation**: Full guides in the repository README
- **Issues**: Report bugs and request features on GitHub
- **Security**: Responsible disclosure via GitHub issues
- **Contributing**: Pull requests welcome!

## 🙏 Acknowledgments

Special thanks to:
- The Go community for excellent libraries
- Beta testers who helped refine the security system
- Contributors who reported issues and suggested improvements

---

## What's Next?

This stable release provides a solid foundation. Future versions will focus on:
- Enhanced analytics and monitoring
- Additional security features
- Performance optimizations
- Extended platform support

**Ready to get started?** Download your platform's binary above and follow the Quick Start guide!

For detailed documentation, visit the [GitHub repository](https://github.com/MeltingBot/p0rt).