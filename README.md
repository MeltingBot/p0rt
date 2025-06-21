# 🚀 P0rt

**Fast, secure SSH tunneling service** - expose your localhost to the internet instantly.

## ⚡ Quick Start

### Development Mode
```bash
./run.sh dev
```
- SSH: `localhost:2222`
- HTTP: `localhost:8080`
- **Open access** - any SSH key works

### Production Mode
```bash
./run.sh prod
```
- SSH: `port 22`
- HTTP: `port 80`
- **Restricted access** - authorized keys only

## 🔑 Key Management

**Add SSH key:**
```bash
./p0rt -key add --key-fingerprint SHA256:your_fingerprint --tier beta --comment "Your Name"
```

**List authorized keys:**
```bash
./p0rt -key list
```

**Remove key:**
```bash
./p0rt -key remove --fingerprint SHA256:your_fingerprint
```

**Interactive CLI:**
```bash
./p0rt -cli
```

## 🌐 Usage

**Create tunnel:**
```bash
ssh -R 443:localhost:8080 your-server.com
```

**Your tunnel:** `https://generated-subdomain.p0rt.xyz`

**Custom subdomain:**
```bash
ssh -R myapp:443:localhost:8080 your-server.com
```

**Your custom tunnel:** `https://myapp.p0rt.xyz`

## 🐳 Docker

Production deployment with Docker:
```bash
# Start production server
./run.sh prod

# Add your SSH key
docker exec p0rt ./p0rt -key add --key-fingerprint SHA256:your_key --tier beta

# View logs
docker logs -f p0rt
```

## 🔒 Access Control

### Open Mode (Development)
- Any SSH key can create tunnels
- Perfect for testing and development

### Restricted Mode (Production)
- Only pre-registered SSH keys allowed
- Ideal for beta programs or controlled access
- Support for tiers: `beta`, `free`, `premium`, `vip`

## 📋 Commands

| Command | Description |
|---------|-------------|
| `./run.sh dev` | Start development server |
| `./run.sh prod` | Start production server |
| `./p0rt -key add` | Add authorized SSH key |
| `./p0rt -key list` | List all keys |
| `./p0rt -cli` | Interactive mode |

---

**Made simple.** Two commands, infinite possibilities. 🚪