# CLI Usage Guide

P0rt provides multiple ways to interact with the system:

## 1. Server Mode (Default)

Start the P0rt server:
```bash
./p0rt
```

With custom configuration:
```bash
./p0rt -config /path/to/config.yaml
```

## 1.1. Server Management

Explicit server commands:
```bash
# Start the server
./p0rt -server start

# Check server status
./p0rt -server status

# Stop/restart (not yet implemented)
./p0rt -server stop
./p0rt -server restart
```

## 2. Interactive CLI Mode

### Local Mode
Start the interactive command-line interface for local management:
```bash
./p0rt -cli
```

### Remote Mode
Connect to a remote P0rt server via API:
```bash
./p0rt -cli -remote http://localhost:80
```

With API key authentication:
```bash
./p0rt -cli -remote http://localhost:80 -api-key your-secret-key
```

### Interactive CLI Features

- **Tab completion**: Press `Tab` to autocomplete commands and domain names
- **Command history**: Use ↑/↓ arrows to navigate command history
- **Help system**: Type `help` for available commands or `help <command>` for detailed help

### Available Commands

#### Basic Commands
- `help [command]` - Show help information
- `server [action]` - Manage the P0rt server (start, stop, restart, status)
- `exit` / `quit` / `q` - Exit the CLI
- `clear` - Clear the screen
- `status` - Show system status
- `stats` - Show system statistics

#### Reservation Commands
- `reservation add <domain> <fingerprint> [comment]` - Reserve a domain
- `reservation remove <domain>` - Remove a reservation
- `reservation list` - List all reservations
- `reservation stats` - Show reservation statistics

You can also use the short form `res` instead of `reservation`.

### Examples

```bash
p0rt> help
Available commands:
  help [command]     - Show help information
  server             - Start the P0rt server
  reservation        - Manage domain reservations
  stats             - Show system statistics
  status            - Show system status
  clear             - Clear the screen
  exit              - Exit the CLI

p0rt> server start
Starting P0rt server...
SSH Port: 2222
HTTP Port: 80
Domain Base: p0rt.xyz

Press Ctrl+C to stop the server

p0rt> reservation add happy-cat-jump SHA256:abc123... "My personal domain"
✓ Successfully reserved domain 'happy-cat-jump' for SSH key fingerprint 'SHA256:abc123...'
  Comment: My personal domain

p0rt> res list
Found 1 reservation(s):

1. Domain: happy-cat-jump
   Fingerprint: SHA256:abc123...
   Comment: My personal domain
   Created: 2024-01-15 10:30:45
   Updated: 2024-01-15 10:30:45

p0rt> help reservation
Reservation commands:
  reservation add <domain> <fingerprint> [comment]
    - Reserve a domain for an SSH key
  reservation remove <domain>
    - Remove a domain reservation
  reservation list
    - List all reservations
  reservation stats
    - Show reservation statistics

Examples:
  reservation add happy-cat-jump SHA256:abc123... "My personal domain"
  reservation remove happy-cat-jump
  reservation list

p0rt> exit
```

## 3. Command-Line Mode

Execute single commands directly:

### Server Management
```bash
# Start the server explicitly
./p0rt -server start

# Check server status
./p0rt -server status

# Stop/restart server (not yet implemented)
./p0rt -server stop
./p0rt -server restart
```

### Local Reservation Management
```bash
# Add a reservation (local storage) - long form
./p0rt -reservation add -domain "happy-cat-jump" -fingerprint "SHA256:abc123..." -comment "My domain"

# Add a reservation (local storage) - short form
./p0rt -r add -d "happy-cat-jump" -f "SHA256:abc123..." -c "My domain"

# List reservations (local storage)
./p0rt -reservation list  # or: ./p0rt -r list

# Remove a reservation (local storage)
./p0rt -reservation remove -domain "happy-cat-jump"  # or: ./p0rt -r remove -d "happy-cat-jump"

# Show statistics (local storage)
./p0rt -reservation stats  # or: ./p0rt -r stats
```

### Remote Reservation Management
```bash
# Add a reservation to remote server - long form
./p0rt -remote http://localhost:80 -reservation add -domain "happy-cat-jump" -fingerprint "SHA256:abc123..." -comment "My domain"

# Add a reservation to remote server - short form
./p0rt -R http://localhost:80 -r add -d "happy-cat-jump" -f "SHA256:abc123..." -c "My domain"

# List reservations from remote server
./p0rt -remote http://localhost:80 -reservation list  # or: ./p0rt -R http://localhost:80 -r list

# Remove a reservation from remote server
./p0rt -remote http://localhost:80 -reservation remove -domain "happy-cat-jump"

# Show statistics from remote server
./p0rt -remote http://localhost:80 -reservation stats

# With API key authentication - short form
./p0rt -R http://localhost:80 -k your-secret-key -r list

# With API key authentication - long form
./p0rt -remote http://localhost:80 -api-key your-secret-key -reservation list
```

## Configuration

All modes use the same configuration system:

1. **Config file**: Specify with `-config` flag
2. **Environment variables**: Override specific settings
3. **Defaults**: Built-in sensible defaults

### Example Configuration
```yaml
server:
  ssh:
    port: 2222
  http:
    port: 80

domain:
  base: "p0rt.xyz"
  reservations_enabled: true

storage:
  type: "json"        # or "redis"
  data_dir: "./data"
```

## Tips

1. **Interactive mode** is best for exploring and managing reservations
2. **Command-line mode** is ideal for scripting and automation  
3. **Server mode** runs the actual tunneling service
4. Use `Tab` completion in interactive mode to discover available options
5. The `help` command provides context-sensitive assistance
6. **Docker/systemd**: Use `./p0rt -server start` for explicit server launching in containers or service files

## Docker & Systemd Integration

The explicit server command is particularly useful for containerization and service management:

### Docker Example
```dockerfile
CMD ["./p0rt", "-server", "start"]
```

### Systemd Service Example
```ini
[Unit]
Description=P0rt SSH Tunneling Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/p0rt -server start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```