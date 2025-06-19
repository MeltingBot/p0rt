# P0rt Quick Reference

## 🚀 **Flag Conventions**

P0rt uses standard GNU conventions:

| Style | Format | Example |
|-------|--------|---------|
| **Short** | `-f` | `p0rt r add -d test -f SHA256:abc` |
| **Long** | `--flag` | `p0rt reservation add --domain test --fingerprint SHA256:abc` |
| **Mixed** | `-f --flag` | `p0rt r add test -f SHA256:abc --comment "mixed"` |

## 📋 **Command Reference**

### Global Flags
```bash
-C, --config      # Configuration file
-R, --remote      # Remote server URL  
-k, --api-key     # API authentication key
-h, --help        # Show help
```

### Server Management
```bash
p0rt server start                    # Start server
p0rt server status                   # Check status
p0rt server stop                     # Stop server (not implemented)
```

### Reservations - Local
```bash
# List
p0rt reservation list                # Long form
p0rt r list                         # Short form

# Add - Positional arguments
p0rt r add happy-cat-jump SHA256:abc123 "comment"

# Add - Flags (short)
p0rt r add -d happy-cat-jump -f SHA256:abc123 -c "comment"

# Add - Flags (long)
p0rt reservation add --domain happy-cat-jump --fingerprint SHA256:abc123 --comment "comment"

# Remove
p0rt r remove happy-cat-jump         # Short
p0rt r rm happy-cat-jump            # Alias
p0rt reservation remove happy-cat-jump  # Long

# Stats
p0rt r stats                        # Short
p0rt reservation stats              # Long
```

### Reservations - Remote
```bash
# Remote with long flags
p0rt --remote http://localhost:80 --api-key secret reservation list

# Remote with short flags
p0rt -R http://localhost:80 -k secret r list

# Remote mixed
p0rt --remote http://localhost:80 -k secret r add test-domain -f SHA256:abc
```

### Statistics
```bash
p0rt stats                          # Global stats
p0rt stats happy-cat-jump           # Domain-specific stats

# Remote stats
p0rt -R http://localhost:80 stats
p0rt --remote http://localhost:80 stats domain-name
```

### Interactive CLI
```bash
p0rt cli                            # Local interactive
p0rt i                              # Short alias

# Remote interactive
p0rt -R http://localhost:80 -k secret cli
p0rt --remote http://localhost:80 --api-key secret i
```

## 🎯 **Common Patterns**

### Daily Usage (Short & Fast)
```bash
p0rt r list                         # List reservations
p0rt r add test -f SHA256:abc       # Quick add
p0rt i                              # Interactive mode
p0rt -R localhost:80 -k secret r list  # Remote list
```

### Scripts (Long & Clear)
```bash
p0rt reservation list
p0rt reservation add --domain test --fingerprint SHA256:abc --comment "Production"
p0rt --remote http://server:80 --api-key "$API_KEY" reservation list
```

### Debugging (Verbose)
```bash
p0rt --config /path/to/config.yaml server start
p0rt --remote http://localhost:80 --api-key secret stats domain-name
```

## 🔧 **Auto-completion Setup**

```bash
# Bash
p0rt completion bash > /etc/bash_completion.d/p0rt

# Zsh
p0rt completion zsh > ~/.zsh/completions/_p0rt

# Fish
p0rt completion fish > ~/.config/fish/completions/p0rt.fish
```

## 💡 **Pro Tips**

1. **Aliases for efficiency**:
   ```bash
   alias pr="p0rt -R http://localhost:80 -k secret r"
   pr list
   pr add test -f SHA256:abc
   ```

2. **Environment variables**:
   ```bash
   export P0RT_API_KEY="secret"
   export CONFIG_FILE="/opt/p0rt/config.yaml"
   ```

3. **Tab completion** (after setup):
   ```bash
   p0rt <TAB>          # Shows commands
   p0rt r <TAB>        # Shows reservation subcommands
   p0rt --<TAB>        # Shows long flags
   ```

4. **Flag precedence**:
   - Flags override positional arguments
   - Short and long forms are equivalent
   - Last flag wins if duplicated

## ❓ **Getting Help**

```bash
p0rt --help                         # General help
p0rt COMMAND --help                 # Command help
p0rt COMMAND SUBCOMMAND --help      # Subcommand help

# Examples
p0rt server --help
p0rt reservation add --help
p0rt completion bash --help
```