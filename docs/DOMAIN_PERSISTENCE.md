# Domain Persistence in P0rt

P0rt maintains persistent mappings between SSH keys and generated domain names, ensuring users always get the same domain for their SSH key.

## How It Works

When a user connects with an SSH key:
1. P0rt calculates a SHA256 hash of the SSH key
2. Checks if a domain is already assigned to that key hash
3. If found, returns the existing domain and updates "last seen"
4. If not found, generates a new three-word domain and stores the mapping

## Storage

Domain mappings are stored in `./data/domains.json`:

```json
{
  "abc123...": {
    "domain": "whale-guitar-fox",
    "ssh_key_hash": "abc123...",
    "first_seen": "2023-12-01T10:00:00Z",
    "last_seen": "2023-12-15T14:30:00Z",
    "use_count": 42
  }
}
```

### Fields

- **domain**: The three-word domain assigned (without .p0rt.xyz)
- **ssh_key_hash**: SHA256 hash of the SSH public key (full)
- **first_seen**: When this mapping was first created
- **last_seen**: Last time this SSH key connected
- **use_count**: Number of times this key has connected

## Collision Handling

While extremely rare with 304+ million possible combinations, domain collisions are handled:

1. Generate domain from SSH key hash
2. Check if domain is already taken by another key
3. If taken, add salt to hash and regenerate
4. Repeat up to 10 attempts
5. Fallback to random domain if all attempts fail

## Persistence Features

### Automatic Saving
- Changes are saved immediately when mappings are created/updated
- Periodic saves every 5 minutes as backup
- Atomic writes using temporary files to prevent corruption

### Statistics Tracking
- Total number of domains
- Active domains (last 24h, last 7d)
- Storage file location

Access via: `curl http://localhost/domain-stats` (localhost only)

## Cleanup

Old domain mappings can be cleaned up to save space:

### Manual Cleanup
```bash
./scripts/cleanup-domains.sh
```

### Automatic Cleanup (Programmatic)
Domains unused for 90+ days are automatically cleaned:
```go
// Remove domains not used in 90 days
removed := domainGen.CleanupOldDomains(90 * 24 * time.Hour)
```

### Cleanup Script Options
```bash
# Custom data directory
DATA_DIR=/path/to/data ./scripts/cleanup-domains.sh

# Custom max age (days)
MAX_AGE_DAYS=30 ./scripts/cleanup-domains.sh
```

## Security Considerations

### What's Stored
- SSH key **hash** (SHA256) - not the actual private key
- Domain names (public information)
- Timestamps (for cleanup purposes)

### What's NOT Stored
- SSH private keys
- SSH public key content
- User identification
- Connection logs or history

### File Permissions
The `data/` directory should have restricted permissions:
```bash
chmod 700 data/
chmod 600 data/domains.json
```

## Backup and Recovery

### Creating Backups
```bash
# Manual backup
cp data/domains.json data/domains.backup.$(date +%Y%m%d)

# Automated backup (cron)
0 2 * * * cd /path/to/p0rt && cp data/domains.json data/domains.backup.$(date +\%Y\%m\%d)
```

### Recovery
```bash
# Restore from backup
cp data/domains.backup.20231201 data/domains.json
```

### Migration
To move P0rt to a new server:
```bash
# On old server
tar czf p0rt-data.tar.gz data/

# On new server
tar xzf p0rt-data.tar.gz
```

## Monitoring

### Check Storage Size
```bash
ls -lh data/domains.json
```

### View Statistics
```bash
# JSON stats
curl -s http://localhost/domain-stats | jq .

# Domain count
jq '. | length' data/domains.json

# Recent activity
jq '[.[] | select(.last_seen > "'$(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%S)'")]' data/domains.json
```

## Configuration

Domain persistence is automatic and requires no configuration. The system:
- Creates `./data/` directory on first run
- Uses JSON for human-readable storage
- Handles file locking and atomic writes
- Recovers gracefully from corruption

## Performance

- **Lookup**: O(1) hash table lookup
- **Storage**: Approximately 150 bytes per domain mapping
- **Memory**: Full dataset loaded in memory for fast access
- **Disk**: Periodic saves, immediate saves for new mappings

### Estimated Storage Usage
- 1,000 domains: ~150 KB
- 10,000 domains: ~1.5 MB  
- 100,000 domains: ~15 MB

## Troubleshooting

### Missing Data Directory
```
Error: failed to create data directory: permission denied
```
**Solution**: Ensure write permissions for the P0rt process

### Corrupted domains.json
```
Error: failed to load domain store: invalid character...
```
**Solution**: Restore from backup or delete file (loses mappings)

### Permission Denied
```
Error: failed to write temp file: permission denied
```
**Solution**: Check file permissions on `data/` directory

### Large File Size
If `domains.json` becomes large, run cleanup:
```bash
./scripts/cleanup-domains.sh
```

## Future Enhancements

Potential improvements for domain persistence:
- Database storage (SQLite/PostgreSQL) for larger deployments
- Distributed storage for multi-server setups
- Domain expiration policies
- User-requested domain releases
- Export/import functionality