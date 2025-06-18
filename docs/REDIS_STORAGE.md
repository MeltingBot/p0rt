# Redis Storage for P0rt Domain Persistence

P0rt now supports Redis as an alternative to JSON file storage for domain persistence. This provides better performance and scalability for high-traffic deployments.

## Configuration

### Environment Variables

```bash
# Use Redis storage
STORAGE_TYPE=redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=yourpassword
REDIS_DB=0
```

### YAML Configuration

```yaml
storage:
  type: "redis"
  redis_url: "redis://localhost:6379"
  redis_password: "yourpassword"
  redis_db: 0
```

### Redis URL Formats

```bash
# Local Redis (default)
REDIS_URL=redis://localhost:6379

# Redis with password
REDIS_URL=redis://:password@localhost:6379

# Redis with custom database
REDIS_URL=redis://localhost:6379/1

# Redis Sentinel
REDIS_URL=redis-sentinel://localhost:26379/mymaster

# Redis Cluster
REDIS_URL=redis://node1:6379,node2:6379,node3:6379
```

## Running P0rt with Redis

### Prerequisites

1. Install and start Redis:
```bash
# Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis

# macOS
brew install redis
brew services start redis

# Docker
docker run -d -p 6379:6379 redis:alpine
```

2. Test Redis connection:
```bash
redis-cli ping
# Should return: PONG
```

### Start P0rt

```bash
# With environment variables
STORAGE_TYPE=redis REDIS_URL=redis://localhost:6379 ./p0rt

# With config file
./p0rt --config config.yaml
```

## Data Structure

Redis stores domain mappings using the following structure:

### Keys

```
p0rt:domain:{ssh_key_hash}          - Main domain record (hash)
p0rt:domain:reverse:{domain_name}   - Reverse lookup (string)
```

### Domain Record Fields

```json
{
  "domain": "whale-guitar-fox",
  "ssh_key_hash": "abc123...",
  "first_seen": 1640995200,
  "last_seen": 1641081600,
  "use_count": 42
}
```

## Redis vs JSON Comparison

| Feature | JSON Storage | Redis Storage |
|---------|-------------|---------------|
| **Performance** | O(1) memory lookup | O(1) Redis lookup |
| **Persistence** | File-based | Memory + AOF/RDB |
| **Scalability** | Single process | Multi-process/server |
| **Memory Usage** | Full dataset in RAM | Configurable eviction |
| **Backup** | Simple file copy | Redis backup tools |
| **Dependencies** | None | Redis server |

## Redis Configuration Recommendations

### Production Settings

```bash
# /etc/redis/redis.conf

# Persistence
save 900 1      # Save after 900 sec if at least 1 key changed
save 300 10     # Save after 300 sec if at least 10 keys changed
save 60 10000   # Save after 60 sec if at least 10000 keys changed

# AOF (Append Only File) for durability
appendonly yes
appendfsync everysec

# Memory management
maxmemory 256mb
maxmemory-policy allkeys-lru

# Security
requirepass your_strong_password
bind 127.0.0.1
```

### High Availability

For production deployments:

```bash
# Redis Sentinel for automatic failover
REDIS_URL=redis-sentinel://sentinel1:26379,sentinel2:26379/mymaster

# Redis Cluster for horizontal scaling
REDIS_URL=redis://node1:6379,node2:6379,node3:6379
```

## Monitoring and Maintenance

### Redis Statistics

```bash
# Domain storage stats
curl -s http://localhost/domain-stats | jq .

# Redis memory usage
redis-cli info memory

# Key count
redis-cli dbsize
```

### Backup and Restore

```bash
# Manual backup
redis-cli bgsave

# Export to JSON (for migration)
redis-cli --json get p0rt:domain:*

# Restore from RDB
cp dump.rdb /var/lib/redis/
sudo systemctl restart redis
```

### Migration from JSON to Redis

```bash
# 1. Start with JSON storage
STORAGE_TYPE=json ./p0rt

# 2. Stop P0rt and export data (if needed)
# Domain data is automatically preserved

# 3. Start Redis
sudo systemctl start redis

# 4. Switch to Redis storage
STORAGE_TYPE=redis REDIS_URL=redis://localhost:6379 ./p0rt
```

## Troubleshooting

### Connection Issues

```bash
# Test Redis connectivity
redis-cli -u redis://localhost:6379 ping

# Check Redis logs
sudo journalctl -u redis

# Verify P0rt can connect
STORAGE_TYPE=redis ./p0rt
```

### Performance Issues

```bash
# Monitor Redis performance
redis-cli --latency-history

# Check slow queries
redis-cli slowlog get 10

# Memory usage
redis-cli memory usage p0rt:domain:*
```

### Data Issues

```bash
# List all P0rt keys
redis-cli keys "p0rt:domain:*"

# Inspect domain record
redis-cli hgetall "p0rt:domain:abc123..."

# Clean up expired domains
redis-cli eval "return redis.call('del', unpack(redis.call('keys', 'p0rt:domain:*')))" 0
```

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `STORAGE_TYPE` | Storage backend ("json" or "redis") | "json" |
| `REDIS_URL` | Redis connection URL | "redis://localhost:6379" |
| `REDIS_PASSWORD` | Redis password | "" |
| `REDIS_DB` | Redis database number | 0 |

## Security Considerations

- Use strong Redis passwords in production
- Bind Redis to localhost only unless clustering
- Enable AUTH and disable dangerous commands
- Use TLS for Redis connections over networks
- Monitor Redis access logs
- Regular backup and disaster recovery testing

Redis storage provides excellent performance and scalability for P0rt domain persistence while maintaining the same API and functionality as JSON storage.