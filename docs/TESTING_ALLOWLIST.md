# Testing SSH Key Allowlist with Docker

This guide shows how to test the SSH key allowlist system using Docker.

## Quick Test

Run the automated test script:

```bash
./scripts/test_allowlist_docker.sh
```

This script will:
1. Build the keymanager tool
2. Create test SSH keys (authorized and unauthorized)
3. Build the P0rt Docker image
4. Start two P0rt servers:
   - One in **restricted mode** (port 2222/8080) - only allows pre-registered keys
   - One in **open mode** (port 2223/8081) - allows any SSH key
5. Test connections with different keys
6. Verify the web UI shows the correct access mode

## Manual Testing

### 1. Start the servers

```bash
# Build the image
docker build -t p0rt:test .

# Start restricted server
docker run -d --name p0rt-restricted \
  -p 2222:2222 -p 8080:80 \
  -e P0RT_OPEN_ACCESS=false \
  -e SSH_SERVER_PORT=2222 \
  -e HTTP_PORT=80 \
  -v $(pwd)/authorized_keys.json:/data/authorized_keys.json \
  p0rt:test

# Start open server
docker run -d --name p0rt-open \
  -p 2223:2222 -p 8081:80 \
  -e P0RT_OPEN_ACCESS=true \
  -e SSH_SERVER_PORT=2222 \
  -e HTTP_PORT=80 \
  p0rt:test
```

### 2. Add authorized keys

```bash
# Build keymanager
go build -o keymanager cmd/keymanager/main.go

# Add your SSH key
./keymanager -action add -key-file ~/.ssh/id_rsa.pub -tier beta -comment "My key"

# List keys
./keymanager -action list
```

### 3. Test connections

```bash
# Test restricted server (will fail if key not authorized)
ssh -R 443:localhost:3000 localhost -p 2222

# Test open server (will always work)
ssh -R 443:localhost:3000 localhost -p 2223
```

### 4. Check web UI

- Restricted server: http://localhost:8080 (shows "🔒 Beta Access")
- Open server: http://localhost:8081 (shows "✨ Open Access")

### 5. Check API

```bash
# Restricted server
curl http://localhost:8080/api/v1/stats | jq '.global_stats.access_mode'
# Output: "restricted"

# Open server
curl http://localhost:8081/api/v1/stats | jq '.global_stats.access_mode'
# Output: "open"
```

## Docker Compose Test

Use the provided `docker-compose.test.yml` for automated testing:

```bash
# Start all test services
docker-compose -f docker-compose.test.yml up

# Watch the logs
docker-compose -f docker-compose.test.yml logs -f

# Cleanup
docker-compose -f docker-compose.test.yml down
```

## Expected Results

### Restricted Mode
- ❌ Unauthorized SSH keys are rejected with "Permission denied (publickey)"
- ✅ Authorized SSH keys can connect and create tunnels
- 🔒 Web UI shows "Beta Access" badge
- API returns `access_mode: "restricted"`

### Open Mode
- ✅ Any SSH key can connect and create tunnels
- ✨ Web UI shows "Open Access" badge
- API returns `access_mode: "open"`

## Troubleshooting

### Key not authorized
```bash
# Check if your key is in the allowlist
./keymanager -action list

# Add your key if missing
./keymanager -action add -key-file ~/.ssh/id_rsa.pub -tier beta
```

### Container can't find authorized_keys.json
```bash
# Create the file if it doesn't exist
touch authorized_keys.json

# Or specify a different path
docker run -e P0RT_AUTHORIZED_KEYS=/custom/path/keys.json ...
```

### Debug mode
```bash
# Enable verbose logging
docker run -e P0RT_VERBOSE=true ...