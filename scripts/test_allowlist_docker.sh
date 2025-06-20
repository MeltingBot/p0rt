#!/bin/bash

# Docker test script for SSH key allowlist system

set -e

echo "==================================="
echo "P0rt SSH Key Allowlist Docker Test"
echo "==================================="
echo ""

# Create test data directory
mkdir -p test_data

# Build keymanager tool
echo "1. Building keymanager tool..."
go build -o keymanager cmd/keymanager/main.go

# Create test SSH keys
echo -e "\n2. Creating test SSH keys..."
ssh-keygen -t rsa -b 2048 -f test_authorized_key -N "" -C "authorized@test.com" >/dev/null 2>&1
ssh-keygen -t rsa -b 2048 -f test_unauthorized_key -N "" -C "unauthorized@test.com" >/dev/null 2>&1

# Create beta keys file with one authorized key
echo -e "\n3. Creating beta_keys.json with authorized key..."
./keymanager -keys-file test_data/beta_keys.json -action add -key-file test_authorized_key.pub -tier beta -comment "Authorized Test User"

echo -e "\n4. Listing keys in allowlist:"
./keymanager -keys-file test_data/beta_keys.json -action list

# Build Docker image
echo -e "\n5. Building P0rt Docker image..."
docker build -t p0rt:test .

# Start services
echo -e "\n6. Starting Docker services..."
docker-compose -f docker-compose.test.yml up -d p0rt-restricted p0rt-open

# Wait for services to start
echo -e "\n7. Waiting for services to start..."
sleep 5

# Test connections
echo -e "\n8. Testing connections..."

echo -e "\n--- Test 1: Unauthorized key -> Restricted server (should FAIL) ---"
docker run --rm --network p0rt-go_p0rt-test \
  -v $(pwd)/test_unauthorized_key:/root/.ssh/id_rsa:ro \
  alpine:latest sh -c "
    apk add --no-cache openssh-client >/dev/null 2>&1 &&
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        -R 443:localhost:8000 p0rt-restricted -p 2222 echo 'Connected!' || echo '❌ Connection rejected (expected)'
  "

echo -e "\n--- Test 2: Authorized key -> Restricted server (should SUCCEED) ---"
docker run --rm --network p0rt-go_p0rt-test \
  -v $(pwd)/test_authorized_key:/root/.ssh/id_rsa:ro \
  alpine:latest sh -c "
    apk add --no-cache openssh-client >/dev/null 2>&1 &&
    timeout 5 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -R 443:localhost:8000 p0rt-restricted -p 2222 sh -c 'echo \"✅ Connection accepted!\"; sleep 2' || echo '❌ Connection failed'
  "

echo -e "\n--- Test 3: Any key -> Open server (should SUCCEED) ---"
docker run --rm --network p0rt-go_p0rt-test \
  -v $(pwd)/test_unauthorized_key:/root/.ssh/id_rsa:ro \
  alpine:latest sh -c "
    apk add --no-cache openssh-client >/dev/null 2>&1 &&
    timeout 5 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -R 443:localhost:8000 p0rt-open -p 2223 sh -c 'echo \"✅ Connection accepted!\"; sleep 2' || echo '❌ Connection failed'
  "

# Check web pages
echo -e "\n9. Checking web pages for access mode display..."

echo -e "\n--- Restricted server (http://localhost:8080) ---"
curl -s http://localhost:8080 | grep -o "Beta Access\|Open Access" | head -1 || echo "Failed to fetch page"

echo -e "\n--- Open server (http://localhost:8081) ---"
curl -s http://localhost:8081 | grep -o "Beta Access\|Open Access" | head -1 || echo "Failed to fetch page"

# Check API endpoints
echo -e "\n10. Checking API endpoints..."

echo -e "\n--- Restricted server stats ---"
curl -s http://localhost:8080/api/v1/stats | jq '.global_stats.access_mode' 2>/dev/null || echo "No access mode in stats"

echo -e "\n--- Open server stats ---"
curl -s http://localhost:8081/api/v1/stats | jq '.global_stats.access_mode' 2>/dev/null || echo "No access mode in stats"

# Cleanup
echo -e "\n11. Cleaning up..."
docker-compose -f docker-compose.test.yml down
rm -f test_authorized_key* test_unauthorized_key* keymanager
rm -rf test_data

echo -e "\n✨ Test completed!"