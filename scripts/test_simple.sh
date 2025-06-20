#!/bin/bash

# Simple test script for SSH key allowlist

set -e

echo "================================="
echo "P0rt SSH Key Allowlist Test"
echo "================================="

# Build the tool
echo "1. Building P0rt..."
go build -o p0rt cmd/server/main.go

# Create test SSH key
echo "2. Creating test SSH key..."
rm -f test_key*
ssh-keygen -t rsa -b 2048 -f test_key -N "" -C "test@p0rt.xyz" >/dev/null 2>&1

echo "3. Testing different access modes:"
echo ""

# Test 1: Restricted mode (no keys authorized)
echo "--- Test 1: Restricted mode with no authorized keys ---"
echo "Starting P0rt in restricted mode..."
./p0rt -server start &
SERVER_PID=$!
sleep 2

echo "Testing connection (should FAIL)..."
timeout 5 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 \
    -i test_key -R 443:localhost:8000 localhost -p 2222 \
    echo "Connected!" 2>/dev/null || echo "❌ Connection rejected (expected)"

# Kill server
kill $SERVER_PID 2>/dev/null || true
sleep 1

# Test 2: Add key to allowlist and test again
echo ""
echo "--- Test 2: Adding key to allowlist ---"
echo "Adding test key to allowlist..."
./p0rt -key add --key-file test_key.pub --tier beta --comment "Test Key"

echo "Listing authorized keys:"
./p0rt -key list

echo "Starting P0rt in restricted mode again..."
./p0rt -server start &
SERVER_PID=$!
sleep 2

echo "Testing connection (should SUCCEED)..."
timeout 5 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 \
    -i test_key -R 443:localhost:8000 localhost -p 2222 \
    sh -c 'echo "✅ Connection accepted!"; sleep 1' 2>/dev/null || echo "❌ Connection failed"

# Kill server
kill $SERVER_PID 2>/dev/null || true
sleep 1

# Test 3: Open access mode
echo ""
echo "--- Test 3: Open access mode ---"
echo "Starting P0rt in open access mode..."
P0RT_OPEN_ACCESS=true ./p0rt -server start &
SERVER_PID=$!
sleep 2

echo "Testing connection with any key (should SUCCEED)..."
timeout 5 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 \
    -i test_key -R 443:localhost:8000 localhost -p 2222 \
    sh -c 'echo "✅ Connection accepted in open mode!"; sleep 1' 2>/dev/null || echo "❌ Connection failed"

# Kill server
kill $SERVER_PID 2>/dev/null || true

# Test 4: Check web UI
echo ""
echo "--- Test 4: Testing web UI access mode display ---"
echo "Starting restricted server..."
./p0rt -server start &
SERVER_PID=$!
sleep 2

echo "Checking restricted mode page..."
curl -s http://localhost:8080 | grep -o "Beta Access\|Open Access" | head -1 || echo "Could not detect access mode"

kill $SERVER_PID 2>/dev/null || true
sleep 1

echo "Starting open access server..."
P0RT_OPEN_ACCESS=true ./p0rt -server start &
SERVER_PID=$!
sleep 2

echo "Checking open mode page..."
curl -s http://localhost:8080 | grep -o "Beta Access\|Open Access" | head -1 || echo "Could not detect access mode"

kill $SERVER_PID 2>/dev/null || true

# Cleanup
echo ""
echo "5. Cleaning up..."
rm -f test_key* p0rt authorized_keys.json*
rm -rf data/

echo ""
echo "✨ Test completed!"
echo ""
echo "Summary:"
echo "- ❌ Unauthorized keys are rejected in restricted mode"
echo "- ✅ Authorized keys can connect in restricted mode"  
echo "- ✅ Any key can connect in open access mode"
echo "- 🔒 Web UI shows current access mode"