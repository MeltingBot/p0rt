#!/bin/bash

# Test script for SSH key allowlist system

set -e

echo "Building keymanager tool..."
go build -o keymanager cmd/keymanager/main.go

echo -e "\n1. Testing key management..."

# Create test SSH keys
echo "Creating test SSH keys..."
ssh-keygen -t rsa -b 2048 -f test_key1 -N "" -C "test1@example.com" >/dev/null 2>&1
ssh-keygen -t rsa -b 2048 -f test_key2 -N "" -C "test2@example.com" >/dev/null 2>&1
ssh-keygen -t rsa -b 2048 -f test_key3 -N "" -C "test3@example.com" >/dev/null 2>&1

# Add keys with different tiers
echo "Adding keys to allowlist..."
./keymanager -action add -key-file test_key1.pub -tier beta -comment "Beta Tester 1"
./keymanager -action add -key-file test_key2.pub -tier premium -comment "Premium User"
./keymanager -action add -key-file test_key3.pub -tier free -comment "Free User"

echo -e "\n2. Listing all keys..."
./keymanager -action list

echo -e "\n3. Testing deactivation..."
# Get fingerprint of key 3
FP3=$(ssh-keygen -lf test_key3.pub | awk '{print $2}')
echo "Deactivating key 3 (fingerprint: $FP3)..."
./keymanager -action deactivate -fingerprint "$FP3"

echo -e "\n4. Listing keys after deactivation..."
./keymanager -action list

echo -e "\n5. Testing with expiration..."
# Add a key that expires in 1 minute
EXPIRE_TIME=$(date -u -d "+1 minute" +"%Y-%m-%dT%H:%M:%SZ")
ssh-keygen -t rsa -b 2048 -f test_key4 -N "" -C "temp@example.com" >/dev/null 2>&1
./keymanager -action add -key-file test_key4.pub -tier beta -comment "Temporary Access" -expires "$EXPIRE_TIME"

echo -e "\nKey added with expiration at: $EXPIRE_TIME"

echo -e "\n6. Testing import from authorized_keys file..."
# Create a sample authorized_keys file
cat > test_authorized_keys <<EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTest1... import1@example.com
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTest2... import2@example.com
EOF

./keymanager -action import -import-file test_authorized_keys -tier beta

echo -e "\n7. Final key list..."
./keymanager -action list

echo -e "\n8. Cleaning up test files..."
rm -f test_key* test_authorized_keys keymanager

echo -e "\nTest completed successfully!"
echo -e "\nTo test with the SSH server:"
echo "1. Run server in restricted mode: ./p0rt"
echo "2. Try connecting with an authorized key: ssh -i test_key1 -R 443:localhost:8080 localhost -p 2222"
echo "3. Try connecting with an unauthorized key: ssh -i ~/.ssh/id_rsa -R 443:localhost:8080 localhost -p 2222"
echo -e "\nTo run in open mode (all keys allowed): P0RT_OPEN_ACCESS=true ./p0rt"