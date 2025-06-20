#!/bin/bash

# P0rt Server Startup Script
# This script demonstrates different ways to start the P0rt server

set -e

# Build the server if not already built
if [ ! -f "./p0rt" ]; then
    echo "Building P0rt server..."
    go build -o p0rt cmd/server/main.go
fi

echo "P0rt Server Startup Options:"
echo "============================"
echo ""
echo "1. Beta/Restricted Mode (default)"
echo "   Only pre-registered SSH keys can create tunnels"
echo ""
echo "2. Open Access Mode"
echo "   Any SSH key can create tunnels"
echo ""
echo "3. Custom authorized keys file"
echo "   Use a specific file for authorized keys"
echo ""

read -p "Select mode (1/2/3): " mode

case $mode in
    1)
        echo "Starting P0rt in RESTRICTED mode..."
        echo "Only keys in authorized_keys.json can connect."
        ./p0rt -server start
        ;;
    2)
        echo "Starting P0rt in OPEN ACCESS mode..."
        echo "Any SSH key can create tunnels."
        P0RT_OPEN_ACCESS=true ./p0rt -server start
        ;;
    3)
        read -p "Enter path to authorized keys file: " keyfile
        echo "Starting P0rt with custom key file: $keyfile"
        P0RT_AUTHORIZED_KEYS="$keyfile" ./p0rt -server start
        ;;
    *)
        echo "Invalid selection"
        exit 1
        ;;
esac