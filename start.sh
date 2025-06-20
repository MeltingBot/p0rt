#!/bin/bash

# P0rt Server Quick Start Script

set -e

# Build if needed
if [ ! -f "./p0rt" ]; then
    echo "Building P0rt..."
    go build -o p0rt cmd/server/main.go
fi

# Check command line argument
case "${1:-}" in
    "open")
        echo "🚀 Starting P0rt in OPEN ACCESS mode"
        echo "   Any SSH key can create tunnels"
        P0RT_OPEN_ACCESS=true ./p0rt -server start
        ;;
    "restricted"|"beta")
        echo "🔒 Starting P0rt in RESTRICTED mode"
        echo "   Only pre-registered SSH keys can create tunnels"
        echo "   Use './p0rt -key add --key-fingerprint SHA256:abc123... --tier beta' to manage keys"
        ./p0rt -server start
        ;;
    "help"|"-h"|"--help")
        echo "P0rt Server Quick Start"
        echo ""
        echo "Usage: $0 [mode]"
        echo ""
        echo "Modes:"
        echo "  open       - Allow any SSH key (P0RT_OPEN_ACCESS=true)"
        echo "  restricted - Only allow pre-registered keys (default)"
        echo "  beta       - Same as restricted"
        echo ""
        echo "Examples:"
        echo "  $0 open       # Start in open mode"
        echo "  $0 restricted # Start in restricted mode"
        echo "  $0            # Start in restricted mode (default)"
        echo ""
        echo "Key Management:"
        echo "  ./p0rt -key add --key-fingerprint SHA256:abc123... --tier beta  # Easiest"
        echo "  ./p0rt -key add --key-file ~/.ssh/id_rsa.pub --tier beta"
        echo "  ./p0rt -key list"
        echo ""
        echo "Environment Variables:"
        echo "  P0RT_OPEN_ACCESS=true      # Allow any SSH key"
        echo "  P0RT_AUTHORIZED_KEYS=file  # Path to authorized keys JSON"
        echo "  SSH_SERVER_PORT=2222       # SSH server port"
        echo "  HTTP_PORT=80               # HTTP server port"
        ;;
    *)
        echo "🔒 Starting P0rt in RESTRICTED mode (default)"
        echo "   Only pre-registered SSH keys can create tunnels"
        echo "   Run '$0 help' for more options"
        echo ""
        ./p0rt -server start
        ;;
esac