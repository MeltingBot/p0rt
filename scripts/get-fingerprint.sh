#!/bin/bash

# Script to get SSH key fingerprint for P0rt custom domain setup

echo "🔑 P0rt Custom Domain Setup - SSH Key Fingerprint"
echo "================================================"
echo ""

# Find SSH public key
KEY_FILE=""
if [ -f ~/.ssh/id_rsa.pub ]; then
    KEY_FILE=~/.ssh/id_rsa.pub
elif [ -f ~/.ssh/id_ed25519.pub ]; then
    KEY_FILE=~/.ssh/id_ed25519.pub
elif [ -f ~/.ssh/id_ecdsa.pub ]; then
    KEY_FILE=~/.ssh/id_ecdsa.pub
else
    echo "❌ No SSH public key found!"
    echo "   Please generate one with: ssh-keygen"
    exit 1
fi

echo "Found SSH key: $KEY_FILE"
echo ""

# Get fingerprint
FINGERPRINT=$(ssh-keygen -lf "$KEY_FILE" | awk '{print $2}' | sed 's/SHA256://')

if [ -z "$FINGERPRINT" ]; then
    echo "❌ Failed to get fingerprint"
    exit 1
fi

echo "Your SSH key fingerprint (SHA256):"
echo "  $FINGERPRINT"
echo ""
echo "📋 DNS Configuration for your custom domain:"
echo ""
echo "1. CNAME Record:"
echo "   Host: yourdomain.com (or subdomain.yourdomain.com)"
echo "   Target: p0rt.xyz"
echo ""
echo "2. TXT Record:"
echo "   Host: _p0rt-authkey.yourdomain.com"
echo "   Value: p0rt-authkey=$FINGERPRINT"
echo ""
echo "3. Wait for DNS propagation (5-30 minutes)"
echo ""
echo "4. Connect with:"
echo "   ssh -R 443:localhost:3000 ssh.p0rt.xyz -o \"SetEnv LC_CUSTOM_DOMAIN=yourdomain.com\""
echo ""
echo "✨ Your service will be available at: https://yourdomain.com"