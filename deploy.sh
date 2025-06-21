#!/bin/bash

# Script de déploiement SIMPLE pour P0rt en PRODUCTION

set -e

echo "🚀 P0rt Production Deployment"
echo "============================"

# Créer les fichiers s'ils n'existent pas
if [ ! -f ssh_host_key ]; then
    echo "📝 Creating ssh_host_key..."
    touch ssh_host_key
    chmod 600 ssh_host_key
fi

if [ ! -f authorized_keys.json ]; then
    echo "📝 Creating authorized_keys.json..."
    echo "[]" > authorized_keys.json
fi

# Créer le dossier data
mkdir -p data

# Arrêter les anciens conteneurs
echo "🛑 Stopping old containers..."
docker-compose -f docker-compose-simple.yml down 2>/dev/null || true

# Construire et démarrer
echo "🔨 Building and starting..."
docker-compose -f docker-compose-simple.yml up -d --build

# Attendre que tout démarre
echo "⏳ Waiting for services..."
sleep 5

# Vérifier le statut
if docker ps | grep -q "p0rt"; then
    echo ""
    echo "✅ P0rt is running in PRODUCTION!"
    echo ""
    echo "📊 Status:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    echo "🔑 Add your SSH keys:"
    echo "  docker exec p0rt ./p0rt -key add --key-fingerprint SHA256:YOUR_KEY_HERE --tier beta"
    echo ""
    echo "📝 View logs:"
    echo "  docker logs -f p0rt"
    echo ""
    echo "🌐 Connect:"
    echo "  ssh -R 443:localhost:8080 your-server.com"
else
    echo "❌ Failed to start P0rt"
    exit 1
fi