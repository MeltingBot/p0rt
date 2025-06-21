#!/bin/bash

# Script de démarrage Docker avec données persistantes

set -e

# Export UID/GID pour Docker
export UID=$(id -u)
export GID=$(id -g)

echo "🚀 P0rt Docker Startup"
echo "===================="

# Créer les fichiers s'ils n'existent pas
if [ ! -f "ssh_host_key" ]; then
    echo "📝 Creating ssh_host_key placeholder..."
    touch ssh_host_key
    chmod 600 ssh_host_key
fi

if [ ! -f "authorized_keys.json" ]; then
    echo "📝 Creating empty authorized_keys.json..."
    echo "[]" > authorized_keys.json
fi

if [ ! -f "config.yaml" ]; then
    echo "📝 Creating default config.yaml..."
    cat > config.yaml << 'EOF'
server:
  ssh_port: "22"
  http_port: "80"

domain:
  base: "p0rt.xyz"
  reservations_enabled: true

storage:
  type: "json"
  data_dir: "./data"

security:
  max_failed_attempts: 5
  ban_duration: "30m"
  cleanup_interval: "1h"
EOF
fi

# Vérifier les permissions
echo "🔒 Setting permissions..."
chmod 600 ssh_host_key 2>/dev/null || true
chmod 644 authorized_keys.json config.yaml

# Gestion des clés SSH
echo ""
echo "🔑 SSH Key Management:"
echo "---------------------"

# Afficher les clés autorisées existantes
if [ -s "authorized_keys.json" ] && [ "$(cat authorized_keys.json)" != "[]" ]; then
    echo "✅ Authorized keys found:"
    # Compter le nombre de clés
    KEY_COUNT=$(grep -o '"fingerprint"' authorized_keys.json | wc -l)
    echo "   $KEY_COUNT key(s) configured"
else
    echo "⚠️  No authorized keys configured"
    echo ""
    echo "To add SSH keys:"
    echo "  docker exec p0rt-server ./p0rt -key add --key-fingerprint SHA256:xxx... --tier beta"
    echo "  docker exec -it p0rt-server ./p0rt -cli"
    echo ""
fi

# Choix du mode
echo ""
echo "🔐 Access Mode:"
echo "--------------"
if [ "$P0RT_OPEN_ACCESS" = "true" ]; then
    echo "✨ OPEN ACCESS - Any SSH key can connect"
else
    echo "🔒 RESTRICTED - Only authorized keys can connect"
    echo "   Set P0RT_OPEN_ACCESS=true to enable open access"
fi

# Démarrer avec docker-compose
echo ""
echo "🐳 Starting Docker containers..."
echo "-------------------------------"
docker-compose up -d

# Attendre que le service démarre
echo ""
echo "⏳ Waiting for services to start..."
sleep 3

# Vérifier le statut
if docker-compose ps | grep -q "Up"; then
    echo ""
    echo "✅ P0rt is running!"
    echo ""
    echo "📊 Service Status:"
    docker-compose ps
    
    echo ""
    echo "🌐 Access Points:"
    echo "  SSH:  ssh -R 443:localhost:8080 localhost -p 22"
    echo "  HTTP: http://localhost:80"
    echo ""
    echo "📝 Logs:"
    echo "  docker-compose logs -f p0rt"
    echo ""
    echo "🔧 CLI Access:"
    echo "  docker exec -it p0rt-server ./p0rt -cli"
else
    echo ""
    echo "❌ Failed to start P0rt"
    echo "Check logs: docker-compose logs p0rt"
    exit 1
fi