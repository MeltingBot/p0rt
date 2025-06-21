#!/bin/bash

# Script Docker SIMPLE pour P0rt

# Arrêter et nettoyer les anciens conteneurs
docker stop p0rt 2>/dev/null
docker rm p0rt 2>/dev/null

# Construire l'image
echo "🔨 Building P0rt..."
docker build -t p0rt .

# Créer les fichiers nécessaires s'ils n'existent pas
[ ! -f ssh_host_key ] && touch ssh_host_key
[ ! -f authorized_keys.json ] && echo "[]" > authorized_keys.json

# Lancer P0rt
echo "🚀 Starting P0rt..."
docker run -d \
  --name p0rt \
  -p 2222:2222 \
  -p 8080:80 \
  -v $(pwd)/ssh_host_key:/app/ssh_host_key \
  -v $(pwd)/authorized_keys.json:/app/authorized_keys.json \
  -e P0RT_OPEN_ACCESS=false \
  p0rt

echo "✅ P0rt is running!"
echo ""
echo "📌 Quick commands:"
echo "  Add key:    docker exec p0rt ./p0rt -key add --key-fingerprint SHA256:xxx... --tier beta"
echo "  List keys:  docker exec p0rt ./p0rt -key list"
echo "  CLI:        docker exec -it p0rt ./p0rt -cli"
echo "  Logs:       docker logs -f p0rt"
echo "  Stop:       docker stop p0rt"
echo ""
echo "🔌 Connect with: ssh -p 2222 -R 443:localhost:8080 localhost"