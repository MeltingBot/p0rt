#!/bin/bash

# P0rt - Script unique pour dev et prod
# Usage: ./run.sh [dev|prod]

set -e

MODE="${1:-dev}"

echo "🚀 P0rt - Mode: $MODE"
echo "===================="

case "$MODE" in
    "dev")
        echo "🔧 Mode développement"
        echo "   - SSH: 2222"
        echo "   - HTTP: 8080" 
        echo "   - Accès ouvert (toutes les clés SSH)"
        echo ""
        
        # Build si nécessaire
        if [ ! -f "./p0rt" ] || [ "cmd/server/main.go" -nt "./p0rt" ]; then
            echo "🔨 Construction..."
            go build -o p0rt cmd/server/main.go
        fi
        
        # Lancer en mode dev
        P0RT_OPEN_ACCESS=true \
        SSH_SERVER_PORT=2222 \
        HTTP_PORT=8080 \
        ./p0rt -server start
        ;;
        
    "prod")
        echo "🏭 Mode production avec Docker"
        echo "   - SSH: 22"
        echo "   - HTTP: 80"
        echo "   - Accès restreint (clés autorisées seulement)"
        echo ""
        
        # Créer les fichiers nécessaires
        if [ ! -f ssh_host_key ]; then
            echo "📝 Création ssh_host_key..."
            touch ssh_host_key
            chmod 600 ssh_host_key
        fi
        
        if [ ! -f authorized_keys.json ]; then
            echo "📝 Création authorized_keys.json..."
            echo "[]" > authorized_keys.json
        fi
        
        mkdir -p data
        
        # Arrêter les anciens conteneurs
        echo "🛑 Arrêt des anciens conteneurs..."
        docker compose down 2>/dev/null || true
        
        # Construire et démarrer
        echo "🔨 Construction et démarrage..."
        docker compose up -d --build
        
        # Vérifier le statut
        sleep 3
        if docker ps | grep -q "p0rt"; then
            echo ""
            echo "✅ P0rt fonctionne en production!"
            echo ""
            echo "🔑 Ajouter des clés SSH:"
            echo "  docker exec p0rt ./p0rt -key add --key-fingerprint SHA256:VOTRE_CLE --tier beta"
            echo ""
            echo "📝 Voir les logs:"
            echo "  docker logs -f p0rt"
        else
            echo "❌ Échec du démarrage"
            exit 1
        fi
        ;;
        
    *)
        echo "Usage: $0 [dev|prod]"
        echo ""
        echo "dev  - Mode développement (ports 2222/8080, accès ouvert)"
        echo "prod - Mode production avec Docker (ports 22/80, accès restreint)"
        exit 1
        ;;
esac