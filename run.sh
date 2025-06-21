#!/bin/bash

# P0rt - Script unique pour dev et prod
# Usage: ./run.sh [dev|dev-redis|prod]

set -e

MODE="${1:-dev}"

echo "🚀 P0rt - Mode: $MODE"
echo "===================="

case "$MODE" in
    "dev")
        echo "🔧 Mode développement (JSON)"
        echo "   - SSH: 2222"
        echo "   - HTTP: 8080" 
        echo "   - Accès ouvert (toutes les clés SSH)"
        echo "   - Stockage: Fichiers JSON locaux"
        echo ""
        
        # Build si nécessaire
        if [ ! -f "./p0rt" ] || [ "cmd/server/main.go" -nt "./p0rt" ]; then
            echo "🔨 Construction..."
            go build -o p0rt cmd/server/main.go
        fi
        
        # Lancer en mode dev avec JSON
        P0RT_OPEN_ACCESS=true \
        SSH_SERVER_PORT=2222 \
        HTTP_PORT=8080 \
        ./p0rt -server start
        ;;
        
    "dev-redis")
        echo "🔧 Mode développement (Redis)"
        echo "   - SSH: 2222"
        echo "   - HTTP: 8080" 
        echo "   - Accès ouvert (toutes les clés SSH)"
        echo "   - Stockage: Redis local"
        echo ""
        
        # Vérifier si Redis est disponible
        if ! command -v redis-server &> /dev/null; then
            echo "⚠️  Redis n'est pas installé. Installation recommandée:"
            echo "   Ubuntu/Debian: sudo apt install redis-server"
            echo "   macOS: brew install redis"
            echo ""
            echo "🔄 Démarrage Redis local avec Docker..."
            docker run -d --name p0rt-redis -p 6379:6379 redis:7-alpine 2>/dev/null || \
            (echo "❌ Impossible de démarrer Redis. Utilisez './run.sh dev' pour JSON." && exit 1)
            sleep 2
        else
            # Démarrer Redis local si pas déjà en cours
            if ! pgrep redis-server > /dev/null; then
                echo "🔄 Démarrage Redis local..."
                redis-server --daemonize yes --port 6379 2>/dev/null || true
                sleep 1
            fi
        fi
        
        # Build si nécessaire
        if [ ! -f "./p0rt" ] || [ "cmd/server/main.go" -nt "./p0rt" ]; then
            echo "🔨 Construction..."
            go build -o p0rt cmd/server/main.go
        fi
        
        # Cleanup function for Redis container
        cleanup_redis() {
            echo "🧹 Arrêt Redis..."
            docker stop p0rt-redis 2>/dev/null || true
            docker rm p0rt-redis 2>/dev/null || true
        }
        
        # Set trap for cleanup on exit
        if docker ps | grep -q "p0rt-redis"; then
            trap cleanup_redis EXIT
        fi
        
        echo "✅ Redis disponible sur localhost:6379"
        echo "📊 Tester Redis: redis-cli ping"
        echo ""
        
        # Lancer en mode dev avec Redis
        P0RT_OPEN_ACCESS=true \
        SSH_SERVER_PORT=2222 \
        HTTP_PORT=8080 \
        REDIS_URL="redis://localhost:6379" \
        ./p0rt -server start
        ;;
        
    "prod")
        echo "🏭 Mode production avec Docker"
        echo "   - SSH: 22"
        echo "   - HTTP: 80"
        echo "   - Accès restreint (clés autorisées seulement)"
        echo "   - Stockage: Redis + JSON backup"
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
        
        # Ajuster les permissions pour Docker (uid 1001)
        echo "🔧 Ajustement des permissions..."
        chmod 666 ssh_host_key authorized_keys.json 2>/dev/null || true
        
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
            echo "📊 Vérifier Redis:"
            echo "  docker exec p0rt-redis redis-cli ping"
            echo "  docker exec p0rt-redis redis-cli info"
            echo ""
            echo "📝 Voir les logs:"
            echo "  docker logs -f p0rt"
            echo "  docker logs -f p0rt-redis"
        else
            echo "❌ Échec du démarrage"
            exit 1
        fi
        ;;
        
    *)
        echo "Usage: $0 [dev|dev-redis|prod]"
        echo ""
        echo "dev       - Mode développement avec JSON (ports 2222/8080, accès ouvert)"
        echo "dev-redis - Mode développement avec Redis (ports 2222/8080, accès ouvert)"
        echo "prod      - Mode production avec Docker+Redis (ports 22/80, accès restreint)"
        echo ""
        echo "Examples:"
        echo "  ./run.sh              # Développement simple (JSON)"
        echo "  ./run.sh dev          # Développement simple (JSON)"  
        echo "  ./run.sh dev-redis    # Développement avec Redis"
        echo "  ./run.sh prod         # Production avec Docker+Redis"
        exit 1
        ;;
esac