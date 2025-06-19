#!/bin/bash

# Script de déploiement Docker pour p0rt
set -e

# Configuration
COMPOSE_FILE="docker-compose.yml"
PROD_COMPOSE_FILE="docker-compose.prod.yml"
ENVIRONMENT=${1:-development}

echo "🚀 Déploiement de p0rt en mode: $ENVIRONMENT"

# Fonctions utilitaires
check_requirements() {
    echo "📋 Vérification des prérequis..."
    
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker n'est pas installé"
        exit 1
    fi
    
    if ! docker compose version &> /dev/null; then
        echo "❌ Docker Compose n'est pas disponible"
        echo "ℹ️  Utilisez Docker Desktop ou installez le plugin docker-compose-plugin"
        exit 1
    fi
    
    echo "✅ Prérequis OK"
}

setup_environment() {
    echo "🔧 Configuration de l'environnement..."
    
    # Créer .env si il n'existe pas
    if [ ! -f .env ]; then
        cp .env.example .env
        echo "📝 Fichier .env créé à partir de .env.example"
        echo "⚠️  Veuillez modifier .env avec vos paramètres avant de continuer"
        read -p "Appuyez sur Entrée pour continuer..."
    fi
    
    # Générer la clé SSH host si elle n'existe pas
    if [ ! -f ssh_host_key ]; then
        echo "🔑 Génération de la clé SSH host..."
        ssh-keygen -t rsa -b 4096 -f ssh_host_key -N "" -C "p0rt-host-key"
        chmod 600 ssh_host_key
        chmod 644 ssh_host_key.pub
    fi
    
    # Créer les répertoires nécessaires
    mkdir -p data/{security,reservations}
    mkdir -p ssl
    
    echo "✅ Environnement configuré"
}

deploy_development() {
    echo "🛠️  Déploiement en mode développement..."
    
    # Construire et démarrer les services
    docker compose up --build -d
    
    echo "📊 État des services:"
    docker compose ps
    
    echo ""
    echo "🌐 Services disponibles:"
    echo "  - SSH: localhost:2222"
    echo "  - HTTP: http://localhost:8080"
    echo "  - Redis: localhost:6380"
    echo ""
    echo "📝 Commandes utiles:"
    echo "  - Logs: docker compose logs -f"
    echo "  - CLI: docker compose exec p0rt ./p0rt cli"
    echo "  - Arrêt: docker compose down"
}

deploy_production() {
    echo "🏭 Déploiement en mode production..."
    
    # Vérifications de production
    if [ ! -f config.prod.yaml ]; then
        echo "❌ config.prod.yaml manquant"
        exit 1
    fi
    
    if [ ! -f ssh_host_key.prod ]; then
        echo "❌ ssh_host_key.prod manquant"
        exit 1
    fi
    
    # Construire et démarrer avec le compose de production
    docker compose -f $COMPOSE_FILE -f $PROD_COMPOSE_FILE up --build -d
    
    echo "📊 État des services:"
    docker compose -f $COMPOSE_FILE -f $PROD_COMPOSE_FILE ps
    
    echo ""
    echo "🌐 Services de production:"
    echo "  - SSH: port 22"
    echo "  - HTTP: port 80"
    echo "  - API: http://localhost/api/v1/status"
    echo ""
    echo "📝 Commandes utiles:"
    echo "  - Logs: docker compose -f $COMPOSE_FILE -f $PROD_COMPOSE_FILE logs -f"
    echo "  - Stats: docker compose -f $COMPOSE_FILE -f $PROD_COMPOSE_FILE exec p0rt ./p0rt stats"
    echo "  - Sécurité: docker compose -f $COMPOSE_FILE -f $PROD_COMPOSE_FILE exec p0rt ./p0rt security stats"
}

deploy_cloudflare() {
    echo "☁️  Déploiement avec Cloudflare..."
    echo "ℹ️  Cloudflare gère SSL et le reverse proxy"
    
    # Utiliser la configuration production
    docker compose -f $COMPOSE_FILE -f $PROD_COMPOSE_FILE up --build -d
    
    echo "🌐 Configuration Cloudflare requise:"
    echo "  1. Pointez votre domaine vers cette IP"
    echo "  2. Configurez Cloudflare en mode 'Full' ou 'Full (strict)'"
    echo "  3. Activez 'Always Use HTTPS'"
    echo ""
    echo "📋 Services exposés:"
    echo "  - SSH: port 22 (accès direct)"
    echo "  - HTTP: port 80 (via Cloudflare)"
    echo "  - API: http://yourdomain.com/api/v1/status"
}

show_status() {
    echo "📊 État actuel des services:"
    docker compose ps
    
    echo ""
    echo "📈 Statistiques des conteneurs:"
    docker stats --no-stream $(docker compose ps -q)
}

# Menu principal
case $ENVIRONMENT in
    "development"|"dev")
        check_requirements
        setup_environment
        deploy_development
        ;;
    "production"|"prod")
        check_requirements
        setup_environment
        deploy_production
        ;;
    "cloudflare"|"cf")
        check_requirements
        setup_environment
        deploy_cloudflare
        ;;
    "status")
        show_status
        ;;
    "stop")
        echo "🛑 Arrêt des services..."
        docker compose down
        ;;
    "clean")
        echo "🧹 Nettoyage complet..."
        docker compose down -v --rmi all
        docker system prune -f
        ;;
    *)
        echo "Usage: $0 {development|production|cloudflare|status|stop|clean}"
        echo ""
        echo "Modes disponibles:"
        echo "  development - Déploiement local (ports 2222, 8080)"
        echo "  production  - Déploiement production (ports 22, 80)"
        echo "  cloudflare  - Déploiement optimisé pour Cloudflare"
        echo "  status      - Afficher l'état des services"
        echo "  stop        - Arrêter tous les services"
        echo "  clean       - Nettoyage complet"
        exit 1
        ;;
esac