# 🐳 P0rt Docker Deployment Guide

Ce guide explique comment déployer p0rt avec Docker et Docker Compose.

## 📋 Prérequis

- Docker 20.10+ (avec plugin Compose V2 intégré)
- Ports 22 et 80 disponibles (production)

> **Note:** `docker compose` (sans tiret) est maintenant intégré dans Docker CLI

## 🚀 Déploiement Rapide

### 1. Préparation

```bash
# Cloner le projet
git clone <repo-url>
cd p0rt-go

# Copier la configuration d'environnement
cp .env.example .env

# Modifier .env avec vos paramètres
nano .env
```

### 2. Développement Local

```bash
# Démarrage en mode développement (ports 2222, 8080)
./scripts/deploy.sh development

# Ou manuellement
docker compose up --build -d
```

**Services disponibles:**
- SSH: `localhost:2222`
- HTTP: `http://localhost:8080`
- Redis: `localhost:6380`

### 3. Production

```bash
# Générer la clé SSH de production
ssh-keygen -t rsa -b 4096 -f ssh_host_key.prod -N ""

# Démarrage en production (ports 22, 80)
./scripts/deploy.sh production

# Ou manuellement
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

**Services de production:**
- SSH: `port 22`
- HTTP: `port 80`
- API: `http://localhost/api/v1/status`

## 🔧 Configuration

### Variables d'environnement (.env)

```bash
# API Key pour l'authentification
P0RT_API_KEY=your-secret-api-key

# Mode verbose
P0RT_VERBOSE=false

# Configuration Redis
REDIS_PASSWORD=secure-redis-password

# Domaine principal
P0RT_DOMAIN=yourdomain.com
```

### Fichiers de configuration

- `config.yaml` - Configuration de développement
- `config.prod.yaml` - Configuration de production
- `ssh_host_key` - Clé SSH pour le développement
- `ssh_host_key.prod` - Clé SSH pour la production

## ☁️ Déploiement avec Cloudflare (Recommandé)

### Configuration optimale avec Cloudflare

Cloudflare gère déjà SSL, DDoS protection, et CDN - pas besoin de Nginx !

```bash
# Déploiement optimisé Cloudflare
./scripts/deploy.sh cloudflare
```

**Avantages :**
- ✅ SSL automatique et gratuit
- ✅ Protection DDoS incluse  
- ✅ CDN global (200+ datacenters)
- ✅ Web Application Firewall
- ✅ Analytics intégrées

**Configuration Cloudflare requise :**
1. Mode SSL : `Full` ou `Full (strict)`
2. Always Use HTTPS : `Activé`
3. Pointer DNS vers votre IP serveur

Voir `README.Cloudflare.md` pour les détails complets.

## 📊 Gestion et Monitoring

### Commandes utiles

```bash
# État des services
./scripts/deploy.sh status

# Logs en temps réel
docker compose logs -f

# Logs d'un service spécifique
docker compose logs -f p0rt

# Accès au CLI interactif
docker compose exec p0rt ./p0rt cli

# Statistiques de sécurité
docker compose exec p0rt ./p0rt security stats

# Arrêt des services
./scripts/deploy.sh stop

# Nettoyage complet
./scripts/deploy.sh clean
```

### Monitoring des performances

```bash
# Statistiques des conteneurs
docker stats

# Utilisation des volumes
docker system df

# Health checks
docker compose ps
curl http://localhost/health
```

## 🔧 Configuration Avancée

### Utilisation avec Redis

```yaml
# config.prod.yaml
storage:
  type: "redis"
  redis_url: "redis://redis:6379"
  redis_password: "${REDIS_PASSWORD}"
  redis_db: 0
```

### Limites de ressources

```yaml
# docker-compose.prod.yml
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '1.0'
    reservations:
      memory: 256M
      cpus: '0.5'
```

### Configuration réseau

```yaml
networks:
  p0rt-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

## 🚨 Sécurité

### Bonnes pratiques

1. **API Key**: Toujours définir une API key forte
2. **Certificats**: Utiliser des certificats valides en production
3. **Firewall**: Configurer iptables/ufw appropriément
4. **Updates**: Maintenir les images à jour
5. **Logs**: Surveiller les logs de sécurité

### Configuration du firewall

```bash
# Permettre SSH et HTTP
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# Bloquer l'accès direct à Redis
ufw deny 6379/tcp
```

## 🔍 Dépannage

### Problèmes courants

1. **Port 22 occupé**
   ```bash
   # Utiliser le mode développement (port 2222)
   ./scripts/deploy.sh development
   ```

2. **Permissions SSH key**
   ```bash
   chmod 600 ssh_host_key*
   ```

3. **Redis connection failed**
   ```bash
   # Vérifier que Redis est démarré
   docker compose logs redis
   ```

4. **Certificats SSL invalides**
   ```bash
   # Vérifier les certificats
   openssl x509 -in ssl/cert.pem -text -noout
   ```

### Logs de débogage

```bash
# Mode verbose
P0RT_VERBOSE=true docker compose up

# Logs détaillés d'un service
docker compose logs --details p0rt

# Suivi en temps réel
docker compose logs -f --tail=100
```

## 📈 Mise à jour

```bash
# Mise à jour du code
git pull

# Reconstruction et redémarrage
docker compose up --build -d

# Avec sauvegarde des données
docker compose down
docker compose up --build -d
```

## 💾 Sauvegarde

```bash
# Sauvegarde des données
docker run --rm -v p0rt_data:/data -v $(pwd):/backup alpine \
  tar czf /backup/p0rt-backup-$(date +%Y%m%d).tar.gz /data

# Sauvegarde Redis
docker compose exec redis redis-cli --rdb /data/dump-backup.rdb
```

## 🔄 Migration

### Depuis une installation locale

```bash
# Copier les données existantes
cp -r ./data/* ./docker-data/

# Copier la configuration
cp config.yaml config.docker.yaml

# Adapter les chemins dans la configuration
```

Cela fournit un système Docker complet pour p0rt avec tous les modes de déploiement nécessaires!