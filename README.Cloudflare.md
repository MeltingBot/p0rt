# ☁️ P0rt avec Cloudflare

Guide de déploiement de p0rt optimisé pour Cloudflare.

## 🎯 Pourquoi cette configuration ?

Avec Cloudflare, vous bénéficiez déjà de :
- ✅ **SSL/TLS automatique** - Certificats gratuits
- ✅ **Protection DDoS** - Incluse dans le plan gratuit
- ✅ **CDN global** - Cache et accélération
- ✅ **Analytics** - Statistiques de trafic
- ✅ **Firewall** - Protection contre les attaques

**Nginx n'est donc pas nécessaire !**

## 🚀 Déploiement

### 1. Configuration DNS Cloudflare

```bash
# Enregistrements DNS requis
A    your-domain.com    → VOTRE_IP_SERVEUR
A    ssh.your-domain.com → VOTRE_IP_SERVEUR  # Optionnel pour SSH custom
```

### 2. Configuration Cloudflare

Dans le dashboard Cloudflare :

#### SSL/TLS
- **Mode SSL** : `Full` ou `Full (strict)`
- **Always Use HTTPS** : `Activé`
- **HSTS** : `Activé` (optionnel)

#### Speed
- **Auto Minify** : `Activé` pour CSS/JS/HTML
- **Brotli** : `Activé`

#### Security
- **Security Level** : `Medium` ou `High`
- **Bot Fight Mode** : `Activé`

### 3. Déploiement serveur

```bash
# Configuration
cp .env.example .env
# Modifier .env avec votre domaine

# Déploiement Cloudflare
./scripts/deploy.sh cloudflare
```

## 🔧 Configuration optimale

### Variables d'environnement (.env)
```bash
# Domaine principal
P0RT_DOMAIN=your-domain.com

# API Key pour stats/management
P0RT_API_KEY=your-secure-api-key

# Redis pour la production
REDIS_PASSWORD=secure-redis-password
```

### Configuration Cloudflare avancée

#### Page Rules (optionnel)
```
your-domain.com/api/*
- Cache Level: Bypass
- Security Level: High

your-domain.com/health
- Cache Level: Bypass
```

#### Rate Limiting
```
your-domain.com/api/*
- 100 requests per 10 minutes per IP
```

#### Firewall Rules
```
# Bloquer l'accès à l'API depuis certains pays
(http.request.uri.path contains "/api/" and ip.geoip.country in {"CN" "RU"})
→ Block
```

## 📊 Monitoring avec Cloudflare

### Analytics disponibles
- **Trafic HTTP** - Via Cloudflare Analytics
- **Sécurité** - Via p0rt security stats
- **Performance** - Core Web Vitals dans Cloudflare

### Commandes de monitoring
```bash
# Stats de sécurité p0rt
docker-compose exec p0rt ./p0rt security stats

# Analytics Cloudflare
# Via dashboard ou API Cloudflare
```

## 🔒 Sécurité renforcée

### Configuration recommandée

#### Cloudflare Access (optionnel)
Pour protéger l'API management :
```bash
# Protéger /api/ avec Cloudflare Access
Policy: Allow emails in your-domain.com
```

#### Firewall p0rt + Cloudflare
```bash
# P0rt gère les bans SSH automatiquement
# Cloudflare gère les attaques HTTP/DDoS

# Vous pouvez synchroniser les IP bannies :
# 1. Exporter depuis p0rt : ./p0rt security bans
# 2. Importer dans Cloudflare Firewall (manuel ou API)
```

## 🚦 Ports et routage

```
Internet → Cloudflare → Votre serveur

HTTP/HTTPS (80/443):
  - Cloudflare gère SSL
  - Route vers votre port 80
  - Cache et protection DDoS

SSH (22):
  - Accès direct au serveur
  - Pas de proxy Cloudflare
  - Protection p0rt native
```

## 🛠️ Dépannage

### Vérifications

1. **DNS propagation**
```bash
dig your-domain.com
nslookup your-domain.com
```

2. **SSL Cloudflare**
```bash
curl -I https://your-domain.com
# Doit retourner CF headers
```

3. **API accessible**
```bash
curl https://your-domain.com/api/v1/status
```

4. **SSH accessible**
```bash
ssh -R 443:localhost:8080 your-domain.com
```

### Problèmes courants

**❌ SSL Error "ERR_SSL_VERSION_OR_CIPHER_MISMATCH"**
- Solution : Changer mode SSL vers "Full" dans Cloudflare

**❌ "Too many redirects"**
- Solution : Désactiver "Always Use HTTPS" temporairement

**❌ SSH connection refused**
- Vérifier que le port 22 n'est pas proxifié par Cloudflare
- Le SSH doit être en "DNS only" (gris) dans Cloudflare

## 📈 Avantages de cette configuration

### Performance
- **CDN global** - Contenu servi depuis 200+ datacenters
- **Compression automatique** - Brotli/Gzip
- **HTTP/2 & HTTP/3** - Protocoles modernes

### Sécurité
- **Protection DDoS** - Jusqu'à plusieurs Tbps
- **Web Application Firewall** - Règles automatiques
- **Rate limiting** - Contrôle du trafic
- **Bot protection** - Détection automatique

### Coûts
- **Plan gratuit suffisant** - Pour la plupart des usages
- **Pas de serveur proxy** - Économie de ressources
- **Certificats SSL gratuits** - Renouvellement automatique

## 🔄 Migration depuis Nginx

Si vous aviez déjà Nginx :

```bash
# Arrêter Nginx
docker-compose --profile ssl down

# Redéployer sans Nginx
./scripts/deploy.sh cloudflare

# Pointer Cloudflare vers le port 80 directement
```

Cette configuration vous donne tous les avantages de Cloudflare sans la complexité d'un reverse proxy local ! 🎉