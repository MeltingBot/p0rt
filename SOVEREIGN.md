# P0rt Sovereign Deployment (Sans Cloudflare)

Cette branche permet de déployer P0rt de manière totalement souveraine et indépendante, sans dépendre de Cloudflare.

## Architecture

```
Internet → Nginx (80/443) → P0rt (8080)
                ↓
         Let's Encrypt SSL
                ↓
           Rate Limiting
                ↓
           DDoS Protection
```

## Fonctionnalités remplacées

| Cloudflare | Solution Nginx |
|------------|----------------|
| SSL/TLS | Let's Encrypt avec Certbot |
| DDoS Protection | Rate limiting + Connection limits |
| CDN/Cache | Cache Nginx pour assets statiques |
| Firewall | iptables/fail2ban (optionnel) |
| Analytics | Prometheus + Grafana (optionnel) |

## Déploiement rapide

```bash
# 1. Cloner et basculer sur la branche
git checkout feature/sovereign-no-cloudflare

# 2. Lancer le script de déploiement
./deploy-sovereign.sh

# 3. Configurer DNS (chez votre registrar)
A     p0rt.xyz      → IP_SERVEUR
A     *.p0rt.xyz    → IP_SERVEUR

# 4. Obtenir certificats SSL
./nginx/scripts/init-letsencrypt.sh
```

## Configuration manuelle

### 1. Variables d'environnement

```bash
# .env
P0RT_DOMAIN=p0rt.xyz
P0RT_HTTP_PORT=8080
SSH_SERVER_PORT=2222
P0RT_OPEN_ACCESS=false
REDIS_HOST=redis
REDIS_PORT=6379
LETSENCRYPT_EMAIL=admin@p0rt.xyz
```

### 2. Démarrage

```bash
# Avec monitoring
docker compose -f docker-compose.sovereign.yml --profile monitoring up -d

# Sans monitoring
docker compose -f docker-compose.sovereign.yml up -d
```

### 3. Certificat wildcard

Pour les sous-domaines (*.p0rt.xyz), validation DNS requise :

```bash
docker compose -f docker-compose.sovereign.yml run --rm certbot certonly \
  --manual --preferred-challenges dns \
  --email admin@p0rt.xyz \
  --domains '*.p0rt.xyz' \
  --agree-tos
```

## Protection DDoS

### Rate Limiting configuré

- **Global** : 30 req/s par IP
- **Tunnels** : 5 req/s pour création
- **Par domaine** : 100 req/s
- **Connexions** : 100 par IP, 500 par domaine

### Sécurité supplémentaire

```nginx
# Bloque les user-agents malveillants
# Bloque les referrers spam
# Limite les méthodes HTTP
# Headers de sécurité (CSP, HSTS, etc.)
```

## Monitoring (optionnel)

- **Prometheus** : http://localhost:9090
- **Grafana** : http://localhost:3000 (admin/admin)

## Maintenance

```bash
# Logs
docker compose -f docker-compose.sovereign.yml logs -f nginx

# Renouvellement SSL (automatique via Certbot)
docker compose -f docker-compose.sovereign.yml exec certbot certbot renew

# Mise à jour config Nginx
docker compose -f docker-compose.sovereign.yml exec nginx nginx -s reload
```

## Avantages vs Cloudflare

✅ **Souveraineté totale** : Aucune dépendance externe  
✅ **Confidentialité** : Trafic non analysé par un tiers  
✅ **Personnalisation** : Configuration complète  
✅ **Coût** : Gratuit (hors serveur)  

## Limitations vs Cloudflare

❌ **Pas de CDN global** : Latence selon localisation serveur  
❌ **Protection DDoS basique** : Volumétrie limitée  
❌ **Pas d'analytics** : Sauf si Prometheus activé  
❌ **Maintenance** : Gestion SSL et sécurité manuelle  

## Recommandations production

1. **Firewall** : Configurer iptables ou ufw
2. **Fail2ban** : Protection contre brute force SSH
3. **Backup** : Sauvegarder `/etc/letsencrypt` et Redis
4. **Monitoring** : Activer Prometheus/Grafana
5. **IPv6** : Configurer si disponible
6. **Géo-blocage** : Installer GeoIP si nécessaire