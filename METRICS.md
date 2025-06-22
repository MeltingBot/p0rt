# P0rt Prometheus Metrics

P0rt expose des métriques Prometheus pour le monitoring des connexions, du trafic, de la sécurité et des abus.

## Configuration

### Variables d'environnement

```bash
# Activer l'endpoint /metrics avec authentification basique
P0RT_METRICS_USERNAME=prometheus
P0RT_METRICS_PASSWORD=secure_password_here
```

### Accès à l'endpoint

```bash
# Accès aux métriques
curl -u prometheus:secure_password_here https://p0rt.xyz/metrics
```

## Métriques disponibles

### 🔐 Connexions SSH

| Métrique | Type | Description | Labels |
|----------|------|-------------|--------|
| `p0rt_ssh_connections_total` | Counter | Nombre total de connexions SSH | `status` (success, failed, banned) |
| `p0rt_ssh_connections_active` | Gauge | Nombre de connexions SSH actives | - |
| `p0rt_ssh_tunnels_active` | Gauge | Nombre de tunnels SSH actifs | - |
| `p0rt_ssh_auth_failures_total` | Counter | Échecs d'authentification SSH | `ip`, `reason` |

### 🌐 Trafic HTTP/WebSocket

| Métrique | Type | Description | Labels |
|----------|------|-------------|--------|
| `p0rt_http_requests_total` | Counter | Nombre total de requêtes HTTP | `method`, `status_code`, `domain_type` |
| `p0rt_http_request_duration_seconds` | Histogram | Durée des requêtes HTTP | `method`, `domain_type` |
| `p0rt_http_bytes_total` | Counter | Octets transférés via HTTP | `direction` (in, out), `domain` |
| `p0rt_websocket_connections_total` | Counter | Connexions WebSocket totales | `status` |
| `p0rt_websocket_connections_active` | Gauge | Connexions WebSocket actives | - |

### 🛡️ Sécurité et abus

| Métrique | Type | Description | Labels |
|----------|------|-------------|--------|
| `p0rt_security_events_total` | Counter | Événements de sécurité | `type`, `severity` |
| `p0rt_banned_ips_total` | Gauge | Nombre d'IPs bannies | - |
| `p0rt_banned_domains_total` | Gauge | Nombre de domaines bannis | - |
| `p0rt_abuse_reports_total` | Counter | Rapports d'abus | `type`, `status` |
| `p0rt_rate_limit_hits_total` | Counter | Violations de rate limiting | `type`, `ip` |

### 🌍 Domaines

| Métrique | Type | Description | Labels |
|----------|------|-------------|--------|
| `p0rt_domains_generated_total` | Counter | Domaines générés (trigrammes) | - |
| `p0rt_domains_reserved_total` | Gauge | Domaines réservés actifs | - |
| `p0rt_domain_usage_total` | Counter | Statistiques d'usage par domaine | `domain`, `type` |

### ⚙️ Système

| Métrique | Type | Description | Labels |
|----------|------|-------------|--------|
| `p0rt_system_info` | Gauge | Informations système | `version`, `build_time`, `git_commit` |
| `p0rt_uptime_seconds` | Gauge | Temps de fonctionnement en secondes | - |

### 🗄️ Redis (si activé)

| Métrique | Type | Description | Labels |
|----------|------|-------------|--------|
| `p0rt_redis_connections_total` | Counter | Connexions Redis totales | `status` |
| `p0rt_redis_operations_total` | Counter | Opérations Redis totales | `operation`, `status` |

## Labels détaillés

### Statuts de connexion SSH
- `success` - Connexion réussie
- `failed` - Échec d'authentification 
- `banned` - IP bannie tentant de se connecter

### Types de domaines HTTP
- `tunnel` - Requêtes vers des tunnels utilisateur
- `homepage` - Requêtes vers la page d'accueil
- `health` - Requêtes de health check

### Types d'événements de sécurité
- `auth_failure` - Échec d'authentification
- `brute_force` - Tentative de force brute détectée
- `port_scanning` - Scan de port détecté
- `abuse_report` - Rapport d'abus soumis
- `domain_ban` - Domaine banni
- `report_accepted` - Rapport d'abus accepté
- `websocket_upgrade_failed` - Échec upgrade WebSocket
- `websocket_connection_failed` - Échec connexion WebSocket
- `websocket_connection_success` - Connexion WebSocket réussie

### Sévérités
- `low` - Événement informatif
- `medium` - Événement suspect
- `high` - Événement critique

### Types de rapports d'abus
- `phishing` - Phishing détecté
- `spam` - Spam détecté
- `scam` - Arnaque détectée
- `malware` - Malware détecté

### Statuts de rapports d'abus
- `pending` - En attente de traitement
- `banned` - Domaine banni suite au rapport
- `accepted` - Rapport accepté mais domaine non banni

## Exemples de requêtes PromQL

### Taux de connexions SSH par minute
```promql
rate(p0rt_ssh_connections_total[1m])
```

### Pourcentage d'échecs d'authentification
```promql
rate(p0rt_ssh_connections_total{status="failed"}[5m]) / rate(p0rt_ssh_connections_total[5m]) * 100
```

### Top 10 des domaines par trafic
```promql
topk(10, sum by (domain) (rate(p0rt_http_bytes_total[1h])))
```

### Événements de sécurité critiques
```promql
increase(p0rt_security_events_total{severity="high"}[1h])
```

### Latence moyenne des requêtes HTTP
```promql
histogram_quantile(0.95, rate(p0rt_http_request_duration_seconds_bucket[5m]))
```

### Nombre d'IPs bannies dans les dernières 24h
```promql
p0rt_banned_ips_total
```

### Taux de rapports d'abus par type
```promql
rate(p0rt_abuse_reports_total[24h]) by (type)
```

## Configuration Grafana

### Alertes recommandées

1. **Pic d'échecs SSH** : `rate(p0rt_ssh_connections_total{status="failed"}[5m]) > 10`
2. **Trop d'IPs bannies** : `p0rt_banned_ips_total > 100`
3. **Latence élevée** : `histogram_quantile(0.95, rate(p0rt_http_request_duration_seconds_bucket[5m])) > 2`
4. **Événements de sécurité critiques** : `increase(p0rt_security_events_total{severity="high"}[5m]) > 0`

### Dashboards suggérés

1. **Vue d'ensemble P0rt** - Métriques clés système et trafic
2. **Sécurité P0rt** - Événements de sécurité et bans
3. **Performance P0rt** - Latences et throughput
4. **Abus P0rt** - Rapports d'abus et modération

## Notes de sécurité

- L'endpoint `/metrics` est protégé par authentification basique
- Les credentials sont stockés dans les variables d'environnement
- Si aucun credential n'est configuré, l'endpoint retourne 503
- Les métriques n'exposent pas d'informations sensibles utilisateur
- Les IPs dans les labels sont tronquées pour la confidentialité