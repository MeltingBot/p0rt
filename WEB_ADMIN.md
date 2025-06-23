# P0rt Web Admin Interface

Interface web d'administration pour P0rt, accessible à `/p0rtadmin`.

## 🚀 Fonctionnalités

- **Dashboard** : Vue d'ensemble avec métriques en temps réel
- **Connexions** : Monitoring des tunnels actifs
- **Domaines** : Gestion des réservations de domaines
- **Sécurité** : Surveillance des IPs bannies et événements
- **Abus** : Traitement des reports d'abus
- **Clés SSH** : Gestion des clés autorisées

## 🔧 Configuration

L'interface utilise les mêmes APIs que le CLI, avec authentification par clé API.

### Variables d'environnement

```bash
export API_KEY="votre-cle-api-secrete"
export SSH_SERVER_PORT="2222"
export HTTP_SERVER_PORT="8080"
export ADMIN_URL="/p0rtadmin"  # REQUIRED - Admin interface disabled if not set
```

**Important:** L'interface d'administration n'est disponible que si `ADMIN_URL` est définie dans l'environnement. Si cette variable n'est pas configurée, l'interface admin est complètement désactivée pour des raisons de sécurité.

### Démarrer le serveur

```bash
# Compilation
go build -o p0rt cmd/main/main.go

# Démarrage
./p0rt server start
```

### Accès à l'interface

1. Configurer `ADMIN_URL` dans l'environnement (ex: `/p0rtadmin`)
2. Ouvrir http://localhost:8080{ADMIN_URL} (ex: http://localhost:8080/p0rtadmin)
3. Entrer la clé API quand demandée
4. La clé sera stockée en localStorage pour les prochaines sessions

## 🎨 Interface

### Navigation
- Interface responsive avec navigation par onglets
- Design moderne avec thème sombre
- Actualisation automatique toutes les 30 secondes

### Dashboard
- Compteurs en temps réel (tunnels actifs, IPs bannies, etc.)
- Status du serveur avec détails techniques
- Historique des connexions récentes

### Gestion des connexions
- Liste des tunnels actifs
- Statistiques de trafic par connexion
- Informations client (IP, domaine, durée)

### Réservations de domaines
- Création/suppression de réservations
- Association domaine ↔ empreinte SSH
- Historique et commentaires

### Sécurité
- Visualisation des IPs bannies
- Débannissement d'IPs
- Statistiques d'attaques et tentatives de scan

### Reports d'abus
- Filtrage par status (en attente/traités)
- Actions en un clic (bannir/accepter)
- Détails complets des reports

### Clés SSH
- Liste des clés autorisées
- Activation/désactivation
- Suppression sécurisée

## 🔒 Sécurité

- **Interface désactivée par défaut** : Requiert `ADMIN_URL` dans l'environnement
- **Authentification requise** via clé API
- **Headers de sécurité** (CSP, X-Frame-Options, etc.)
- **Files statiques embarqués** dans le binaire
- **URL personnalisable** pour masquer l'interface d'administration
- **Pas d'accès extérieur** aux APIs d'administration sans authentification

### Configuration de sécurité recommandée

```bash
# URL d'admin difficile à deviner
export ADMIN_URL="/secret-admin-panel-$(date +%s)"

# Clé API forte
export API_KEY="$(openssl rand -hex 32)"
```

## 🛠️ Développement

### Structure des fichiers

```
internal/web/
├── admin.go              # Handler principal
└── admin/static/
    ├── admin.html        # Interface principale
    ├── admin.css         # Styles CSS
    └── admin.js          # Logique JavaScript
```

### APIs utilisées

L'interface consomme uniquement les APIs REST existantes :

- `GET /api/v1/stats` - Statistiques globales
- `GET /api/v1/connections` - Connexions actives
- `GET /api/v1/reservations` - Réservations
- `GET /api/v1/security/stats` - Statistiques sécurité
- `GET /api/v1/abuse/reports` - Reports d'abus
- `GET /api/v1/keys` - Clés SSH

### Extension

Pour ajouter de nouvelles fonctionnalités :

1. Modifier `admin.html` pour l'interface
2. Ajouter la logique dans `admin.js`
3. Utiliser les APIs existantes ou en créer de nouvelles

## 🧪 Tests

```bash
# Script de test automatique
./test_admin.sh

# Test manuel des APIs
curl -H "X-API-Key: your-key" http://localhost:8080/api/v1/status
```

## 📱 Responsive Design

L'interface s'adapte automatiquement :
- **Desktop** : Navigation horizontale, grilles multi-colonnes
- **Tablet** : Navigation compacte, grilles adaptatives  
- **Mobile** : Navigation verticale, colonnes simples

## 🎯 Intégration Production

Pour déployer en production :

1. Générer une clé API sécurisée
2. Configurer un reverse proxy (nginx/traefik)
3. Restriction d'accès par IP si nécessaire
4. Monitoring des logs d'accès

```nginx
# Exemple nginx
location /p0rtadmin {
    allow 192.168.1.0/24;  # Réseau admin
    deny all;
    proxy_pass http://localhost:8080;
}
```