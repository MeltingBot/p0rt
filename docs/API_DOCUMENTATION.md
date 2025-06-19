# P0rt API Documentation

L'API REST de P0rt permet de gérer les réservations de domaines et d'obtenir des statistiques à distance. Cette API est particulièrement utile pour administrer un serveur P0rt en cours d'exécution.

## Configuration

### Activation de l'API

L'API est automatiquement activée quand le serveur P0rt démarre. Elle écoute sur le même port que le proxy HTTP.

### Authentification (Optionnelle)

Pour sécuriser l'API, vous pouvez définir une clé API via la variable d'environnement :

```bash
export P0RT_API_KEY="your-secret-api-key"
```

Si aucune clé n'est définie, l'API accepte toutes les requêtes.

### Utilisation de la clé API

La clé API peut être fournie de deux façons :

1. **En-tête HTTP** :
   ```
   X-API-Key: your-secret-api-key
   ```

2. **Paramètre de requête** :
   ```
   ?api_key=your-secret-api-key
   ```

## Endpoints API

### Base URL

```
http://localhost:80/api/v1
```

### 1. Status du serveur

**GET** `/api/v1/status`

Retourne le statut du serveur P0rt.

**Réponse** :
```json
{
  "success": true,
  "service": "p0rt",
  "version": "1.0.0",
  "api_version": "v1",
  "uptime": "2h 15m 30s",
  "active_tunnels": 5,
  "timestamp": "2024-01-15T10:30:45Z"
}
```

### 2. Gestion des réservations

#### Lister toutes les réservations

**GET** `/api/v1/reservations`

**Réponse** :
```json
{
  "success": true,
  "reservations": [
    {
      "domain": "happy-cat-jump",
      "fingerprint": "SHA256:abc123...",
      "comment": "Mon domaine personnel",
      "created_at": "2024-01-15T10:30:45Z",
      "updated_at": "2024-01-15T10:30:45Z"
    }
  ],
  "count": 1,
  "timestamp": "2024-01-15T10:30:45Z"
}
```

#### Obtenir une réservation spécifique

**GET** `/api/v1/reservations/{domain}`

**Réponse** :
```json
{
  "success": true,
  "reservation": {
    "domain": "happy-cat-jump",
    "fingerprint": "SHA256:abc123...",
    "comment": "Mon domaine personnel",
    "created_at": "2024-01-15T10:30:45Z",
    "updated_at": "2024-01-15T10:30:45Z"
  },
  "timestamp": "2024-01-15T10:30:45Z"
}
```

#### Créer une nouvelle réservation

**POST** `/api/v1/reservations`

**Corps de requête** :
```json
{
  "domain": "happy-cat-jump",
  "fingerprint": "SHA256:abc123...",
  "comment": "Mon domaine personnel"
}
```

**Réponse** :
```json
{
  "success": true,
  "message": "Reservation created for domain happy-cat-jump",
  "domain": "happy-cat-jump",
  "timestamp": "2024-01-15T10:30:45Z"
}
```

#### Supprimer une réservation

**DELETE** `/api/v1/reservations/{domain}`

**Réponse** :
```json
{
  "success": true,
  "message": "Reservation removed for domain happy-cat-jump",
  "domain": "happy-cat-jump",
  "timestamp": "2024-01-15T10:30:45Z"
}
```

### 3. Statistiques

#### Statistiques globales

**GET** `/api/v1/stats`

**Réponse** :
```json
{
  "success": true,
  "global_stats": {
    "uptime": "2h 15m 30s",
    "active_tunnels": 5,
    "total_tunnels": 25,
    "total_connections": 150,
    "http_requests": 1200,
    "websocket_connections": 10,
    "bytes_transferred": 1048576,
    "top_domains": [
      {
        "domain": "happy-cat-jump",
        "total_requests": 100,
        "bytes_in": 50000,
        "bytes_out": 75000
      }
    ]
  },
  "reservation_stats": {
    "total_reservations": 5,
    "active_reservations": 3
  },
  "timestamp": "2024-01-15T10:30:45Z"
}
```

#### Statistiques d'un tunnel spécifique

**GET** `/api/v1/stats/tunnel/{domain}`

**Réponse** :
```json
{
  "success": true,
  "tunnel_stats": {
    "domain": "happy-cat-jump",
    "created_at": "2024-01-15T08:15:30Z",
    "last_activity": "2024-01-15T10:30:45Z",
    "total_requests": 100,
    "bytes_in": 50000,
    "bytes_out": 75000,
    "websocket_upgrades": 2,
    "active_connections": 1
  },
  "timestamp": "2024-01-15T10:30:45Z"
}
```

## Codes d'erreur

L'API utilise les codes de statut HTTP standard :

- `200` - Succès
- `201` - Créé avec succès 
- `400` - Requête malformée
- `401` - Non autorisé (clé API invalide)
- `404` - Ressource non trouvée
- `405` - Méthode non autorisée
- `409` - Conflit (réservation déjà existante)
- `500` - Erreur serveur interne

**Format d'erreur** :
```json
{
  "error": true,
  "message": "Description de l'erreur",
  "timestamp": "2024-01-15T10:30:45Z"
}
```

## Utilisation avec le CLI

### Mode CLI interactif distant

```bash
# Se connecter à un serveur P0rt distant
./p0rt -cli -remote http://localhost:80 -api-key your-secret-key

# Utiliser les commandes normalement
p0rt> reservation list
p0rt> stats
p0rt> reservation add my-domain SHA256:abc123... "Mon domaine"
```

### Commandes en ligne de commande

```bash
# Lister les réservations à distance
./p0rt -remote http://localhost:80 -reservation list

# Ajouter une réservation à distance
./p0rt -remote http://localhost:80 -reservation add -domain my-domain -fingerprint SHA256:abc123... -comment "Mon domaine"

# Avec authentification
./p0rt -remote http://localhost:80 -api-key your-secret-key -reservation list
```

## Exemples avec curl

### Lister les réservations

```bash
curl -H "X-API-Key: your-secret-key" http://localhost:80/api/v1/reservations
```

### Créer une réservation

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{"domain":"my-domain","fingerprint":"SHA256:abc123...","comment":"Mon domaine"}' \
  http://localhost:80/api/v1/reservations
```

### Obtenir les statistiques

```bash
curl -H "X-API-Key: your-secret-key" http://localhost:80/api/v1/stats
```

### Supprimer une réservation

```bash
curl -X DELETE \
  -H "X-API-Key: your-secret-key" \
  http://localhost:80/api/v1/reservations/my-domain
```

## Sécurité

### Recommandations

1. **Utilisez HTTPS** en production pour protéger la clé API
2. **Générez une clé API forte** (au moins 32 caractères aléatoires)
3. **Limitez l'accès réseau** à l'API (firewall, VPN)
4. **Surveillez les logs** pour détecter les accès non autorisés

### Génération d'une clé API sécurisée

```bash
# Générer une clé API aléatoire
openssl rand -hex 32
```

## Intégration

L'API REST peut être intégrée dans :

- **Scripts de déploiement** pour automatiser la gestion des domaines
- **Interfaces web** pour une administration graphique
- **Systèmes de monitoring** pour surveiller les statistiques
- **Outils DevOps** pour l'intégration CI/CD

## Limitations

- L'API partage le même port que le proxy HTTP
- Pas de limitation de débit intégrée (à implémenter au niveau reverse proxy)
- Authentification basique par clé API uniquement
- Pas de gestion des permissions granulaires