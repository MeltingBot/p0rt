# P0rt CLI Examples with Cobra

## 🎯 **Conventions d'options**

P0rt utilise les conventions GNU standard :
- **Options courtes** : `-f`, `-d`, `-k` (un tiret, une lettre)
- **Options longues** : `--fingerprint`, `--domain`, `--api-key` (double tiret, mot complet)

## 📋 **Exemples d'usage**

### Server Management

```bash
# Démarrer le serveur
p0rt server start

# Statut du serveur
p0rt server status

# Avec configuration personnalisée (les deux formes)
p0rt -C /path/to/config.yaml server start
p0rt --config /path/to/config.yaml server start
```

### Local Reservation Management

```bash
# Lister les réservations
p0rt reservation list
p0rt r list          # forme courte avec alias

# Ajouter une réservation - forme complète
p0rt reservation add happy-cat-jump SHA256:abc123... "My personal domain"

# Ajouter une réservation - forme mixte (courte/longue)
p0rt r add test-domain -f SHA256:def456... --comment "Test domain"

# Ajouter avec flags courts uniquement
p0rt r add -d test2 -f SHA256:ghi789... -c "Another test"

# Supprimer une réservation
p0rt reservation remove happy-cat-jump
p0rt r remove test-domain
p0rt r rm test2      # alias pour remove

# Statistiques
p0rt reservation stats
p0rt r stats
```

### Remote Server Management

```bash
# Mode long complet
p0rt --remote http://localhost:80 --api-key secret123 reservation list

# Mode court complet  
p0rt -R http://localhost:80 -k secret123 r list

# Forme mixte
p0rt --remote http://localhost:80 -k secret123 r add test-domain -f SHA256:abc123...

# CLI interactif distant
p0rt --remote http://localhost:80 --api-key secret123 cli
p0rt -R http://localhost:80 -k secret123 i    # forme ultra-courte
```

### Statistics

```bash
# Statistiques globales
p0rt stats

# Statistiques d'un domaine spécifique
p0rt stats happy-cat-jump

# Statistiques distantes
p0rt --remote http://localhost:80 stats
p0rt -R http://localhost:80 stats test-domain
```

### Interactive CLI

```bash
# CLI local
p0rt cli
p0rt i              # alias court

# CLI distant avec authentification
p0rt --remote http://localhost:80 --api-key secret cli
p0rt -R http://localhost:80 -k secret i
```

## 🚀 **Exemples avancés**

### Gestion batch avec scripts

```bash
#!/bin/bash
# Script de déploiement avec p0rt

# Variables
REMOTE_URL="http://prod-server.com:80"
API_KEY="prod-secret-key"

# Ajouter plusieurs domaines
domains=("app1" "app2" "app3")
fingerprints=("SHA256:abc123..." "SHA256:def456..." "SHA256:ghi789...")

for i in "${!domains[@]}"; do
    p0rt -R "$REMOTE_URL" -k "$API_KEY" r add "${domains[$i]}" "${fingerprints[$i]}" "Prod domain $((i+1))"
done

# Vérifier les statistiques
p0rt -R "$REMOTE_URL" -k "$API_KEY" stats
```

### Auto-complétion Bash

```bash
# Installer l'auto-complétion
p0rt completion bash > /etc/bash_completion.d/p0rt

# Maintenant vous pouvez faire :
p0rt <TAB>          # complète les commandes
p0rt r <TAB>        # complète les sous-commandes
p0rt --<TAB>        # complète les options longues
```

### Configuration avec variables d'environnement

```bash
# Définir l'API key par défaut
export P0RT_API_KEY="your-secret-key"

# Plus besoin de -k à chaque fois
p0rt -R http://localhost:80 r list

# Configuration personnalisée
export CONFIG_FILE="/opt/p0rt/prod.yaml"
p0rt server start
```

## 💡 **Conseils d'usage**

### Pour l'usage interactif quotidien
```bash
# Utilisez les formes courtes et alias
p0rt r list
p0rt i
p0rt -R http://localhost:80 -k secret r add test -f SHA256:abc...
```

### Pour les scripts et la documentation
```bash
# Utilisez les formes longues pour la lisibilité
p0rt reservation list
p0rt --remote http://localhost:80 --api-key secret reservation add test-domain --fingerprint SHA256:abc... --comment "Production domain"
```

### Pour l'efficacité maximale
```bash
# Combinez aliases et formes courtes
alias pr="p0rt -R http://localhost:80 -k secret r"
pr list
pr add test -f SHA256:abc...
pr stats
```

## 🎯 **Comparaison des approches**

| Situation | Forme recommandée | Exemple |
|-----------|-------------------|---------|
| Usage quotidien | Courte + alias | `p0rt r list` |
| Scripts | Longue | `p0rt reservation list` |
| Combiné | Mixte | `p0rt --remote url -k key r add` |
| Documentation | Longue explicite | `p0rt --config file server start` |
| Démo/tutoriel | Progressive | Montrer les deux |

## 🔧 **Aide contextuelle**

```bash
# Aide générale
p0rt --help
p0rt -h

# Aide sur une commande
p0rt server --help
p0rt reservation --help

# Aide sur une sous-commande
p0rt reservation add --help
p0rt r add -h
```

La beauté de Cobra est qu'il supporte naturellement toutes ces conventions sans configuration supplémentaire !