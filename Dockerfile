# Multi-stage Dockerfile pour p0rt
FROM golang:1.24-alpine AS builder

# Installer les dépendances nécessaires
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copier les fichiers go mod
COPY go.mod go.sum ./
RUN go mod download

# Copier le code source
COPY . .

# Construire l'application avec la nouvelle structure
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o p0rt cmd/main/main.go

# Image de production
FROM alpine:latest AS production

RUN apk --no-cache add ca-certificates curl tzdata && \
    addgroup -g 1001 -S p0rt && \
    adduser -u 1001 -D -S -G p0rt p0rt

WORKDIR /app

# Copier l'exécutable
COPY --from=builder /app/p0rt .

# Créer les répertoires nécessaires et fichiers par défaut
RUN mkdir -p data/security data/reservations data/stats && \
    echo "[]" > authorized_keys.json && \
    touch ssh_host_key && \
    chown -R p0rt:p0rt /app && \
    chmod 666 ssh_host_key authorized_keys.json

# Aucun fichier de configuration requis - tout est par variables d'environnement

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/health || exit 1

# Exposer les ports
EXPOSE 22 80

# Pour le port 22, nous devons démarrer en root puis drop privileges
# ou utiliser setcap pour permettre à l'utilisateur de bind des ports privilégiés
RUN apk add --no-cache libcap && \
    setcap 'cap_net_bind_service=+ep' /app/p0rt

# Utiliser l'utilisateur non-root
USER p0rt

# Commande par défaut
CMD ["./p0rt", "server", "start"]