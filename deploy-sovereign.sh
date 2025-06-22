#!/bin/bash

set -e

echo "P0rt Sovereign Deployment Script"
echo "================================"
echo

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo "Please do not run this script as root"
   exit 1
fi

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || command -v docker compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed. Aborting." >&2; exit 1; }

# Configuration
read -p "Enter your domain (default: p0rt.xyz): " DOMAIN
DOMAIN=${DOMAIN:-p0rt.xyz}

read -p "Enter your email for Let's Encrypt: " EMAIL
if [ -z "$EMAIL" ]; then
    echo "Email is required for Let's Encrypt"
    exit 1
fi

read -p "Enable monitoring stack? (y/N): " ENABLE_MONITORING
MONITORING_PROFILE=""
if [ "$ENABLE_MONITORING" = "y" ] || [ "$ENABLE_MONITORING" = "Y" ]; then
    MONITORING_PROFILE="--profile monitoring"
fi

# Create necessary directories
echo "Creating directories..."
mkdir -p nginx/ssl certbot/conf certbot/www data configs monitoring

# Generate self-signed certificate for initial setup
echo "Generating self-signed certificate..."
docker run --rm -v "$(pwd)/nginx/ssl:/output" alpine/openssl \
    req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /output/default.key \
    -out /output/default.crt \
    -subj "/C=FR/ST=IDF/L=Paris/O=P0rt/OU=IT/CN=localhost"

# Update configuration with domain
echo "Updating configuration..."
sed -i "s/p0rt.xyz/$DOMAIN/g" nginx/conf.d/p0rt.conf
sed -i "s/admin@p0rt.xyz/$EMAIL/g" nginx/scripts/init-letsencrypt.sh

# Create .env file
cat > .env <<EOF
# P0rt Configuration
P0RT_DOMAIN=$DOMAIN
P0RT_HTTP_PORT=8080
SSH_SERVER_PORT=2222
P0RT_OPEN_ACCESS=false

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379

# Email for Let's Encrypt
LETSENCRYPT_EMAIL=$EMAIL
EOF

echo "Configuration saved to .env"

# Build P0rt
echo "Building P0rt..."
docker compose -f docker-compose.sovereign.yml build

# Start services
echo "Starting services..."
docker compose -f docker-compose.sovereign.yml up -d $MONITORING_PROFILE

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 10

# Check health
echo "Checking service health..."
docker compose -f docker-compose.sovereign.yml ps

# Initialize Let's Encrypt
echo
echo "Services are running!"
echo
echo "Next steps:"
echo "1. Make sure your DNS A records point to this server:"
echo "   - $DOMAIN -> $(curl -s ifconfig.me)"
echo "   - *.$DOMAIN -> $(curl -s ifconfig.me)"
echo
echo "2. Once DNS is configured, run Let's Encrypt initialization:"
echo "   ./nginx/scripts/init-letsencrypt.sh"
echo
echo "3. For wildcard certificate (required for subdomains), you'll need DNS validation:"
echo "   docker compose -f docker-compose.sovereign.yml run --rm certbot certonly \\"
echo "     --manual --preferred-challenges dns --email $EMAIL \\"
echo "     --domains '*.$DOMAIN' --agree-tos"
echo
echo "4. Access your services:"
echo "   - P0rt: https://$DOMAIN"
echo "   - SSH: ssh -R 443:localhost:8080 $DOMAIN -p 2222"
if [ "$ENABLE_MONITORING" = "y" ] || [ "$ENABLE_MONITORING" = "Y" ]; then
    echo "   - Prometheus: http://localhost:9090"
    echo "   - Grafana: http://localhost:3000 (admin/admin)"
fi
echo
echo "Logs: docker compose -f docker-compose.sovereign.yml logs -f"