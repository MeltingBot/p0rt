#!/bin/bash

# Script to initialize Let's Encrypt certificates for P0rt

domains=(p0rt.xyz www.p0rt.xyz)
rsa_key_size=4096
data_path="./certbot"
email="admin@p0rt.xyz" # Change this
staging=0 # Set to 1 if testing

if [ -d "$data_path" ]; then
  read -p "Existing data found. Continue and replace certificates? (y/N) " decision
  if [ "$decision" != "Y" ] && [ "$decision" != "y" ]; then
    exit
  fi
fi

# Download recommended TLS parameters
if [ ! -e "$data_path/conf/options-ssl-nginx.conf" ] || [ ! -e "$data_path/conf/ssl-dhparams.pem" ]; then
  echo "### Downloading recommended TLS parameters..."
  mkdir -p "$data_path/conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > "$data_path/conf/options-ssl-nginx.conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem > "$data_path/conf/ssl-dhparams.pem"
  echo
fi

# Create dummy certificate
echo "### Creating dummy certificate for ${domains[0]}..."
path="/etc/letsencrypt/live/${domains[0]}"
mkdir -p "$data_path/conf/live/${domains[0]}"
docker compose run --rm --entrypoint "\
  openssl req -x509 -nodes -newkey rsa:$rsa_key_size -days 1\
    -keyout '$path/privkey.pem' \
    -out '$path/fullchain.pem' \
    -subj '/CN=localhost'" certbot
echo

# Start nginx
echo "### Starting nginx..."
docker compose up --force-recreate -d nginx
echo

# Delete dummy certificate
echo "### Deleting dummy certificate for ${domains[0]}..."
docker compose run --rm --entrypoint "\
  rm -Rf /etc/letsencrypt/live/${domains[0]} && \
  rm -Rf /etc/letsencrypt/archive/${domains[0]} && \
  rm -Rf /etc/letsencrypt/renewal/${domains[0]}.conf" certbot
echo

# Request certificate with wildcard
echo "### Requesting Let's Encrypt certificate for ${domains[0]} and *.${domains[0]}..."

# Enable staging mode if needed
if [ $staging != "0" ]; then staging_arg="--staging"; fi

docker compose run --rm --entrypoint "\
  certbot certonly --webroot -w /var/www/certbot \
    $staging_arg \
    --email $email \
    --domains ${domains[0]},www.${domains[0]} \
    --rsa-key-size $rsa_key_size \
    --agree-tos \
    --force-renewal" certbot
echo

# Note about wildcard
echo "### IMPORTANT: Wildcard certificate requires DNS validation ###"
echo "To get wildcard certificate for *.p0rt.xyz, run:"
echo "docker compose run --rm certbot certonly --manual --preferred-challenges dns --email $email --domains '*.p0rt.xyz' --agree-tos"
echo

# Reload nginx
echo "### Reloading nginx..."
docker compose exec nginx nginx -s reload