#!/bin/bash

# Generate self-signed certificate for default server block

mkdir -p /etc/nginx/ssl

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/default.key \
    -out /etc/nginx/ssl/default.crt \
    -subj "/C=FR/ST=IDF/L=Paris/O=P0rt/OU=IT/CN=localhost"

chmod 600 /etc/nginx/ssl/default.key
chmod 644 /etc/nginx/ssl/default.crt

echo "Self-signed certificate generated successfully"