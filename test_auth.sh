#!/bin/bash

echo "=== Test d'authentification API P0rt ==="
echo

# Test 1: Démarrer le serveur sans clé API
echo "Test 1: Serveur sans authentification"
echo "Commande: ./p0rt -server start"
echo "Attendu: Accepte toutes les requêtes"
echo

# Test 2: Démarrer le serveur avec clé API
echo "Test 2: Serveur avec authentification"
echo "Commande: P0RT_API_KEY=secret123 ./p0rt -server start"
echo "Attendu: Requiert authentification"
echo

# Test 3: CLI avec bonne clé
echo "Test 3: CLI avec bonne clé API"
echo "Commande: ./p0rt -cli -remote http://localhost:80 -api-key secret123"
echo "Attendu: Connexion réussie"
echo

# Test 4: CLI avec mauvaise clé
echo "Test 4: CLI avec mauvaise clé API"
echo "Commande: ./p0rt -cli -remote http://localhost:80 -api-key wrong123"
echo "Attendu: Échec de connexion"
echo

# Test 5: Requête curl avec bonne clé
echo "Test 5: Requête curl avec bonne clé"
echo "Commande: curl -H 'X-API-Key: secret123' http://localhost:80/api/v1/status"
echo "Attendu: Réponse JSON avec succès"
echo

# Test 6: Requête curl avec mauvaise clé
echo "Test 6: Requête curl avec mauvaise clé"
echo "Commande: curl -H 'X-API-Key: wrong123' http://localhost:80/api/v1/status"
echo "Attendu: Erreur 401 Unauthorized"
echo

echo "Pour tester manuellement:"
echo "1. Démarrez le serveur: P0RT_API_KEY=secret123 ./p0rt -server start"
echo "2. Dans un autre terminal, testez:"
echo "   - Bonne clé: curl -H 'X-API-Key: secret123' http://localhost:80/api/v1/status"
echo "   - Mauvaise clé: curl -H 'X-API-Key: wrong123' http://localhost:80/api/v1/status"
echo "   - CLI bon: ./p0rt -cli -remote http://localhost:80 -api-key secret123"
echo "   - CLI faux: ./p0rt -cli -remote http://localhost:80 -api-key wrong123"