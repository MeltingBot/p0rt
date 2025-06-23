#!/bin/bash

# Test script for P0rt web admin interface

echo "🚀 Starting P0rt server with web admin interface..."

# Set test environment variables
export API_KEY="test-admin-key-12345"
export SSH_PORT="2222"
export HTTP_PORT="8080"
export P0RT_OPEN_ACCESS="false"
export P0RT_VERBOSE="true"
export ADMIN_URL="/p0rtadmin"

# Start the server in background
./p0rt server start &
SERVER_PID=$!

echo "📡 P0rt server started with PID $SERVER_PID"
echo "🔑 API Key: $API_KEY"
echo ""
echo "🌐 Web Admin Interface: http://localhost:8080/p0rtadmin"
echo "📊 API Endpoints:"
echo "   - http://localhost:8080/api/v1/status"
echo "   - http://localhost:8080/api/v1/stats"
echo "   - http://localhost:8080/api/v1/reservations"
echo ""
echo "⚡ Test commands:"
echo "   curl -H 'X-API-Key: $API_KEY' http://localhost:8080/api/v1/status"
echo "   curl -H 'X-API-Key: $API_KEY' http://localhost:8080/api/v1/stats"
echo ""
echo "🛑 Press Ctrl+C to stop the server"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping P0rt server..."
    kill $SERVER_PID 2>/dev/null
    echo "✅ Server stopped"
    exit 0
}

# Trap Ctrl+C
trap cleanup INT

# Wait for the server process
wait $SERVER_PID
