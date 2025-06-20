#!/bin/bash

# Test web page rendering

echo "Testing P0rt web page..."

# Start server
go build -o p0rt cmd/server/main.go
./p0rt -server start &
SERVER_PID=$!

# Wait for server to start
sleep 3

echo "Checking web page..."
response=$(curl -s -H "Host: p0rt.xyz" http://localhost:8080)

if echo "$response" | grep -q "Built for Speed"; then
    echo "✅ Page loads correctly"
else
    echo "❌ Page has issues"
fi

if echo "$response" | grep -q "&lt; 50ms"; then
    echo "✅ Latency display fixed"
else
    echo "❌ Latency display issue"
fi

if echo "$response" | grep -q "99.9%"; then
    echo "✅ Uptime percentage fixed"
else
    echo "❌ Uptime percentage issue"
fi

if echo "$response" | grep -q "Beta Access\|Open Access"; then
    echo "✅ Access mode badge found"
else
    echo "❌ Access mode badge missing"
fi

# Kill server
kill $SERVER_PID 2>/dev/null

echo "Test completed"