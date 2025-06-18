#!/bin/bash

# Script to clean up old domain mappings

DATA_DIR="${DATA_DIR:-./data}"
MAX_AGE_DAYS="${MAX_AGE_DAYS:-90}"

echo "🧹 P0rt Domain Cleanup"
echo "====================="
echo ""
echo "Data directory: $DATA_DIR"
echo "Max age: $MAX_AGE_DAYS days"
echo ""

if [ ! -f "$DATA_DIR/domains.json" ]; then
    echo "❌ No domains.json file found in $DATA_DIR"
    echo "   Nothing to clean up."
    exit 0
fi

# Show current stats
echo "📊 Current domain statistics:"
TOTAL_DOMAINS=$(jq '. | length' "$DATA_DIR/domains.json" 2>/dev/null || echo "0")
echo "   Total domains: $TOTAL_DOMAINS"

# Find domains older than MAX_AGE_DAYS
CUTOFF_DATE=$(date -d "$MAX_AGE_DAYS days ago" -u +"%Y-%m-%dT%H:%M:%S")
echo "   Cutoff date: $CUTOFF_DATE"

# Count old domains
OLD_DOMAINS=$(jq --arg cutoff "$CUTOFF_DATE" '[.[] | select(.last_seen < $cutoff)] | length' "$DATA_DIR/domains.json" 2>/dev/null || echo "0")
echo "   Domains to remove: $OLD_DOMAINS"

if [ "$OLD_DOMAINS" -eq "0" ]; then
    echo "✅ No old domains to clean up."
    exit 0
fi

# Create backup
BACKUP_FILE="$DATA_DIR/domains.json.backup.$(date +%Y%m%d_%H%M%S)"
cp "$DATA_DIR/domains.json" "$BACKUP_FILE"
echo "💾 Backup created: $BACKUP_FILE"

# Remove old domains
jq --arg cutoff "$CUTOFF_DATE" 'with_entries(select(.value.last_seen >= $cutoff))' "$DATA_DIR/domains.json" > "$DATA_DIR/domains.json.tmp"

if [ $? -eq 0 ]; then
    mv "$DATA_DIR/domains.json.tmp" "$DATA_DIR/domains.json"
    echo "✅ Removed $OLD_DOMAINS old domain mappings"
    
    # Show new stats
    NEW_TOTAL=$(jq '. | length' "$DATA_DIR/domains.json")
    echo "📊 New total: $NEW_TOTAL domains"
    echo "💾 Freed space: ~$((OLD_DOMAINS * 150)) bytes"
else
    echo "❌ Failed to clean up domains"
    rm -f "$DATA_DIR/domains.json.tmp"
    exit 1
fi

echo ""
echo "🎉 Cleanup completed successfully!"