#!/bin/bash
set -e

echo "=== MyClover.Tech.NetMon ==="
echo "Starting at $(date -u)"

# Copy default config if user hasn't mounted one
if [ ! -f /app/config.yaml ]; then
    echo "No config.yaml found — copying default..."
    cp /app/config.yaml.default /app/config.yaml
fi

# Start NetMon
exec python netmon.py
