#!/bin/bash
# reset-demo.sh -- Resets the demo database to a fresh state
# Add to crontab: 0 */6 * * * /opt/netmon-demo/reset-demo.sh >> /var/log/netmon-demo-reset.log 2>&1

set -e
echo "$(date -u) -- Resetting demo database..."

cd /opt/netmon-demo

# Re-seed the database inside the running container
docker exec netmon-demo python demo_seed.py

echo "$(date -u) -- Demo reset complete"
