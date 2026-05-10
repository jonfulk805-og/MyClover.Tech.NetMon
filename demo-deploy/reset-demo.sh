#!/bin/bash
# reset-demo.sh -- Resets both demo databases to a fresh state
# Add to crontab: 0 */6 * * * /opt/netmon-demo/reset-demo.sh >> /var/log/netmon-demo-reset.log 2>&1

set -e
echo "$(date -u) -- Resetting demo databases..."

cd /opt/netmon-demo

# Re-seed NetMon database
docker exec netmon-demo python demo_seed.py
echo "$(date -u) -- NetMon reset complete"

# Re-seed SentryLog database
docker exec sentrylog-demo python sentrylog_seed.py 2>/dev/null || echo "$(date -u) -- SentryLog reset skipped (container not running)"
echo "$(date -u) -- SentryLog reset complete"

echo "$(date -u) -- All demo resets complete"
