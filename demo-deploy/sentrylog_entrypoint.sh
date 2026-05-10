#!/bin/bash
set -e
echo "=== MyClover.Tech.SentryLog Demo Container ==="
echo "Starting at $(date)"

echo "Seeding demo database..."
python3 sentrylog_seed.py
echo "Seed complete."

echo "Starting SentryLog on port 8514..."
exec python3 sentrylog.py
