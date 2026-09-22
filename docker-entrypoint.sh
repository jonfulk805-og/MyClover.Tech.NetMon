#!/bin/bash
set -e

echo "=== MyClover.Tech.NetMon ==="
echo "Starting at $(date -u)"

DATA_DIR="${NETMON_DATA_DIR:-/app/data}"
CONFIG_PATH="${NETMON_CONFIG:-$DATA_DIR/config.yaml}"
mkdir -p "$DATA_DIR" "${NETMON_BACKUP_DIR:-$DATA_DIR/backups}"

# Seed the config inside the data volume so edits survive container replacement.
if [ ! -f "$CONFIG_PATH" ]; then
    if [ -f /app/config.yaml ]; then
        echo "Migrating existing /app/config.yaml into $CONFIG_PATH ..."
        cp /app/config.yaml "$CONFIG_PATH"
    else
        echo "No config found - seeding default at $CONFIG_PATH ..."
        cp /app/config.yaml.default "$CONFIG_PATH"
    fi
fi
echo "Data dir: $DATA_DIR | config: $CONFIG_PATH | db: ${NETMON_DB_PATH:-$DATA_DIR/netmon.db}"

# Start NetMon
exec python netmon.py
