#!/bin/bash
set -e

echo "=== MyClover.Tech.NetMon ==="
echo "Starting at $(date -u)"

DATA_DIR="${NETMON_DATA_DIR:-/app/data}"
CONFIG_PATH="${NETMON_CONFIG:-$DATA_DIR/config.yaml}"
BACKUP_DIR="${NETMON_BACKUP_DIR:-$DATA_DIR/backups}"
PLUGIN_DIR="${NETMON_PLUGIN_DIR:-$DATA_DIR/plugins}"

mkdir -p "$DATA_DIR" "$BACKUP_DIR" "$PLUGIN_DIR"

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

# Seed bundled plugins into the data volume (user uploads land there too).
if [ -d /app/plugins ]; then
    for f in /app/plugins/*.py; do
        [ -e "$f" ] || continue
        if [ ! -f "$PLUGIN_DIR/$(basename "$f")" ]; then
            cp "$f" "$PLUGIN_DIR/"
        fi
    done
fi

echo "Data dir: $DATA_DIR | config: $CONFIG_PATH | db: ${NETMON_DB_PATH:-$DATA_DIR/netmon.db} | backups: $BACKUP_DIR | plugins: $PLUGIN_DIR"

# Start NetMon
exec python netmon.py
