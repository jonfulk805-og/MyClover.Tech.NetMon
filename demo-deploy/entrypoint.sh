#!/bin/bash
set -e

echo "=== MyClover.Tech.NetMon Demo Container ==="
echo "Starting at $(date -u)"

# Seed the database with demo data
echo "Seeding demo database..."
python demo_seed.py

# Start the simulator in the background
echo "Starting data simulator..."
python demo_simulator.py &
SIMULATOR_PID=$!

# Start netmon with gunicorn for production
echo "Starting NetMon dashboard..."
exec python netmon.py
