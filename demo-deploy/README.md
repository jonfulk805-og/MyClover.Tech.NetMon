# MyClover.Tech.NetMon - Live Demo Deployment

Live demo system for `demo.myclover.tech` — showcases all Enterprise features with simulated network data.

## Quick Start

```bash
# On your Hostinger Ubuntu VPS:
# 1. Make sure demo.myclover.tech DNS A record points to VPS IP
# 2. Upload this folder to the VPS (e.g. via scp or SFTP)
# 3. Run:
chmod +x setup.sh
sudo ./setup.sh
```

That's it. The script handles everything: Docker build, SSL, cron jobs.

## What Gets Deployed

| Container | Purpose |
|---|---|
| `netmon-demo` | Flask app (Enterprise tier, all features unlocked) |
| `netmon-nginx` | Nginx reverse proxy with SSL |
| `netmon-certbot` | Auto-renews Let's Encrypt certificate |

## Demo Environment

- **23 simulated devices** across Network, Servers, Wireless, Security, Infrastructure, Peripherals
- **Enterprise license** pre-activated — visitors see every feature
- **Login**: `demo` / `TryNetMon2026`
- **Live data**: Simulator generates realistic check results, alerts, and performance data
- **Auto-reset**: Database resets every 6 hours (cron) to stay fresh
- **Auto-update**: Pulls latest code from GitHub daily at 3 AM

## Files

| File | Purpose |
|---|---|
| `setup.sh` | One-shot installer (run once) |
| `docker-compose.yml` | Container orchestration |
| `Dockerfile` | App container build |
| `demo_config.yaml` | Demo config (Enterprise license, simulated devices) |
| `demo_seed.py` | Populates DB with 48h of history, alerts, inventory, scans |
| `demo_simulator.py` | Generates live monitoring data every 30s |
| `entrypoint.sh` | Container startup (seed + simulate + run) |
| `nginx.conf` | HTTPS proxy config |
| `nginx-initial.conf` | HTTP-only config (pre-SSL) |
| `reset-demo.sh` | Resets demo data (called by cron) |

## Management

```bash
# View status
docker compose ps

# View logs
docker compose logs -f netmon-demo

# Manual reset
/opt/netmon-demo/reset-demo.sh

# Manual update from GitHub
cd /opt/netmon-demo && git -C app pull && docker compose build && docker compose up -d

# Stop everything
docker compose down

# Full cleanup
docker compose down -v  # removes volumes too
```
