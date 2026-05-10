#!/bin/bash
# ============================================================
# MyClover.Tech Suite - Demo Setup Script (Traefik Edition)
# ============================================================
# Run this on your Hostinger Ubuntu VPS:
#   chmod +x setup.sh && sudo ./setup.sh
#
# Prerequisites:
#   - Traefik already running (handles SSL + routing)
#   - demo.myclover.tech DNS A record → VPS IP
#   - logs.demo.myclover.tech DNS A record → VPS IP
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "============================================"
echo "  MyClover.Tech Suite Demo Setup"
echo "  NetMon + SentryLog"
echo "============================================"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo ./setup.sh${NC}"
    exit 1
fi

# Check Docker
if ! command -v docker &>/dev/null; then
    echo -e "${RED}Docker not found!${NC}"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Docker $(docker --version | cut -d' ' -f3)"

# Check Traefik is running
if ! docker ps | grep -q traefik; then
    echo -e "${YELLOW}[WARN] Traefik container not detected. Make sure it's running for SSL.${NC}"
fi

# Determine paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Set up install directory
INSTALL_DIR="/opt/netmon-demo"
mkdir -p "$INSTALL_DIR"

echo ""
echo -e "${YELLOW}Copying deployment files to $INSTALL_DIR...${NC}"
for f in Dockerfile Dockerfile.sentrylog docker-compose.yml \
         demo_config.yaml demo_seed.py demo_simulator.py \
         sentrylog_demo_config.yaml sentrylog_seed.py sentrylog_entrypoint.sh \
         entrypoint.sh reset-demo.sh README.md; do
    if [ -f "$SCRIPT_DIR/$f" ]; then
        cp "$SCRIPT_DIR/$f" "$INSTALL_DIR/"
    fi
done
chmod +x "$INSTALL_DIR/reset-demo.sh" "$INSTALL_DIR/entrypoint.sh" "$INSTALL_DIR/sentrylog_entrypoint.sh"

# Copy NetMon app source
if [ -d "$INSTALL_DIR/app" ]; then
    echo -e "${YELLOW}Updating existing NetMon app source...${NC}"
    rm -rf "$INSTALL_DIR/app"
fi
echo -e "${YELLOW}Copying NetMon app source from repo...${NC}"
mkdir -p "$INSTALL_DIR/app"
for item in "$REPO_ROOT"/*; do
    bn=$(basename "$item")
    if [ "$bn" != "demo-deploy" ] && [ "$bn" != ".git" ]; then
        cp -r "$item" "$INSTALL_DIR/app/"
    fi
done
echo -e "${GREEN}[OK]${NC} NetMon app source copied"

# Clone/update SentryLog repo (private)
SENTRYLOG_REPO="/opt/sentrylog-repo"
echo ""
echo -e "${YELLOW}Setting up SentryLog...${NC}"
if [ -d "$SENTRYLOG_REPO" ]; then
    echo "  Updating SentryLog repo..."
    cd "$SENTRYLOG_REPO" && git pull origin main 2>/dev/null || git pull origin master 2>/dev/null || true
else
    echo "  Cloning SentryLog repo..."
    git clone https://github.com/jonfulk805-og/myclover.tech.sentrylog.git "$SENTRYLOG_REPO" 2>/dev/null || {
        echo -e "${RED}  Could not clone SentryLog repo.${NC}"
        echo -e "${RED}  For private repos, set up a GitHub PAT or deploy key first.${NC}"
        echo -e "${YELLOW}  Trying without SentryLog...${NC}"
        SENTRYLOG_REPO=""
    }
fi

if [ -n "$SENTRYLOG_REPO" ]; then
    rm -rf "$INSTALL_DIR/sentrylog-app"
    mkdir -p "$INSTALL_DIR/sentrylog-app"
    for item in "$SENTRYLOG_REPO"/*; do
        bn=$(basename "$item")
        if [ "$bn" != ".git" ]; then
            cp -r "$item" "$INSTALL_DIR/sentrylog-app/"
        fi
    done
    echo -e "${GREEN}[OK]${NC} SentryLog app source copied"
fi

cd "$INSTALL_DIR"

# Build and start
echo ""
echo -e "${YELLOW}Building Docker containers...${NC}"
docker compose build --no-cache
echo -e "${GREEN}[OK]${NC} Build complete"

echo ""
echo -e "${YELLOW}Starting demo...${NC}"
docker compose up -d
echo -e "${GREEN}[OK]${NC} Containers running"

# Wait for NetMon
echo ""
echo -e "${YELLOW}Waiting for NetMon to start...${NC}"
sleep 10
for i in {1..30}; do
    if docker exec netmon-demo curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null | grep -q "200\|302"; then
        echo -e "${GREEN}[OK]${NC} NetMon is running"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "${YELLOW}[WARN] NetMon health check timed out. Check: docker compose logs netmon-demo${NC}"
    fi
    sleep 2
done

# Wait for SentryLog
echo -e "${YELLOW}Waiting for SentryLog to start...${NC}"
for i in {1..30}; do
    if docker exec sentrylog-demo curl -s -o /dev/null -w "%{http_code}" http://localhost:8514/ 2>/dev/null | grep -q "200\|302"; then
        echo -e "${GREEN}[OK]${NC} SentryLog is running"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "${YELLOW}[WARN] SentryLog health check timed out. Check: docker compose logs sentrylog-demo${NC}"
    fi
    sleep 2
done

# Set up cron for auto-reset every 6 hours
echo ""
echo -e "${YELLOW}Setting up auto-reset cron (every 6 hours)...${NC}"
CRON_LINE="0 */6 * * * /opt/netmon-demo/reset-demo.sh >> /var/log/netmon-demo-reset.log 2>&1"
(crontab -l 2>/dev/null | grep -v 'reset-demo.sh'; echo "$CRON_LINE") | crontab -
echo -e "${GREEN}[OK]${NC} Cron installed"

# Set up auto-update from GitHub (daily at 3 AM)
echo ""
echo -e "${YELLOW}Setting up auto-update from GitHub (daily at 3 AM)...${NC}"
UPDATE_SCRIPT="/opt/netmon-demo/auto-update.sh"
cat > "$UPDATE_SCRIPT" << 'EOFSCRIPT'
#!/bin/bash
set -e
# Update NetMon
REPO_DIR="/opt/netmon-repo"
if [ ! -d "$REPO_DIR" ]; then
    git clone https://github.com/jonfulk805-og/MyClover.Tech.NetMon.git "$REPO_DIR"
fi
cd "$REPO_DIR" && git pull origin main

# Copy updated demo files
for f in Dockerfile Dockerfile.sentrylog docker-compose.yml \
         demo_config.yaml demo_seed.py demo_simulator.py \
         sentrylog_demo_config.yaml sentrylog_seed.py sentrylog_entrypoint.sh \
         entrypoint.sh; do
    [ -f "demo-deploy/$f" ] && cp "demo-deploy/$f" /opt/netmon-demo/
done

# Copy updated NetMon app files
rm -rf /opt/netmon-demo/app
mkdir -p /opt/netmon-demo/app
for item in "$REPO_DIR"/*; do
    bn=$(basename "$item")
    [ "$bn" != "demo-deploy" ] && [ "$bn" != ".git" ] && cp -r "$item" /opt/netmon-demo/app/
done

# Update SentryLog
SL_REPO="/opt/sentrylog-repo"
if [ -d "$SL_REPO" ]; then
    cd "$SL_REPO" && git pull origin main 2>/dev/null || git pull origin master 2>/dev/null || true
    rm -rf /opt/netmon-demo/sentrylog-app
    mkdir -p /opt/netmon-demo/sentrylog-app
    for item in "$SL_REPO"/*; do
        bn=$(basename "$item")
        [ "$bn" != ".git" ] && cp -r "$item" /opt/netmon-demo/sentrylog-app/
    done
fi

cd /opt/netmon-demo
docker compose build --quiet
docker compose up -d
EOFSCRIPT
chmod +x "$UPDATE_SCRIPT"
UPDATE_LINE="0 3 * * * /opt/netmon-demo/auto-update.sh >> /var/log/netmon-demo-update.log 2>&1"
(crontab -l 2>/dev/null | grep -v 'auto-update.sh'; echo "$UPDATE_LINE") | crontab -
echo -e "${GREEN}[OK]${NC} Auto-update cron installed"

# Summary
echo ""
echo -e "${GREEN}============================================"
echo "  SETUP COMPLETE"
echo "============================================${NC}"
echo ""
echo "  NetMon Demo:    https://demo.myclover.tech"
echo "  SentryLog Demo: https://logs.demo.myclover.tech"
echo "  Login:          demo / TryNetMon2026"
echo ""
echo "  Traefik handles SSL automatically via"
echo "  Let's Encrypt for both subdomains."
echo ""
echo "  Containers:     docker compose ps"
echo "  Logs:           docker compose logs -f"
echo "  Stop:           docker compose down"
echo "  Reset data:     /opt/netmon-demo/reset-demo.sh"
echo ""
echo "  Auto-reset:     Every 6 hours (cron)"
echo "  Auto-update:    Daily at 3 AM from GitHub"
echo ""
