#!/bin/bash
# ============================================================
# MyClover.Tech.NetMon - Demo Setup Script (Traefik Edition)
# ============================================================
# Run this on your Hostinger Ubuntu VPS:
#   chmod +x setup.sh && sudo ./setup.sh
#
# Prerequisites:
#   - Traefik already running (handles SSL + routing)
#   - demo.myclover.tech DNS A record pointing to VPS IP
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "============================================"
echo "  MyClover.Tech.NetMon Demo Setup"
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
cp "$SCRIPT_DIR/Dockerfile" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/docker-compose.yml" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/demo_config.yaml" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/demo_seed.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/demo_simulator.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/entrypoint.sh" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/reset-demo.sh" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/reset-demo.sh"
chmod +x "$INSTALL_DIR/entrypoint.sh"

# Symlink or copy the app source from the repo root
if [ -d "$INSTALL_DIR/app" ]; then
    echo -e "${YELLOW}Updating existing app source from GitHub...${NC}"
    rm -rf "$INSTALL_DIR/app"
fi

echo -e "${YELLOW}Copying app source from repo...${NC}"
mkdir -p "$INSTALL_DIR/app"
# Copy only the app files (not demo-deploy folder)
for item in "$REPO_ROOT"/*; do
    basename_item=$(basename "$item")
    if [ "$basename_item" != "demo-deploy" ] && [ "$basename_item" != ".git" ]; then
        cp -r "$item" "$INSTALL_DIR/app/"
    fi
done
echo -e "${GREEN}[OK]${NC} App source copied"

cd "$INSTALL_DIR"

# Build and start
echo ""
echo -e "${YELLOW}Building Docker container...${NC}"
docker compose build --no-cache
echo -e "${GREEN}[OK]${NC} Build complete"

echo ""
echo -e "${YELLOW}Starting demo...${NC}"
docker compose up -d
echo -e "${GREEN}[OK]${NC} Container running"

# Wait for NetMon to be healthy
echo ""
echo -e "${YELLOW}Waiting for NetMon to start...${NC}"
sleep 10
for i in {1..30}; do
    if docker exec netmon-demo curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null | grep -q "200\|302"; then
        echo -e "${GREEN}[OK]${NC} NetMon is running"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "${YELLOW}[WARN] Health check timed out. Check: docker compose logs${NC}"
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
REPO_DIR="/opt/netmon-repo"
if [ ! -d "$REPO_DIR" ]; then
    git clone https://github.com/jonfulk805-og/MyClover.Tech.NetMon.git "$REPO_DIR"
fi
cd "$REPO_DIR"
git pull origin main
# Copy updated demo files
cp demo-deploy/Dockerfile /opt/netmon-demo/
cp demo-deploy/docker-compose.yml /opt/netmon-demo/
cp demo-deploy/demo_config.yaml /opt/netmon-demo/
cp demo-deploy/demo_seed.py /opt/netmon-demo/
cp demo-deploy/demo_simulator.py /opt/netmon-demo/
cp demo-deploy/entrypoint.sh /opt/netmon-demo/
# Copy updated app files
rm -rf /opt/netmon-demo/app
mkdir -p /opt/netmon-demo/app
for item in "$REPO_DIR"/*; do
    bn=$(basename "$item")
    if [ "$bn" != "demo-deploy" ] && [ "$bn" != ".git" ]; then
        cp -r "$item" /opt/netmon-demo/app/
    fi
done
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
echo "  Demo URL:     https://demo.myclover.tech"
echo "  Login:        demo / TryNetMon2026"
echo ""
echo "  Traefik handles SSL automatically via"
echo "  Let's Encrypt. Certificate will be issued"
echo "  on first HTTPS request to the domain."
echo ""
echo "  Container:    cd /opt/netmon-demo && docker compose ps"
echo "  Logs:         cd /opt/netmon-demo && docker compose logs -f"
echo "  Stop:         cd /opt/netmon-demo && docker compose down"
echo "  Reset data:   /opt/netmon-demo/reset-demo.sh"
echo ""
echo "  Auto-reset:   Every 6 hours (cron)"
echo "  Auto-update:  Daily at 3 AM from GitHub"
echo ""
