# Ubuntu LTS Server Setup — MyClover.Tech.NetMon

Complete guide for deploying MyClover.Tech.NetMon on a fresh Ubuntu LTS server (22.04 or 24.04).

> **Also deploying SentryLog?** See the [Combined NetMon + SentryLog Setup](#combined-netmon--sentrylog-deployment) section at the bottom, or check the [SentryLog repo](https://github.com/jonfulk805-og/myclover.tech.sentrylog) for its standalone guide.

---

## Table of Contents

1. [Server Requirements](#server-requirements)
2. [Base Server Setup](#1-base-server-setup)
3. [Install NetMon](#2-install-netmon)
4. [Run as a systemd Service](#3-run-as-a-systemd-service)
5. [Firewall Configuration](#4-firewall-configuration)
6. [Reverse Proxy with Nginx + SSL](#5-reverse-proxy-with-nginx--ssl)
7. [Stripe Payment Handler](#6-stripe-payment-handler-optional)
8. [SNMP Deep Polling](#7-snmp-deep-polling-enterprise)
9. [Backups](#8-backups)
10. [Updating](#9-updating)
11. [Troubleshooting](#10-troubleshooting)
12. [Combined NetMon + SentryLog Deployment](#combined-netmon--sentrylog-deployment)

---

## Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| **CPU** | 1 core | 2+ cores |
| **RAM** | 512 MB | 1-2 GB |
| **Disk** | 10 GB | 20+ GB |
| **Python** | 3.10+ | 3.12+ |
| **Network** | Port 8080 (web UI) | 443 via Nginx |

> NetMon is lightweight — a $5/mo VPS handles hundreds of devices easily.

---

## 1. Base Server Setup

Start with a fresh Ubuntu LTS install (minimal or server edition).

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install core dependencies
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    net-tools \
    ufw

# Set your timezone (adjust as needed)
sudo timedatectl set-timezone America/Los_Angeles

# Verify Python version (must be 3.10+)
python3 --version
```

### Create a dedicated service user (recommended)

```bash
sudo useradd -r -m -s /bin/bash netmon
```

---

## 2. Install NetMon

```bash
# Create application directory
sudo mkdir -p /opt/myclover/netmon
sudo chown netmon:netmon /opt/myclover/netmon

# Switch to service user
sudo -u netmon -i

# Clone the repository
cd /opt/myclover/netmon
git clone https://github.com/jonfulk805-og/MyClover.Tech.NetMon.git .

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Edit configuration (add your devices)
nano config.yaml
```

### Quick config.yaml example

```yaml
devices:
  - name: "Gateway Router"
    host: "192.168.1.1"
    group: "Network"
    checks:
      - type: ping
        label: "ICMP"
        warning_ms: 20
        critical_ms: 100

  - name: "Web Server"
    host: "10.0.0.5"
    group: "Servers"
    checks:
      - type: http
        label: "HTTP"
        url: "http://10.0.0.5"

  - name: "Switch Core"
    host: "192.168.1.2"
    group: "Network"
    checks:
      - type: ping
        label: "ICMP"
      - type: tcp
        label: "SSH"
        port: 22
```

### Test run

```bash
# Still as netmon user with venv active
python netmon.py
```

Open your browser to `http://YOUR_SERVER_IP:8080` — you should see the dashboard. Press `Ctrl+C` to stop.

---

## 3. Run as a systemd Service

```bash
# Exit back to your admin user
exit

# Create the service file
sudo tee /etc/systemd/system/netmon.service << 'EOF'
[Unit]
Description=MyClover.Tech.NetMon - Network Monitoring
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=netmon
Group=netmon
WorkingDirectory=/opt/myclover/netmon
ExecStart=/opt/myclover/netmon/venv/bin/python netmon.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/myclover/netmon

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable netmon
sudo systemctl start netmon

# Check status
sudo systemctl status netmon

# View live logs
sudo journalctl -u netmon -f
```

---

## 4. Firewall Configuration

```bash
# Allow SSH (so you don't lock yourself out)
sudo ufw allow 22/tcp

# Allow NetMon web UI
sudo ufw allow 8080/tcp

# If using Nginx reverse proxy (see next section)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
sudo ufw status
```

---

## 5. Reverse Proxy with Nginx + SSL

For production deployments with HTTPS:

```bash
# Install Nginx and Certbot
sudo apt install -y nginx certbot python3-certbot-nginx

# Create Nginx site config
sudo tee /etc/nginx/sites-available/netmon << 'EOF'
server {
    listen 80;
    server_name netmon.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (for live updates)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

# Enable the site
sudo ln -s /etc/nginx/sites-available/netmon /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default  # Remove default site (optional)
sudo nginx -t && sudo systemctl reload nginx

# Get free SSL certificate from Let's Encrypt
sudo certbot --nginx -d netmon.yourdomain.com

# Auto-renewal is set up automatically by certbot
```

After SSL is configured, remove the direct 8080 rule if desired:

```bash
sudo ufw delete allow 8080/tcp
```

---

## 6. Stripe Payment Handler (optional)

If you're selling NetMon licenses:

```bash
# Switch to netmon user
sudo -u netmon -i
cd /opt/myclover/netmon
source venv/bin/activate

# Install Stripe SDK
pip install stripe

# Configure Stripe
nano stripe_config.yaml
# Add your Stripe secret key (sk_live_...), SMTP settings, webhook secret (whsec_...)

# Exit back to admin
exit

# Create Stripe handler service
sudo tee /etc/systemd/system/netmon-stripe.service << 'EOF'
[Unit]
Description=MyClover.Tech.NetMon - Stripe Payment Handler
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=netmon
Group=netmon
WorkingDirectory=/opt/myclover/netmon
ExecStart=/opt/myclover/netmon/venv/bin/python stripe_handler.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/myclover/netmon

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable netmon-stripe
sudo systemctl start netmon-stripe
```

Add Nginx config for the Stripe webhook endpoint:

```bash
sudo tee /etc/nginx/sites-available/netmon-stripe << 'EOF'
server {
    listen 80;
    server_name payments.yourdomain.com;

    location /webhook/stripe {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/netmon-stripe /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d payments.yourdomain.com
```

---

## 7. SNMP Deep Polling (Enterprise)

```bash
# Install SNMP tools
sudo apt install -y snmp snmp-mibs-downloader

# Enable MIB translation (optional but helpful)
sudo sed -i 's/^mibs :$/# mibs :/' /etc/snmp/snmp.conf

# Test SNMP connectivity
snmpget -v2c -c public 192.168.1.1 sysDescr.0
```

---

## 8. Backups

### Manual backup

```bash
# Use the built-in backup API
curl -o netmon_backup_$(date +%Y%m%d).zip http://localhost:8080/api/backup
```

### Automated daily backup via cron

```bash
sudo -u netmon crontab -e
```

Add this line:

```
0 2 * * * curl -s -o /opt/myclover/netmon/backups/netmon_$(date +\%Y\%m\%d).zip http://localhost:8080/api/backup && find /opt/myclover/netmon/backups/ -name "*.zip" -mtime +30 -delete
```

This creates a backup at 2 AM daily and cleans up backups older than 30 days.

```bash
# Create backups directory
sudo -u netmon mkdir -p /opt/myclover/netmon/backups
```

---

## 9. Updating

```bash
# Stop the service
sudo systemctl stop netmon

# Switch to netmon user and pull latest
sudo -u netmon -i
cd /opt/myclover/netmon

# Backup first
cp netmon.db netmon.db.bak
cp config.yaml config.yaml.bak

# Pull latest code
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Exit and restart
exit
sudo systemctl start netmon
sudo systemctl status netmon
```

---

## 10. Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u netmon -n 50 --no-pager

# Check if port is in use
sudo ss -tlnp | grep 8080

# Test manually
sudo -u netmon /opt/myclover/netmon/venv/bin/python /opt/myclover/netmon/netmon.py
```

### Permission denied on port 8080

```bash
# The netmon user needs access to the working directory
sudo chown -R netmon:netmon /opt/myclover/netmon
```

### Can't ping devices (ICMP requires root)

```bash
# Option 1: Give Python ping capability
sudo setcap cap_net_raw+ep /opt/myclover/netmon/venv/bin/python3

# Option 2: Run as root (less secure)
# Change User=root in the systemd service file
```

### Database locked errors

```bash
# Stop the service, run integrity check
sudo systemctl stop netmon
sudo -u netmon sqlite3 /opt/myclover/netmon/netmon.db "PRAGMA integrity_check;"
sudo systemctl start netmon
```

### Dashboard loads but shows "Loading..."

- Verify you're using the latest `templates/dashboard.html` from the repo
- Check browser console (F12) for JavaScript errors
- Ensure `netmon.py` and `dashboard.html` versions match

---

## Combined NetMon + SentryLog Deployment

Deploy both products on the same Ubuntu LTS server:

### Directory layout

```
/opt/myclover/
├── netmon/        # NetMon (port 8080)
└── sentrylog/     # SentryLog (port 8514)
```

### Server requirements (combined)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 1 core | 2+ cores |
| **RAM** | 1 GB | 2-4 GB |
| **Disk** | 20 GB | 50+ GB (logs grow) |

### Install both products

```bash
# Base setup (if not done already)
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git curl wget net-tools ufw snmp

# Create shared service user
sudo useradd -r -m -s /bin/bash myclover

# --- NetMon ---
sudo mkdir -p /opt/myclover/netmon
sudo chown myclover:myclover /opt/myclover/netmon
sudo -u myclover bash -c '
    cd /opt/myclover/netmon
    git clone https://github.com/jonfulk805-og/MyClover.Tech.NetMon.git .
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
'

# --- SentryLog ---
sudo mkdir -p /opt/myclover/sentrylog
sudo chown myclover:myclover /opt/myclover/sentrylog
sudo -u myclover bash -c '
    cd /opt/myclover/sentrylog
    git clone https://github.com/jonfulk805-og/myclover.tech.sentrylog.git .
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
'
```

### Enable NetMon integration in SentryLog

Edit `/opt/myclover/sentrylog/sentrylog_config.yaml`:

```yaml
netmon_integration:
  enabled: true
  netmon_url: "http://localhost:8080"
```

### Create systemd services for both

```bash
# NetMon service
sudo tee /etc/systemd/system/netmon.service << 'EOF'
[Unit]
Description=MyClover.Tech.NetMon - Network Monitoring
After=network.target

[Service]
Type=simple
User=myclover
Group=myclover
WorkingDirectory=/opt/myclover/netmon
ExecStart=/opt/myclover/netmon/venv/bin/python netmon.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/myclover/netmon

[Install]
WantedBy=multi-user.target
EOF

# SentryLog service
sudo tee /etc/systemd/system/sentrylog.service << 'EOF'
[Unit]
Description=MyClover.Tech.SentryLog - Log Aggregation
After=network.target netmon.service

[Service]
Type=simple
User=myclover
Group=myclover
WorkingDirectory=/opt/myclover/sentrylog
ExecStart=/opt/myclover/sentrylog/venv/bin/python sentrylog.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/myclover/sentrylog
# Syslog on privileged port 514 requires this:
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Enable and start both
sudo systemctl daemon-reload
sudo systemctl enable netmon sentrylog
sudo systemctl start netmon sentrylog
```

### Firewall (combined)

```bash
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # Nginx HTTP
sudo ufw allow 443/tcp    # Nginx HTTPS
sudo ufw allow 514/udp    # Syslog UDP
sudo ufw allow 514/tcp    # Syslog TCP
sudo ufw enable
```

### Nginx reverse proxy (combined)

```bash
sudo apt install -y nginx certbot python3-certbot-nginx

sudo tee /etc/nginx/sites-available/myclover << 'EOF'
# NetMon
server {
    listen 80;
    server_name netmon.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# SentryLog
server {
    listen 80;
    server_name sentrylog.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8514;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/myclover /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# SSL for both
sudo certbot --nginx -d netmon.yourdomain.com -d sentrylog.yourdomain.com
```

### Point your devices' syslog to SentryLog

On your network devices (routers, switches, firewalls), set the syslog server to:

```
YOUR_SERVER_IP:514 (UDP or TCP)
```

SentryLog will auto-discover sources as logs arrive.

### Verify both are running

```bash
sudo systemctl status netmon sentrylog
curl -s http://localhost:8080/api/status | python3 -m json.tool | head -5
curl -s http://localhost:8514/api/overview | python3 -m json.tool | head -5
```

---

**Built by [MyClover.Tech](https://myclover.tech)**
