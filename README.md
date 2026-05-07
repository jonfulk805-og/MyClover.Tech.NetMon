# 🍀 MyClover.Tech.netmon v5.3

**Lightweight, self-hosted network monitoring — up and running in 60 seconds.**

MyClover.Tech.netmon v5.3 is a Python-based network monitoring system with a modern dark-themed web dashboard, multi-protocol checks, real-time alerting, network discovery, security scanning, and enterprise features like host dependencies, performance graphing, and role-based access control.

🌐 **Website:** [myclover.tech](https://myclover.tech)

---

## Features

### Community Edition (Free — up to 10 devices)

- **Multi-protocol monitoring** — ICMP ping, TCP port, HTTP/HTTPS, SNMP
- **12-tab web dashboard** — Status, Alerts, History, Devices, Settings, Help, and more
- **Real-time status** — Auto-refresh with color-coded OK / Warning / Critical indicators
- **Email alerts** — SMTP notifications with cooldown throttling
- **Device management** — Add, edit, delete devices via the web UI or config file
- **SQLite storage** — Zero-config database, no external dependencies
- **REST API** — 40+ read-only endpoints for monitoring integration
- **YAML configuration** — Human-readable config file
- **Built-in Help** — Searchable help tab with 17 documented topics, troubleshooting, and API reference

### Pro Edition ($29/mo) — Up to 500 devices

Everything in Community, plus:

- **Asset Inventory** — Full CRUD, batch operations, search & filter
- **Network Map** — Interactive vis.js topology graph with dependency arrows
- **Network Discovery** — CIDR sweep, port scanning, reverse DNS, one-click import
- **Performance Graphing** — Chart.js time-series (1h to 7d) with threshold coloring
- **Host Dependencies** — Parent-child relationships, recursive downstream alert suppression
- **Scheduled Downtime** — Maintenance windows with automatic alert suppression
- **REST API Write Access** — Full read/write access to all 40+ endpoints

### Enterprise Edition ($99/mo) — Unlimited devices

Everything in Pro, plus:

- **Security Scanner** — 6-module passive security analysis (port scan, SSL/TLS, HTTP headers, SNMP, DNS, service vulnerabilities) with severity-rated findings
- **NOC/TV Display Mode** — Full-screen wall display at `/noc` with auto-refresh
- **Multi-Channel Notifications** — Slack, Microsoft Teams, PagerDuty, and generic webhooks
- **SLA & Uptime Reports** — Generate reports with CSV export for any time period
- **User Authentication & RBAC** — JWT-based auth with admin/operator/viewer roles
- **SNMP Deep Polling** — CPU load, memory, disk, and interface utilization
- **Custom Check Plugins** — Drop-in Python scripts in `plugins/`
- **Multi-recipient Alerts** — Send to multiple email addresses simultaneously

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure your devices

Edit `config.yaml` to add your network devices:

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
    parent: "Gateway Router"
    checks:
      - type: http
        label: "HTTP"
        url: "http://10.0.0.5"
        expected_code: 200
      - type: port
        label: "SSH"
        port: 22
```

### 3. Start monitoring

```bash
python netmon.py
```

Open your browser to **http://localhost:8080** — that's it!

---

## Dashboard Tabs

| Tab | Description | Tier |
|-----|-------------|------|
| Status | Live device status with color-coded cards and detail drawer | Community |
| Alerts | Alert history with per-alert and bulk acknowledgment | Community |
| History | Full check history timeline | Community |
| Manage Devices | Add/edit/delete devices with check configuration | Community |
| Settings | General, SMTP, license, webhook configuration | Community |
| Help | Searchable documentation with 17 topics and troubleshooting | Community |
| Discovery | Network scanner with CIDR sweep and auto-import | Pro |
| Network Map | Interactive vis.js topology graph | Pro |
| Inventory | Asset management with batch operations | Pro |
| Downtime | Scheduled maintenance windows | Pro |
| Reports | SLA & uptime reports with CSV export | Enterprise |
| Security | 6-module security scanner with findings dashboard | Enterprise |

---

## Security Scanner

The built-in security scanner performs non-destructive, passive analysis of your network:

| Module | What It Checks |
|--------|---------------|
| Port Scan | 33 common ports with banner grabbing and service ID |
| SSL/TLS | Certificate expiry, weak protocols, weak ciphers, trust validation |
| HTTP Headers | 7 critical security headers, server info disclosure |
| Services | FTP anon, Telnet, RDP, exposed DBs, Redis, VNC, SMB |
| SNMP | 10 default community strings |
| DNS | Zone transfer (AXFR) vulnerability |

Findings are rated by severity (Critical, High, Medium, Low, Info) with remediation guidance. Scans can be stopped mid-run and partial results are preserved.

---

## NOC / TV Display Mode

Access the full-screen NOC display at `http://localhost:8080/noc` — designed for wall-mounted monitors. Auto-refreshes every 10 seconds with critical devices sorted to the top.

---

## Custom Check Plugins

Drop Python scripts into the `plugins/` directory. Plugins receive `--host <hostname>` and must print JSON:

```json
{"status": "ok", "message": "Disk usage: 45%", "metrics": {"disk_percent": 45}}
```

See `plugins/check_disk_space.py` for a working example. List available plugins via `GET /api/plugins`.

---

## Multi-Channel Notifications (Enterprise)

Send alerts to multiple channels simultaneously:

```yaml
webhooks:
  - type: slack
    url: "https://hooks.slack.com/services/T.../B.../xxx"
  - type: teams
    url: "https://outlook.office.com/webhook/..."
  - type: pagerduty
    routing_key: "your-events-api-v2-key"
  - type: generic
    url: "https://your-endpoint.com/webhook"
```

Configure via `config.yaml` or the Settings tab. Test webhooks from the API.

---

## License Activation

License keys are delivered via email after purchase at [myclover.tech](https://myclover.tech). To activate:

1. Open the dashboard and go to **Settings > License**
2. Paste your license key and click **Activate**
3. All features for your tier unlock immediately

Keys are validated locally — no internet connection required.

---

## API Reference

Full REST API with 40+ endpoints. Examples:

```bash
# Get all device statuses
curl http://localhost:8080/api/status

# Add a device
curl -X POST http://localhost:8080/api/devices \
  -H "Content-Type: application/json" \
  -d '{"name": "Web Server", "host": "10.0.0.5", "checks": [{"type": "http", "url": "http://10.0.0.5"}]}'

# Get SLA report as CSV
curl "http://localhost:8080/api/reports/sla?hours=720&format=csv"

# Start a security scan
curl -X POST http://localhost:8080/api/security/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.1"], "types": ["ports", "ssl", "http_headers"]}'

# Get current license info
curl http://localhost:8080/api/license
```

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Latest check results per device |
| GET | `/api/alerts` | Alert history (default 48h) |
| GET | `/api/history` | Full check history (default 24h) |
| GET/POST | `/api/devices` | List/add devices |
| PUT/DELETE | `/api/devices/<name>` | Update/delete a device |
| GET/PUT | `/api/settings` | Current settings |
| GET/POST | `/api/license` | License info / activate key |

### Pro Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices/<name>/perf` | Performance time-series |
| GET | `/api/dependencies` | Dependency map |
| GET/POST | `/api/downtime` | List/schedule downtime |
| POST | `/api/scan` | Start network discovery |
| GET/POST | `/api/inventory` | Asset inventory |
| GET | `/api/map/data` | Network map data |

### Enterprise Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/security/scan` | Start security scan |
| GET | `/api/security/scans` | List all security scans |
| POST | `/api/security/cancel` | Cancel running scan |
| GET | `/api/reports/sla` | SLA uptime report |
| GET | `/api/noc/data` | NOC display data |
| GET/PUT | `/api/webhooks` | Webhook configuration |
| POST | `/api/auth/login` | User login (get token) |
| GET | `/api/plugins` | List available plugins |
| GET | `/api/devices/<name>/snmp` | SNMP deep poll |

See [FEATURES.md](FEATURES.md) for the complete endpoint reference.

---

## Configuration

### config.yaml

```yaml
license_key: ""                # Your license key here
check_interval_seconds: 60

dashboard:
  host: 0.0.0.0
  port: 8080

smtp:
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  use_tls: true
  username: ""
  password: ""
  from_addr: "netmon@yourdomain.com"
  recipients: []
  cooldown_minutes: 15

users: []                      # Enterprise RBAC
webhooks: []                   # Enterprise notifications

devices: []
```

Most settings can be changed via the dashboard and are applied immediately without restarting.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| Web Framework | Flask |
| Database | SQLite |
| Charting | Chart.js 4.x |
| Network Graph | vis.js 9.x |
| Config | YAML |
| Auth | JWT (PyJWT) |
| Payments | Stripe |

---

## Deployment

### Linux systemd Service

```ini
[Unit]
Description=MyClover.Tech.netmon
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/netmon/netmon.py
WorkingDirectory=/opt/netmon
Restart=always
User=netmon

[Install]
WantedBy=multi-user.target
```

### Windows

Run directly or set up as a Windows Service using [NSSM](https://nssm.cc/).

---

## Project Structure

```
MyClover.Tech.NetMon/
├── netmon.py              # Main application (3,400+ lines)
├── stripe_handler.py      # Stripe payment integration
├── config.yaml            # Monitoring configuration
├── stripe_config.yaml     # Stripe/payment configuration
├── requirements.txt       # Python dependencies
├── FEATURES.md            # Detailed feature documentation
├── LICENSE                # MIT License
├── plugins/
│   └── check_disk_space.py
└── templates/
    ├── dashboard.html     # Main web dashboard (12 tabs)
    └── noc.html           # NOC/TV display mode
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

**Built by [MyClover.Tech](https://myclover.tech)** 🍀
