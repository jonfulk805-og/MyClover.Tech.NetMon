# MyClover.Tech.NetMon v5.7

**Lightweight, self-hosted network monitoring — up and running in 60 seconds.**

MyClover.Tech.NetMon is a Python-based network monitoring system with a skinnable web dashboard, multi-protocol checks, real-time alerting, network discovery, security scanning, and enterprise features like host dependencies, performance graphing, and role-based access control.

🌐 **Website:** [myclover.tech](https://myclover.tech)

---

## Pricing

| | Community (Free) | Pro | Enterprise |
|---|---|---|---|
| **Monthly** | $0 | **$15/mo** | **$39/mo** |
| **Annual** | $0 | **$150/yr** (save 17%) | **$390/yr** (save 17%) |
| **Devices** | 10 devices / 100 sensors | Unlimited | Unlimited |

> 💡 **Save more with bundles!** Get NetMon + [SentryLog](https://github.com/jonfulk805-og/myclover.tech.sentrylog) together:
> - **Suite Pro Bundle:** $25/mo or $250/yr
> - **Suite Enterprise Bundle:** $59/mo or $590/yr
>
> **MSP / Managed Service Provider pricing** also available — per-customer rates for IT service providers. [Contact us](mailto:inforequest@myclover.tech) for details.

---

## Features

### Community Edition (Free — up to 10 devices / 100 sensors)

- **Multi-protocol monitoring** — ICMP ping, TCP port, HTTP/HTTPS, SNMP
- **9-tab web dashboard** — Status, Alerts, History, Devices, Settings, and more
- **Real-time status** — Auto-refresh with color-coded OK / Warning / Critical indicators
- **Email alerts** — SMTP notifications with cooldown throttling
- **Device management** — Add, edit, delete devices via the web UI
- **6 visual skins** — Midnight, Light, Corporate Blue, Matrix/Cyber, Amber NOC, Solarized Dark
- **Dashboard customization** — Default tab, card density, auto-refresh interval, summary bar toggle
- **Automatic local timezone** — All timestamps auto-convert to the user's browser timezone
- **SQLite storage** — Zero-config database, no external dependencies
- **REST API** — 40+ endpoints for full programmatic control
- **YAML configuration** — Human-readable config file

### Pro Edition ($15/mo) — Unlimited devices & sensors

Everything in Community, plus:

- **Asset Inventory** — Full CRUD, batch operations, search & filter
- **Network Map** — Interactive vis.js topology graph
- **Network Discovery** — CIDR sweep, port scanning, one-click import
- **Performance Graphing** — Chart.js time-series (1h to 7d)
- **Host Dependencies** — Parent-child relationships, downstream alert suppression
- **Scheduled Downtime** — Maintenance windows with alert suppression
- **Multi-channel Alerts** — Slack, Teams, PagerDuty webhooks
- **Drag-and-drop tab reordering** — Customize tab order and visibility
- **Custom accent color** — 7 presets + native color picker
- **Pinned/favorite devices** — Quick access to critical hosts
- **Per-card layout options** — Grid or list view per section
- **Custom dashboard widgets** — 4 quick-stats panels (uptime, response, device count, alerts)

### Enterprise Edition ($39/mo)

Everything in Pro, plus:

- **Security Scanner** — 6 scan modules: ports, SSL/TLS, HTTP headers, services, SNMP, DNS
- **Clickable service links** — One-click RDP, SSH, VNC, HTTP/HTTPS from device cards
- **User Authentication** — JWT-based auth with admin/operator/viewer roles
- **SNMP Deep Polling** — CPU, memory, disk, interface utilization
- **SLA & Uptime Reports** — Generate reports with CSV export
- **NOC/TV Display Mode** — Full-screen wall display at `/noc`
- **Custom Check Plugins** — Drop-in Python scripts in `plugins/`
- **PagerDuty / SMS Integration**
- **Priority support**

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
| Status | Live device status with color-coded cards | Community |
| Alerts | Alert history with acknowledgment | Community |
| History | Full check history timeline | Community |
| Manage Devices | Add/edit/delete devices | Community |
| Settings | General, SMTP, license config | Community |
| Discovery | Network scanner with auto-import | Pro |
| Network Map | Interactive topology graph | Pro |
| Inventory | Asset management database | Pro |
| Downtime | Scheduled maintenance windows | Pro |
| Security | Security vulnerability scanner (6 modules) | Enterprise |
| Reports | SLA & uptime reports with CSV export | Enterprise |

---

## NOC / TV Display Mode

Access the full-screen NOC display at `http://localhost:8080/noc` — designed for wall-mounted monitors. Auto-refreshes every 10 seconds with critical devices sorted to the top.

---

## Custom Check Plugins

Drop Python scripts into the `plugins/` directory. Use check type `"plugin"` in your device config:

```yaml
checks:
  - type: plugin
    label: "Disk Space"
    plugin: "check_disk_space.py"
```

Plugins receive `--host <hostname>` and must print JSON:

```json
{"status": "OK", "message": "Disk usage: 45%", "response_ms": 1.23}
```

See `plugins/check_disk_space.py` for a working example.

---

## Stripe Payment Integration

`stripe_handler.py` provides automated license key fulfillment:

- Stripe Checkout sessions for Pro and Enterprise tiers
- Webhook fulfillment with automatic license key generation and email delivery
- Customer self-service portal
- Admin endpoints for order management

See `stripe_config.yaml` for configuration.

---

## License Activation

After purchase, you'll receive a license key by email. Paste it into **Settings > License > Activate** in the dashboard to unlock your tier.

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
```

See [FEATURES.md](FEATURES.md) for the complete endpoint reference.

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
myclover.tech.netmon/
├── netmon.py              # Main application (3,400+ lines)
├── stripe_handler.py      # Stripe payment integration
├── config.yaml            # Monitoring configuration
├── stripe_config.yaml     # Stripe/payment configuration
├── requirements.txt       # Python dependencies
├── FEATURES.md            # Detailed feature documentation
├── plugins/               # Custom check plugins
│   └── check_disk_space.py
└── templates/
    ├── dashboard.html     # Main web dashboard
    └── noc.html           # NOC/TV display mode
```

---

## Part of the MyClover.Tech Suite

| Product | Description |
|---------|-------------|
| **[NetMon](https://github.com/jonfulk805-og/MyClover.Tech.NetMon)** | Network monitoring, alerting & security scanning |
| **[SentryLog](https://github.com/jonfulk805-og/myclover.tech.sentrylog)** | Log aggregation & security alert platform |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

**Built by [MyClover.Tech](https://myclover.tech)**
