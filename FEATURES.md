# Clover.tech.netmon - Features Document

**Version:** 5.0
**Build Date:** 2026-05-05
**Product:** Clover.tech.netmon - Network Monitoring System

---

## Product Overview

Clover.tech.netmon is a lightweight, self-hosted network monitoring system built in Python. It provides real-time monitoring of network devices and services with a modern dark-themed web dashboard, email alerting, network discovery, asset inventory management, and enterprise-grade features like host dependencies, performance graphing, alert acknowledgment, and scheduled downtime windows.

---

## Feature Inventory

### Core Monitoring Engine

| Feature | Version | Status |
|---------|---------|--------|
| ICMP Ping Checks | v1 | Active |
| TCP Port Checks | v1 | Active |
| HTTP/HTTPS Endpoint Checks | v1 | Active |
| SNMP GET Checks | v1 | Active |
| Warning/Critical Thresholds (ms) | v1 | Active |
| Configurable Timeout & Retries | v1 | Active |
| Threaded Parallel Check Execution | v1 | Active |
| SQLite Results Storage | v1 | Active |
| Windows TTL-based Ping Validation | v4 | Active |

### Alerting & Notifications

| Feature | Version | Status |
|---------|---------|--------|
| SMTP Email Alerts (HTML + Plain Text) | v1 | Active |
| Alert Cooldown Throttling | v1 | Active |
| Status Change Detection | v1 | Active |
| **Alert Acknowledgment** | **v5** | **New** |
| **Acknowledge All Alerts** | **v5** | **New** |
| **Ack Suppresses Repeat Notifications** | **v5** | **New** |
| **Auto-clear Ack on Recovery** | **v5** | **New** |

### Web Dashboard

| Feature | Version | Status |
|---------|---------|--------|
| Dark-themed Responsive UI | v1 | Active |
| Real-time Status Cards with Color Coding | v1 | Active |
| Auto-refresh (30s interval) | v1 | Active |
| Status / Alerts / History Tabs | v1 | Active |
| Device CRUD via REST API | v2 | Active |
| Live Config Reload (no restart) | v2 | Active |
| Auto-save to config.yaml | v2 | Active |
| Links & Notes per Device | v3 | Active |
| Maintenance Mode Toggle | v3 | Active |
| Device Detail Drawer (slide-out panel) | v3 | Active |
| 24h / 7d / 30d Uptime Percentages | v3 | Active |
| Status Filters & Search | v3 | Active |
| Network Map Tab (vis.js graph) | v4 | Active |
| Discovery Scanner Tab | v4 | Active |
| Manage Devices Tab | v2 | Active |
| Settings Tab (General, Dashboard, SMTP) | v4 | Active |
| Inventory Tab | v4 | Active |
| Test Email from Settings | v4 | Active |
| **Downtime Tab** | **v5** | **New** |
| **Performance Charts (Chart.js)** | **v5** | **New** |
| **Parent Device Selector in Device Modal** | **v5** | **New** |
| **Alert Acknowledge Buttons** | **v5** | **New** |
| **9 Dashboard Tabs** | **v5** | **New** |

### Network Discovery Scanner

| Feature | Version | Status |
|---------|---------|--------|
| CIDR & Range IP Parsing (max 1024) | v4 | Active |
| Threaded Ping Sweep | v4 | Active |
| TCP Port Scanning (11 common ports) | v4 | Active |
| Reverse DNS Lookup | v4 | Active |
| Real-time Scan Progress Bar | v4 | Active |
| One-click Add to Monitoring | v4 | Active |
| Scan History & Past Results | v4 | Active |
| Alive-only Results (filters dead hosts) | v4 | Active |
| Auto-import to Inventory | v4 | Active |

### Asset Inventory

| Feature | Version | Status |
|---------|---------|--------|
| Full Asset Database (IP, hostname, MAC, vendor, model, OS, location, serial, etc.) | v4 | Active |
| Inventory CRUD API | v4 | Active |
| Batch Delete with Checkboxes | v4 | Active |
| Import from Discovery Scan | v4 | Active |
| Inventory Stats Dashboard | v4 | Active |
| Search & Filter by Type/Status | v4 | Active |
| One-click "Monitor" from Inventory | v4 | Active |

### Network Map

| Feature | Version | Status |
|---------|---------|--------|
| Interactive vis.js Network Graph | v4 | Active |
| Color-coded Nodes by Status | v4 | Active |
| Discovered Devices (dashed borders) | v4 | Active |
| Click to Open Device Drawer | v4 | Active |
| Click to Add Discovered Device | v4 | Active |
| Hub Node (Clover.tech) | v4 | Active |
| **Dependency Edges (parent-child lines)** | **v5** | **New** |
| **Directional Arrows on Edges** | **v5** | **New** |
| **Parent Down Status Color** | **v5** | **New** |

### Host & Service Dependencies (NEW in v5)

| Feature | Version | Status |
|---------|---------|--------|
| **Parent Device Field per Device** | **v5** | **New** |
| **Recursive Ancestor Check** | **v5** | **New** |
| **Downstream Alert Suppression** | **v5** | **New** |
| **PARENT DOWN Status Badge** | **v5** | **New** |
| **Skip Checks when Parent is CRITICAL** | **v5** | **New** |
| **Dependency Visualization on Network Map** | **v5** | **New** |
| **Dependencies API Endpoint** | **v5** | **New** |

### Performance Graphing (NEW in v5)

| Feature | Version | Status |
|---------|---------|--------|
| **perf_data Time-series Database Table** | **v5** | **New** |
| **Automatic Data Collection on Every Check** | **v5** | **New** |
| **Chart.js Line Graphs in Device Drawer** | **v5** | **New** |
| **Per-check Response Time Charts** | **v5** | **New** |
| **Color-coded by Status (OK/Warning/Critical)** | **v5** | **New** |
| **Selectable Time Periods (1h, 6h, 24h, 7d)** | **v5** | **New** |
| **Intelligent Downsampling (max 200 points)** | **v5** | **New** |
| **Performance API Endpoint** | **v5** | **New** |

### Alert Acknowledgment (NEW in v5)

| Feature | Version | Status |
|---------|---------|--------|
| **Per-alert Acknowledge Button** | **v5** | **New** |
| **Acknowledge All Unacknowledged** | **v5** | **New** |
| **ACK Badge with Timestamp & User** | **v5** | **New** |
| **In-memory Ack Set (suppresses re-alerting)** | **v5** | **New** |
| **Auto-clear on Recovery** | **v5** | **New** |
| **Acknowledged Alerts Dimmed in UI** | **v5** | **New** |
| **Acknowledge API Endpoints** | **v5** | **New** |

### Scheduled Downtime (NEW in v5)

| Feature | Version | Status |
|---------|---------|--------|
| **Downtime Database Table** | **v5** | **New** |
| **Schedule with Start/End Time + Reason** | **v5** | **New** |
| **Active / Upcoming / Expired Status** | **v5** | **New** |
| **Monitoring Loop Skips Devices in Downtime** | **v5** | **New** |
| **Alert Suppression During Downtime** | **v5** | **New** |
| **Cancel Active/Upcoming Downtimes** | **v5** | **New** |
| **Remove Expired Downtimes** | **v5** | **New** |
| **Dedicated Downtime Dashboard Tab** | **v5** | **New** |
| **Downtime CRUD API** | **v5** | **New** |
| **Downtime Indicator on Network Map** | **v5** | **New** |

### Configuration & Settings

| Feature | Version | Status |
|---------|---------|--------|
| YAML Configuration File | v1 | Active |
| Web-based Settings Editor | v4 | Active |
| General Settings (check interval) | v4 | Active |
| Dashboard Settings (host, port) | v4 | Active |
| SMTP Settings (host, port, TLS, auth) | v4 | Active |
| Test Email Functionality | v4 | Active |
| Hot Reload (no restart needed for devices) | v2 | Active |

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| v1 | 2026-05 | Core monitoring, email alerts, Flask dashboard |
| v2 | 2026-05 | Device CRUD via web, REST API, live config |
| v3 | 2026-05 | Links/Notes, maintenance mode, detail drawer, filters |
| v4 | 2026-05 | Discovery scanner, network map, settings, inventory, alive-only scans, batch delete, Windows ping fix |
| **v5** | **2026-05** | **Host dependencies, performance graphing, alert acknowledgment, scheduled downtime, renamed to Clover.tech.netmon** |

---

## Technical Stack

- **Language:** Python 3.10+
- **Web Framework:** Flask
- **Database:** SQLite (zero config)
- **Charting:** Chart.js 4.x
- **Network Graph:** vis.js 9.x
- **Config Format:** YAML
- **Platforms:** Windows, Linux, macOS

---

## API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Latest check results per device/check |
| GET | `/api/alerts?hours=48` | Alert history |
| POST | `/api/alerts/<id>/acknowledge` | Acknowledge a single alert |
| POST | `/api/alerts/acknowledge-all` | Acknowledge all unacknowledged |
| GET | `/api/history?hours=24` | Full check history |
| GET | `/api/devices` | List all devices |
| GET | `/api/devices/<name>` | Get single device |
| POST | `/api/devices` | Add device |
| PUT | `/api/devices/<name>` | Update device |
| DELETE | `/api/devices/<name>` | Delete device |
| POST | `/api/devices/<name>/maintenance` | Toggle maintenance |
| GET | `/api/devices/<name>/uptime` | 24h/7d/30d uptime |
| GET | `/api/devices/<name>/history` | Device check history |
| GET | `/api/devices/<name>/perf?hours=24` | Performance time-series |
| GET | `/api/dependencies` | Device dependency map |
| GET | `/api/downtime` | List all downtimes |
| POST | `/api/downtime` | Schedule downtime |
| POST | `/api/downtime/<id>/cancel` | Cancel downtime |
| DELETE | `/api/downtime/<id>` | Remove downtime record |
| POST | `/api/scan` | Start network scan |
| GET | `/api/scan/status` | Scan progress |
| GET | `/api/scan/results` | Scan results |
| GET | `/api/scan/history` | Past scans |
| GET | `/api/scan/<id>/results` | Results for specific scan |
| GET | `/api/map/data` | Network map graph data |
| GET | `/api/settings` | Current settings |
| PUT | `/api/settings` | Update settings |
| POST | `/api/settings/test-email` | Send test email |
| GET | `/api/inventory` | List all assets |
| GET | `/api/inventory/<id>` | Get single asset |
| POST | `/api/inventory` | Add asset |
| PUT | `/api/inventory/<id>` | Update asset |
| DELETE | `/api/inventory/<id>` | Delete asset |
| POST | `/api/inventory/batch-delete` | Batch delete assets |
| POST | `/api/inventory/import-scan` | Import scan to inventory |
| GET | `/api/inventory/stats` | Inventory statistics |

---

## Deployment

### Quick Start (Windows)
```
pip install -r requirements.txt
python netmon.py
```
Dashboard: http://localhost:8080

### Quick Start (Linux)
```
pip3 install -r requirements.txt
python3 netmon.py
```

### As a Service (Linux systemd)
```ini
[Unit]
Description=Clover.tech.netmon
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/netmon/netmon.py
WorkingDirectory=/opt/netmon
Restart=always
User=netmon

[Install]
WantedBy=multi-user.target
```

---

*Clover.tech.netmon - Open-source network monitoring for teams that demand reliability.*
