#!/usr/bin/env python3
"""
demo_seed.py -- Seed the demo database with realistic historical data.
Run once at container startup or on cron reset.
Populates: check_results, alerts, perf_data, inventory, scan_results,
           scheduled_downtime, security_scans, security_findings.
"""

import sqlite3
import datetime
import random
import json
import os
import hashlib

DB_PATH = os.environ.get("DEMO_DB_PATH", "/app/netmon.db")

# ---------------------------------------------------------------------------
# Device definitions (must match demo_config.yaml)
# ---------------------------------------------------------------------------
DEVICES = [
    {"name": "Edge Firewall", "host": "10.0.1.1", "group": "Network", "checks": [("ping", "ICMP")]},
    {"name": "Core Switch", "host": "10.0.1.2", "group": "Network", "checks": [("ping", "ICMP")]},
    {"name": "Distribution Switch A", "host": "10.0.1.3", "group": "Network", "checks": [("ping", "ICMP")]},
    {"name": "Distribution Switch B", "host": "10.0.1.4", "group": "Network", "checks": [("ping", "ICMP")]},
    {"name": "Wireless Controller", "host": "10.0.1.10", "group": "Network", "checks": [("ping", "ICMP")]},
    {"name": "Office AP-1", "host": "10.0.1.11", "group": "Wireless", "checks": [("ping", "ICMP")]},
    {"name": "Office AP-2", "host": "10.0.1.12", "group": "Wireless", "checks": [("ping", "ICMP")]},
    {"name": "Office AP-3", "host": "10.0.1.13", "group": "Wireless", "checks": [("ping", "ICMP")]},
    {"name": "DC-01 (Domain Controller)", "host": "10.0.2.10", "group": "Servers", "checks": [("ping", "ICMP"), ("port", "DNS"), ("port", "LDAP")]},
    {"name": "DC-02 (Backup DC)", "host": "10.0.2.11", "group": "Servers", "checks": [("ping", "ICMP"), ("port", "DNS"), ("port", "LDAP")]},
    {"name": "File Server", "host": "10.0.2.20", "group": "Servers", "checks": [("ping", "ICMP"), ("port", "SMB")]},
    {"name": "Web Server (IIS)", "host": "10.0.2.30", "group": "Servers", "checks": [("ping", "ICMP"), ("http", "HTTP"), ("port", "HTTPS")]},
    {"name": "SQL Server", "host": "10.0.2.40", "group": "Servers", "checks": [("ping", "ICMP"), ("port", "SQL")]},
    {"name": "Exchange Server", "host": "10.0.2.50", "group": "Servers", "checks": [("ping", "ICMP"), ("port", "SMTP"), ("port", "HTTPS")]},
    {"name": "Backup Server", "host": "10.0.2.60", "group": "Servers", "checks": [("ping", "ICMP")]},
    {"name": "Hypervisor-01", "host": "10.0.2.70", "group": "Servers", "checks": [("ping", "ICMP"), ("port", "Web UI")]},
    {"name": "Hypervisor-02", "host": "10.0.2.71", "group": "Servers", "checks": [("ping", "ICMP"), ("port", "Web UI")]},
    {"name": "VPN Gateway", "host": "10.0.1.5", "group": "Network", "checks": [("ping", "ICMP"), ("port", "WireGuard")]},
    {"name": "IP Camera NVR", "host": "10.0.3.10", "group": "Security", "checks": [("ping", "ICMP"), ("port", "RTSP")]},
    {"name": "VoIP PBX", "host": "10.0.3.20", "group": "Infrastructure", "checks": [("ping", "ICMP"), ("port", "SIP")]},
    {"name": "Printer - Main Office", "host": "10.0.3.30", "group": "Peripherals", "checks": [("ping", "ICMP")]},
    {"name": "Printer - Warehouse", "host": "10.0.3.31", "group": "Peripherals", "checks": [("ping", "ICMP")]},
    {"name": "UPS - Server Room", "host": "10.0.3.40", "group": "Infrastructure", "checks": [("ping", "ICMP"), ("port", "SNMP")]},
]


def init_db(conn):
    """Create tables matching netmon.py schema."""
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS check_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, device_name TEXT NOT NULL, host TEXT NOT NULL,
        check_type TEXT NOT NULL, check_label TEXT, status TEXT NOT NULL,
        response_ms REAL, message TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, device_name TEXT NOT NULL,
        check_type TEXT NOT NULL, check_label TEXT, status TEXT NOT NULL,
        message TEXT, email_sent INTEGER DEFAULT 0,
        acknowledged INTEGER DEFAULT 0, acknowledged_by TEXT DEFAULT '',
        acknowledged_at TEXT DEFAULT ''
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL, timestamp TEXT NOT NULL, ip TEXT NOT NULL,
        hostname TEXT, is_alive INTEGER DEFAULT 0, open_ports TEXT,
        response_ms REAL, added_to_devices INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL, hostname TEXT DEFAULT '', mac_address TEXT DEFAULT '',
        device_type TEXT DEFAULT '', vendor TEXT DEFAULT '', model TEXT DEFAULT '',
        os_info TEXT DEFAULT '', location TEXT DEFAULT '', serial_number TEXT DEFAULT '',
        purchase_date TEXT DEFAULT '', notes TEXT DEFAULT '', open_ports TEXT DEFAULT '',
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_scan_id TEXT DEFAULT '',
        monitored_device TEXT DEFAULT '', status TEXT DEFAULT 'active',
        custom_fields TEXT DEFAULT '{}'
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS perf_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, device_name TEXT NOT NULL,
        check_label TEXT NOT NULL, status TEXT NOT NULL, response_ms REAL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS scheduled_downtime (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL,
        reason TEXT DEFAULT '', created_by TEXT DEFAULT '',
        created_at TEXT NOT NULL, active INTEGER DEFAULT 1
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS security_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL, started_at TEXT NOT NULL,
        finished_at TEXT, targets TEXT NOT NULL, scan_types TEXT NOT NULL,
        status TEXT DEFAULT 'running', summary TEXT DEFAULT '{}'
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS security_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL, target TEXT NOT NULL, category TEXT NOT NULL,
        severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
        details TEXT DEFAULT '{}', remediation TEXT DEFAULT ''
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS helpdesk_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        remote_id TEXT NOT NULL, provider TEXT NOT NULL,
        subject TEXT NOT NULL, description TEXT DEFAULT '',
        status TEXT DEFAULT '', priority TEXT DEFAULT '',
        ticket_type TEXT DEFAULT '', assignee TEXT DEFAULT '',
        requester TEXT DEFAULT '', created_at TEXT DEFAULT '',
        updated_at TEXT DEFAULT '', due_date TEXT DEFAULT '',
        device_name TEXT DEFAULT '', url TEXT DEFAULT '',
        raw_json TEXT DEFAULT '{}', synced_at TEXT NOT NULL
    )""")
    # Indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_results_ts ON check_results(timestamp DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_results_device ON check_results(device_name, check_label)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scan_id ON scan_results(scan_id)")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_ip ON inventory(ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_perf_ts ON perf_data(device_name, check_label, timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_downtime_device ON scheduled_downtime(device_name, start_time)")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_helpdesk_remote ON helpdesk_tickets(provider, remote_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_secscans_id ON security_scans(scan_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_secfindings_scan ON security_findings(scan_id)")
    conn.commit()


def random_mac():
    return ":".join("%02x" % random.randint(0, 255) for _ in range(6))


def seed_check_results(conn, hours=48):
    """Generate check results history for the past N hours."""
    now = datetime.datetime.utcnow()
    rows = []
    perf_rows = []
    interval = 60  # seconds between checks

    for dev in DEVICES:
        for check_type, check_label in dev["checks"]:
            t = now - datetime.timedelta(hours=hours)
            while t <= now:
                ts = t.isoformat()
                # Most checks succeed; ~3% warning, ~1% critical
                roll = random.random()
                if dev["name"] == "Printer - Warehouse":
                    # In maintenance - still generate data but more failures
                    if roll < 0.15:
                        status = "critical"
                        resp_ms = None
                        msg = "Request timed out"
                    elif roll < 0.3:
                        status = "warning"
                        resp_ms = round(random.uniform(80, 150), 1)
                        msg = "High latency"
                    else:
                        status = "ok"
                        resp_ms = round(random.uniform(5, 40), 1)
                        msg = "OK"
                elif roll < 0.01:
                    status = "critical"
                    resp_ms = None
                    msg = "Request timed out" if check_type == "ping" else "Connection refused"
                elif roll < 0.04:
                    status = "warning"
                    resp_ms = round(random.uniform(25, 90), 1)
                    msg = "High latency"
                else:
                    status = "ok"
                    if check_type == "ping":
                        base = {"Network": 2, "Wireless": 8, "Servers": 3,
                                "Security": 5, "Infrastructure": 4, "Peripherals": 12}
                        b = base.get(dev["group"], 5)
                        resp_ms = round(random.gauss(b, b * 0.3), 1)
                        resp_ms = max(0.5, resp_ms)
                    elif check_type == "http":
                        resp_ms = round(random.gauss(45, 15), 1)
                    else:
                        resp_ms = round(random.gauss(3, 1.5), 1)
                        resp_ms = max(0.3, resp_ms)
                    msg = "OK"

                rows.append((ts, dev["name"], dev["host"], check_type,
                             check_label, status, resp_ms, msg))
                perf_rows.append((ts, dev["name"], check_label, status, resp_ms))
                t += datetime.timedelta(seconds=interval)

    conn.executemany(
        "INSERT INTO check_results (timestamp,device_name,host,check_type,check_label,status,response_ms,message) "
        "VALUES (?,?,?,?,?,?,?,?)", rows)
    conn.executemany(
        "INSERT INTO perf_data (timestamp,device_name,check_label,status,response_ms) "
        "VALUES (?,?,?,?,?)", perf_rows)
    conn.commit()
    print(f"  Seeded {len(rows)} check results + perf data ({hours}h history)")


def seed_alerts(conn, hours=72):
    """Generate realistic alert history."""
    now = datetime.datetime.utcnow()
    alerts = []

    # Pre-defined alert scenarios
    scenarios = [
        ("Exchange Server", "port", "SMTP", "critical", "Port 25 connection refused", -2.5, True, "demo"),
        ("Exchange Server", "port", "SMTP", "ok", "Port 25 responsive", -2.3, False, ""),
        ("Printer - Warehouse", "ping", "ICMP", "critical", "Request timed out (5 retries)", -18, True, "admin"),
        ("Printer - Warehouse", "ping", "ICMP", "critical", "Request timed out (5 retries)", -12, False, ""),
        ("Office AP-3", "ping", "ICMP", "warning", "High latency: 89ms (threshold: 50ms)", -8, False, ""),
        ("Office AP-3", "ping", "ICMP", "ok", "Latency returned to normal: 12ms", -7.8, False, ""),
        ("SQL Server", "port", "SQL", "critical", "Port 1433 connection refused", -36, True, "admin"),
        ("SQL Server", "port", "SQL", "ok", "Port 1433 responsive", -35.5, False, ""),
        ("Web Server (IIS)", "http", "HTTP", "critical", "HTTP 503 Service Unavailable", -48, True, "demo"),
        ("Web Server (IIS)", "http", "HTTP", "ok", "HTTP 200 OK", -47.7, False, ""),
        ("File Server", "port", "SMB", "warning", "Slow response: 45ms", -24, False, ""),
        ("IP Camera NVR", "ping", "ICMP", "critical", "Request timed out", -60, True, "admin"),
        ("IP Camera NVR", "ping", "ICMP", "ok", "Restored after 15 minutes", -59.7, False, ""),
        ("UPS - Server Room", "port", "SNMP", "warning", "SNMP response slow: 2100ms", -5, False, ""),
        ("DC-01 (Domain Controller)", "port", "LDAP", "warning", "Slow response: 38ms", -40, False, ""),
        ("Hypervisor-01", "port", "Web UI", "critical", "Port 8006 connection refused", -15, True, "admin"),
        ("Hypervisor-01", "port", "Web UI", "ok", "Port 8006 responsive after reboot", -14.5, False, ""),
        ("VPN Gateway", "port", "WireGuard", "critical", "Port 51820 unreachable", -1.2, False, ""),
        ("VPN Gateway", "port", "WireGuard", "ok", "Port 51820 responsive", -1.0, False, ""),
    ]

    for dev_name, chk_type, chk_label, status, msg, hours_ago, acked, acked_by in scenarios:
        ts = (now + datetime.timedelta(hours=hours_ago)).isoformat()
        ack_at = (now + datetime.timedelta(hours=hours_ago, minutes=random.randint(2, 30))).isoformat() if acked else ""
        alerts.append((ts, dev_name, chk_type, chk_label, status, msg, 1,
                        int(acked), acked_by, ack_at))

    conn.executemany(
        "INSERT INTO alerts (timestamp,device_name,check_type,check_label,status,message,"
        "email_sent,acknowledged,acknowledged_by,acknowledged_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)", alerts)
    conn.commit()
    print(f"  Seeded {len(alerts)} alerts")


def seed_inventory(conn):
    """Populate the asset inventory with realistic data."""
    now = datetime.datetime.utcnow().isoformat()
    first_seen = (datetime.datetime.utcnow() - datetime.timedelta(days=90)).isoformat()

    assets = [
        ("10.0.1.1", "fw-edge-01", random_mac(), "Firewall", "Fortinet", "FortiGate 60F", "FortiOS 7.4.3", "Server Room Rack A", "FGT60F-SN-10284", "2024-03-15", "Primary perimeter firewall", "443,22,8443", "Edge Firewall"),
        ("10.0.1.2", "sw-core-01", random_mac(), "Switch", "Cisco", "Catalyst 9300-48P", "IOS-XE 17.9", "Server Room Rack A", "FCW2438L0AB", "2023-08-22", "48-port PoE+ core switch", "22,23,80,443,161", "Core Switch"),
        ("10.0.1.3", "sw-dist-a", random_mac(), "Switch", "Cisco", "2960X-24PS-L", "IOS 15.2", "Floor 1 IDF", "FOC2134V1K9", "2022-11-10", "Floor 1 distribution", "22,23,80,161", "Distribution Switch A"),
        ("10.0.1.4", "sw-dist-b", random_mac(), "Switch", "Cisco", "2960X-24PS-L", "IOS 15.2", "Floor 2 IDF", "FOC2134V1L2", "2022-11-10", "Floor 2 distribution", "22,23,80,161", "Distribution Switch B"),
        ("10.0.1.10", "udm-pro-01", random_mac(), "Wireless Controller", "Ubiquiti", "Dream Machine Pro", "UniFi OS 3.2", "Server Room Rack B", "UDMPRO-SN-38291", "2024-01-20", "UniFi wireless controller", "22,443,8443", "Wireless Controller"),
        ("10.0.1.11", "ap-lobby", random_mac(), "Access Point", "Ubiquiti", "U6-Pro", "6.6.65", "Lobby ceiling", "U6PRO-SN-19283", "2024-01-20", "", "22", "Office AP-1"),
        ("10.0.1.12", "ap-office", random_mac(), "Access Point", "Ubiquiti", "U6-Pro", "6.6.65", "Open office ceiling", "U6PRO-SN-19284", "2024-01-20", "", "22", "Office AP-2"),
        ("10.0.1.13", "ap-warehouse", random_mac(), "Access Point", "Ubiquiti", "U6-LR", "6.6.65", "Warehouse high-mount", "U6LR-SN-48271", "2024-01-20", "", "22", "Office AP-3"),
        ("10.0.2.10", "dc-01", random_mac(), "Server", "Dell", "PowerEdge R750", "Windows Server 2022", "Server Room Rack B", "DELL-SVC-7382910", "2023-06-15", "Primary AD DC, DNS, DHCP", "53,88,135,389,445,636,3389", "DC-01 (Domain Controller)"),
        ("10.0.2.11", "dc-02", random_mac(), "Server", "Dell", "PowerEdge R750", "Windows Server 2022", "Server Room Rack B", "DELL-SVC-7382911", "2023-06-15", "Secondary AD DC", "53,88,135,389,445,636,3389", "DC-02 (Backup DC)"),
        ("10.0.2.20", "nas-01", random_mac(), "NAS", "Synology", "RS1221+", "DSM 7.2.1", "Server Room Rack C", "SYN-RS1221-29481", "2023-01-10", "48TB RAID6 file storage", "22,80,443,445,5001", "File Server"),
        ("10.0.2.30", "web-01", random_mac(), "Server", "HP", "ProLiant DL380 Gen10", "Windows Server 2022", "Server Room Rack B", "HP-SVC-9182734", "2022-09-01", "IIS web applications", "80,443,3389", "Web Server (IIS)"),
        ("10.0.2.40", "sql-01", random_mac(), "Server", "Dell", "PowerEdge R750", "Windows Server 2022", "Server Room Rack C", "DELL-SVC-8472910", "2023-06-15", "SQL Server 2022 Standard", "1433,3389", "SQL Server"),
        ("10.0.2.50", "exch-01", random_mac(), "Server", "Dell", "PowerEdge R750xs", "Windows Server 2022", "Server Room Rack C", "DELL-SVC-5738291", "2023-03-20", "Exchange 2019 on-prem", "25,80,443,587,993,995,3389", "Exchange Server"),
        ("10.0.2.60", "backup-01", random_mac(), "Server", "HP", "ProLiant DL380 Gen10", "Windows Server 2022", "Server Room Rack D", "HP-SVC-2839174", "2022-09-01", "Veeam B&R v12", "9443,3389", "Backup Server"),
        ("10.0.2.70", "pve-01", random_mac(), "Hypervisor", "Dell", "PowerEdge R760", "Proxmox VE 8.2", "Server Room Rack D", "DELL-SVC-6482910", "2024-06-01", "128GB RAM, Dual Xeon Gold", "22,8006", "Hypervisor-01"),
        ("10.0.2.71", "pve-02", random_mac(), "Hypervisor", "Dell", "PowerEdge R760", "Proxmox VE 8.2", "Server Room Rack D", "DELL-SVC-6482911", "2024-06-01", "128GB RAM, Dual Xeon Gold", "22,8006", "Hypervisor-02"),
        ("10.0.1.5", "vpn-01", random_mac(), "VPN Gateway", "Linux", "Custom WireGuard", "Ubuntu 24.04 LTS", "Server Room Rack A", "", "2024-02-28", "WireGuard remote access VPN", "22,51820", "VPN Gateway"),
        ("10.0.3.10", "nvr-01", random_mac(), "NVR", "Hikvision", "DS-7616NI-K2", "V4.62", "Security closet", "HIK-NVR-19284", "2023-09-15", "16-channel NVR", "80,554,8000", "IP Camera NVR"),
        ("10.0.3.20", "pbx-01", random_mac(), "PBX", "3CX", "Dedicated", "3CX v20", "Server Room Rack A", "", "2024-04-01", "3CX Phone System - 50 extensions", "80,443,5001,5060,5061", "VoIP PBX"),
        ("10.0.3.30", "prn-office", random_mac(), "Printer", "HP", "LaserJet Enterprise M507", "2506A", "Main office - copy room", "CNBRF29381", "2023-05-10", "", "80,443,9100,515", "Printer - Main Office"),
        ("10.0.3.31", "prn-warehouse", random_mac(), "Printer", "Zebra", "ZT411", "V82.20.15Z", "Warehouse shipping desk", "ZBR-ZT411-8291", "2024-07-20", "Label printer - in maintenance", "80,9100", "Printer - Warehouse"),
        ("10.0.3.40", "ups-sr", random_mac(), "UPS", "APC", "Smart-UPS SRT3000", "UPS 11.0", "Server Room Rack A", "APC-SRT3K-29481", "2022-06-01", "3000VA - SNMP card installed", "80,161", "UPS - Server Room"),
    ]

    for a in assets:
        try:
            conn.execute(
                "INSERT INTO inventory (ip,hostname,mac_address,device_type,vendor,model,"
                "os_info,location,serial_number,purchase_date,notes,open_ports,"
                "first_seen,last_seen,last_scan_id,monitored_device,status) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (*a, first_seen, now, "demo-seed", a[12] if len(a) > 12 else "", "active"))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    print(f"  Seeded {len(assets)} inventory assets")


def seed_scan_results(conn):
    """Create a recent network discovery scan."""
    now = datetime.datetime.utcnow()
    scan_id = "demo-scan-" + now.strftime("%Y%m%d")
    scan_ts = (now - datetime.timedelta(hours=3)).isoformat()

    # Scan the 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24 subnets
    results = []
    for dev in DEVICES:
        ports = []
        for ct, cl in dev["checks"]:
            if ct == "port":
                port_map = {"DNS": 53, "LDAP": 389, "SMB": 445, "HTTP": 80,
                            "HTTPS": 443, "SQL": 1433, "SMTP": 25, "Web UI": 8006,
                            "WireGuard": 51820, "RTSP": 554, "SIP": 5060,
                            "SNMP": 161}
                if cl in port_map:
                    ports.append(port_map[cl])
            elif ct == "http":
                ports.append(80)
        # Always include common ports for alive hosts
        ports.extend([22])
        ports = sorted(set(ports))
        resp_ms = round(random.gauss(5, 2), 1)
        results.append((scan_id, scan_ts, dev["host"], dev["name"].split(" ")[0].lower(),
                         1, json.dumps(ports), max(0.5, resp_ms), 1))

    # Add some extra "unknown" IPs found in the scan
    extras = [
        ("10.0.1.50", "unknown-50", [22, 80]),
        ("10.0.1.51", "unknown-51", [22]),
        ("10.0.3.50", "cam-01", [80, 554]),
        ("10.0.3.51", "cam-02", [80, 554]),
        ("10.0.3.52", "cam-03", [80, 554]),
    ]
    for ip, hostname, ports in extras:
        results.append((scan_id, scan_ts, ip, hostname, 1,
                         json.dumps(ports), round(random.gauss(8, 3), 1), 0))

    conn.executemany(
        "INSERT INTO scan_results (scan_id,timestamp,ip,hostname,is_alive,open_ports,response_ms,added_to_devices) "
        "VALUES (?,?,?,?,?,?,?,?)", results)
    conn.commit()
    print(f"  Seeded {len(results)} scan results (scan: {scan_id})")


def seed_downtime(conn):
    """Create scheduled downtime entries."""
    now = datetime.datetime.utcnow()
    entries = [
        ("Printer - Warehouse", (now - datetime.timedelta(days=2)).isoformat(),
         (now + datetime.timedelta(days=5)).isoformat(),
         "Paper jam repair - awaiting parts", "admin",
         (now - datetime.timedelta(days=2)).isoformat(), 1),
        ("Backup Server", (now + datetime.timedelta(hours=6)).isoformat(),
         (now + datetime.timedelta(hours=10)).isoformat(),
         "Scheduled Veeam update to v12.2", "admin",
         now.isoformat(), 1),
        ("Core Switch", (now - datetime.timedelta(days=7)).isoformat(),
         (now - datetime.timedelta(days=7, hours=-2)).isoformat(),
         "IOS-XE firmware update", "admin",
         (now - datetime.timedelta(days=8)).isoformat(), 0),
    ]
    conn.executemany(
        "INSERT INTO scheduled_downtime (device_name,start_time,end_time,reason,created_by,created_at,active) "
        "VALUES (?,?,?,?,?,?,?)", entries)
    conn.commit()
    print(f"  Seeded {len(entries)} downtime entries")


def seed_security_scan(conn):
    """Create a completed security scan with findings."""
    now = datetime.datetime.utcnow()
    scan_id = "sec-demo-001"
    started = (now - datetime.timedelta(hours=6)).isoformat()
    finished = (now - datetime.timedelta(hours=5, minutes=45)).isoformat()
    targets = "10.0.1.0/24,10.0.2.0/24,10.0.3.0/24"
    scan_types = "ports,ssl,headers,services,snmp,dns"

    summary = json.dumps({
        "total_targets": 23,
        "scanned": 23,
        "total_findings": 8,
        "by_severity": {"critical": 1, "high": 2, "medium": 3, "low": 2}
    })

    conn.execute(
        "INSERT INTO security_scans (scan_id,started_at,finished_at,targets,scan_types,status,summary) "
        "VALUES (?,?,?,?,?,?,?)",
        (scan_id, started, finished, targets, scan_types, "completed", summary))

    findings = [
        (scan_id, "10.0.3.10", "services", "critical",
         "Telnet service enabled on NVR",
         "Hikvision NVR at 10.0.3.10 has Telnet (port 23) open. Telnet transmits credentials in plaintext.",
         json.dumps({"port": 23, "service": "telnet"}),
         "Disable Telnet on the NVR. Use SSH or HTTPS for management access."),
        (scan_id, "10.0.2.50", "ssl", "high",
         "SSL certificate expires in 12 days",
         "The SSL certificate on Exchange Server (10.0.2.50:443) expires on 2026-05-22.",
         json.dumps({"port": 443, "expiry": "2026-05-22", "cn": "mail.example.com"}),
         "Renew the SSL certificate before expiration to prevent mail client warnings."),
        (scan_id, "10.0.2.30", "headers", "high",
         "Missing security headers on web server",
         "IIS web server at 10.0.2.30 is missing Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security headers.",
         json.dumps({"missing": ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]}),
         "Configure IIS to send security headers. Add a web.config with appropriate HTTP response headers."),
        (scan_id, "10.0.3.40", "snmp", "medium",
         "SNMP using default 'public' community string",
         "UPS SNMP agent at 10.0.3.40 responds to the default 'public' community string.",
         json.dumps({"community": "public"}),
         "Change the SNMP community string to a unique value. Consider upgrading to SNMPv3."),
        (scan_id, "10.0.1.3", "services", "medium",
         "Telnet enabled on distribution switch",
         "Cisco 2960X at 10.0.1.3 has Telnet (port 23) open alongside SSH.",
         json.dumps({"port": 23}),
         "Disable Telnet: 'no ip telnet server'. Use SSH only for management."),
        (scan_id, "10.0.2.30", "ssl", "medium",
         "TLS 1.0 and 1.1 supported",
         "Web server at 10.0.2.30:443 supports deprecated TLS 1.0 and TLS 1.1 protocols.",
         json.dumps({"port": 443, "protocols": ["TLSv1.0", "TLSv1.1"]}),
         "Disable TLS 1.0 and 1.1 in IIS. Require TLS 1.2 minimum."),
        (scan_id, "10.0.1.1", "headers", "low",
         "FortiGate admin page exposes server version",
         "The management interface at 10.0.1.1:443 reveals FortiOS version in HTTP headers.",
         json.dumps({"header": "Server: FortiGate"}),
         "This is informational. Restrict admin access to management VLAN only."),
        (scan_id, "10.0.3.30", "services", "low",
         "Printer has web interface on HTTP (no HTTPS)",
         "HP LaserJet at 10.0.3.30 serves its management page over unencrypted HTTP.",
         json.dumps({"port": 80}),
         "Enable HTTPS on the printer if supported. Restrict access to the management VLAN."),
    ]

    conn.executemany(
        "INSERT INTO security_findings (scan_id,target,category,severity,title,description,details,remediation) "
        "VALUES (?,?,?,?,?,?,?,?)", findings)
    conn.commit()
    print(f"  Seeded security scan with {len(findings)} findings")


def seed_helpdesk_tickets(conn):
    """Create sample helpdesk tickets."""
    now = datetime.datetime.utcnow()
    tickets = [
        ("FS-1042", "freshservice", "Exchange SMTP port down",
         "Alert: Exchange Server port 25 connection refused. Email delivery may be impacted.",
         "Open", "High", "Incident", "Jon F.", "NetMon Auto", 
         (now - datetime.timedelta(hours=2)).isoformat(),
         (now - datetime.timedelta(hours=2)).isoformat(),
         (now + datetime.timedelta(days=1)).isoformat(),
         "Exchange Server", "https://helpdesk.example.com/tickets/1042"),
        ("FS-1038", "freshservice", "Printer - Warehouse offline",
         "Printer - Warehouse has been critical for 3+ days. Paper jam reported. Parts ordered.",
         "Pending", "Medium", "Incident", "Tech Support", "NetMon Auto",
         (now - datetime.timedelta(days=3)).isoformat(),
         (now - datetime.timedelta(hours=12)).isoformat(),
         (now + datetime.timedelta(days=4)).isoformat(),
         "Printer - Warehouse", "https://helpdesk.example.com/tickets/1038"),
        ("FS-1035", "freshservice", "SSL certificate renewal - Exchange",
         "SSL cert on Exchange expires 2026-05-22. Needs renewal before expiry.",
         "Open", "High", "Service Request", "Jon F.", "Security Team",
         (now - datetime.timedelta(days=5)).isoformat(),
         (now - datetime.timedelta(days=5)).isoformat(),
         (now + datetime.timedelta(days=10)).isoformat(),
         "Exchange Server", "https://helpdesk.example.com/tickets/1035"),
        ("FS-1030", "freshservice", "Veeam update scheduled",
         "Scheduled update of Veeam B&R to v12.2. Downtime window: 6 hours.",
         "Planned", "Low", "Change", "Backup Admin", "Jon F.",
         (now - datetime.timedelta(days=7)).isoformat(),
         (now - datetime.timedelta(days=1)).isoformat(),
         (now + datetime.timedelta(hours=10)).isoformat(),
         "Backup Server", "https://helpdesk.example.com/tickets/1030"),
        ("FS-1025", "freshservice", "NVR Telnet security finding",
         "Security scan found Telnet enabled on Hikvision NVR. Must be disabled.",
         "Resolved", "Medium", "Incident", "Network Admin", "Security Scan",
         (now - datetime.timedelta(days=10)).isoformat(),
         (now - datetime.timedelta(days=8)).isoformat(), "",
         "IP Camera NVR", "https://helpdesk.example.com/tickets/1025"),
    ]

    for t in tickets:
        try:
            conn.execute(
                "INSERT INTO helpdesk_tickets (remote_id,provider,subject,description,"
                "status,priority,ticket_type,assignee,requester,"
                "created_at,updated_at,due_date,device_name,url,raw_json,synced_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (*t, "{}", now.isoformat()))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    print(f"  Seeded {len(tickets)} helpdesk tickets")


def main():
    print("=== MyClover.Tech.NetMon Demo Seed ===")
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"  Removed old database: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    print("  Database initialized")

    seed_check_results(conn, hours=48)
    seed_alerts(conn, hours=72)
    seed_inventory(conn)
    seed_scan_results(conn)
    seed_downtime(conn)
    seed_security_scan(conn)
    seed_helpdesk_tickets(conn)

    conn.close()
    print("=== Seed complete ===")


if __name__ == "__main__":
    main()
