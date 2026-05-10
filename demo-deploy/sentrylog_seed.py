#!/usr/bin/env python3
"""
sentrylog_seed.py -- Seed the SentryLog demo database with realistic log data.
Populates: logs, sources, alert_rules, alerts
"""

import sqlite3
import datetime
import random
import os
import json

DB_PATH = os.environ.get("SENTRYLOG_DB_PATH", "/app-sentrylog/sentrylog.db")

SOURCES = [
    ("10.0.1.1", "fw-edge-01", "Firewall", "FortiOS"),
    ("10.0.1.2", "sw-core-01", "Switch", "IOS-XE"),
    ("10.0.1.3", "sw-dist-a", "Switch", "IOS"),
    ("10.0.1.5", "vpn-gw-01", "VPN Gateway", "Linux"),
    ("10.0.2.10", "dc-01", "Server", "Windows"),
    ("10.0.2.11", "dc-02", "Server", "Windows"),
    ("10.0.2.30", "web-01", "Server", "Windows"),
    ("10.0.2.50", "exch-01", "Server", "Windows"),
    ("10.0.3.10", "nvr-01", "NVR", "Linux"),
    ("10.0.3.20", "pbx-01", "PBX", "Linux"),
]

FIREWALL_MSGS = [
    (4, "warning", "kern", 0, "UTM", "Attack log: srcip=203.0.113.{rnd} dstip=10.0.2.30 dstport=443 action=blocked attack=SQL.Injection"),
    (6, "info", "kern", 0, "UTM", "Session log: srcip=192.168.1.{rnd} dstip=8.8.8.8 dstport=53 action=accept proto=UDP bytes=128"),
    (6, "info", "kern", 0, "UTM", "VPN tunnel up: name=Site-B srcip=72.61.76.21 dstip=198.51.100.10"),
    (4, "warning", "kern", 0, "IPS", "IPS alert: srcip=198.51.100.{rnd} attack_id=40256 severity=medium msg=HTTP.URI.SQL.Injection"),
    (6, "info", "auth", 4, "sshd", "Accepted publickey for admin from 66.189.174.10 port 52{rnd}"),
    (3, "error", "kern", 0, "UTM", "Anti-virus: infected file blocked src=10.0.2.20 file=invoice.exe virus=W32/Malware.ABC"),
    (5, "notice", "kern", 0, "system", "Configuration changed by admin from 66.189.174.10 via HTTPS"),
    (4, "warning", "kern", 0, "anomaly", "DoS anomaly: srcip=203.0.113.{rnd} attack=tcp_syn_flood action=dropped count=1500"),
    (6, "info", "kern", 0, "traffic", "DNS query: srcip=10.0.2.10 dstip=8.8.8.8 domain=update.microsoft.com action=accept"),
    (6, "info", "kern", 0, "traffic", "HTTPS session: srcip=10.0.2.30 dstip=13.107.42.14 bytes_sent=4521 bytes_rcvd=89234 duration=45"),
]

SWITCH_MSGS = [
    (5, "notice", "local7", 23, "STP", "SPANTREE-2-BLOCK_PVID_LOCAL: Blocking port Gi0/24 on VLAN 10"),
    (6, "info", "local7", 23, "LINK", "LINK-3-UPDOWN: Interface GigabitEthernet0/12, changed state to up"),
    (4, "warning", "local7", 23, "DUPLEX", "DUPLEX_MISMATCH: duplex mismatch on Gi0/18 (half) with Gi0/1 (full)"),
    (6, "info", "local7", 23, "AUTHMGR", "DOT1X: Authentication success for MAC 00:1a:2b:3c:4d:{rnd} on Gi0/8"),
    (4, "warning", "local7", 23, "STORM", "STORM_CONTROL: packet rate exceeded on Gi0/24, action: filter"),
    (6, "info", "local7", 23, "CDP", "CDP neighbor update: Device sw-dist-b on Gi0/1, platform Cisco 2960X"),
    (5, "notice", "local7", 23, "CONFIG", "SYS-5-CONFIG_I: Configured from console by admin on vty0"),
]

WINDOWS_MSGS = [
    (6, "info", "auth", 4, "Security", "Event 4624: An account was successfully logged on. Subject: CORP\\\\svc_backup Logon Type: 3"),
    (4, "warning", "auth", 4, "Security", "Event 4625: An account failed to log on. Subject: CORP\\\\admin Logon Type: 10 Failure: Bad password"),
    (4, "warning", "auth", 4, "Security", "Event 4625: An account failed to log on. Subject: .\\\\administrator Logon Type: 3 Source: 203.0.113.{rnd}"),
    (6, "info", "auth", 4, "Security", "Event 4672: Special privileges assigned to new logon. Subject: CORP\\\\Domain Admins"),
    (5, "notice", "daemon", 3, "Service Control", "Event 7036: The Windows Update service entered the running state."),
    (3, "error", "daemon", 3, "Service Control", "Event 7031: The Print Spooler service terminated unexpectedly. Recovery action: Restart."),
    (6, "info", "local0", 16, "TaskScheduler", "Event 201: Task \\\\Backup\\\\DailyFull completed successfully."),
    (4, "warning", "kern", 0, "Disk", "Event 153: The IO operation at logical block address 0x1234 was retried."),
    (6, "info", "auth", 4, "Security", "Event 4720: A user account was created. Subject: CORP\\\\admin Target: CORP\\\\newuser01"),
]

VPN_MSGS = [
    (6, "info", "daemon", 3, "wireguard", "wg0: Peer rVpK...x8= (66.189.174.10) connected, handshake complete"),
    (6, "info", "daemon", 3, "wireguard", "wg0: Peer AbCd...z9= (198.51.100.50) disconnected, keepalive timeout"),
    (5, "notice", "auth", 4, "sshd", "Failed password for root from 203.0.113.{rnd} port 44{rnd} ssh2"),
    (5, "notice", "auth", 4, "sshd", "Accepted publickey for admin from 66.189.174.10 port 55{rnd} ssh2"),
    (4, "warning", "auth", 4, "sshd", "Invalid user guest from 203.0.113.{rnd} port 33{rnd}"),
]

NVR_MSGS = [
    (6, "info", "daemon", 3, "hikvision", "Camera 3 motion detected: region=entrance confidence=92%"),
    (4, "warning", "daemon", 3, "hikvision", "Camera 7 video loss: signal interrupted duration=5s"),
    (6, "info", "daemon", 3, "hikvision", "Recording started: camera=5 stream=main event=schedule"),
    (3, "error", "daemon", 3, "hikvision", "Disk warning: HDD 1 SMART status degraded, temperature=52C"),
]

PBX_MSGS = [
    (6, "info", "daemon", 3, "3cx", "Call: ext=201 -> 9-1-555-0{rnd} duration=3m42s status=completed"),
    (6, "info", "daemon", 3, "3cx", "Registration: ext=215 ip=10.0.3.55 registered successfully"),
    (4, "warning", "daemon", 3, "3cx", "SIP attack blocked: srcip=203.0.113.{rnd} method=REGISTER attempts=50"),
]


def init_db(conn):
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, received_at TEXT NOT NULL,
        source_ip TEXT NOT NULL, source_name TEXT DEFAULT '',
        facility TEXT DEFAULT '', facility_code INTEGER DEFAULT -1,
        severity TEXT DEFAULT 'info', severity_code INTEGER DEFAULT 6,
        app_name TEXT DEFAULT '', process_id TEXT DEFAULT '',
        message TEXT NOT NULL, raw TEXT DEFAULT ''
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source_ip, timestamp DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity_code, timestamp DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_received ON logs(received_at DESC)")

    c.execute("""CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL, name TEXT DEFAULT '', device_type TEXT DEFAULT '',
        os_type TEXT DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        log_count INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1, notes TEXT DEFAULT ''
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alert_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, description TEXT DEFAULT '',
        pattern TEXT NOT NULL, pattern_type TEXT DEFAULT 'contains',
        severity_filter TEXT DEFAULT '', source_filter TEXT DEFAULT '',
        facility_filter TEXT DEFAULT '', enabled INTEGER DEFAULT 1,
        action TEXT DEFAULT 'log', cooldown_minutes INTEGER DEFAULT 15,
        last_fired TEXT DEFAULT '', fire_count INTEGER DEFAULT 0,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id INTEGER, rule_name TEXT DEFAULT '', log_id INTEGER,
        timestamp TEXT NOT NULL, source_ip TEXT DEFAULT '',
        severity TEXT DEFAULT '', message TEXT DEFAULT '',
        acknowledged INTEGER DEFAULT 0, ack_by TEXT DEFAULT '', ack_at TEXT DEFAULT ''
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
    conn.commit()


def seed_sources(conn):
    now = datetime.datetime.utcnow().isoformat()
    first = (datetime.datetime.utcnow() - datetime.timedelta(days=30)).isoformat()
    for ip, name, dtype, ostype in SOURCES:
        try:
            conn.execute(
                "INSERT INTO sources (ip,name,device_type,os_type,first_seen,last_seen,log_count,enabled) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (ip, name, dtype, ostype, first, now, random.randint(500, 5000), 1))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    print(f"  Seeded {len(SOURCES)} sources")


def seed_logs(conn, hours=24):
    now = datetime.datetime.utcnow()
    rows = []

    msg_map = {
        "10.0.1.1": FIREWALL_MSGS,
        "10.0.1.2": SWITCH_MSGS,
        "10.0.1.3": SWITCH_MSGS,
        "10.0.1.5": VPN_MSGS,
        "10.0.2.10": WINDOWS_MSGS,
        "10.0.2.11": WINDOWS_MSGS,
        "10.0.2.30": WINDOWS_MSGS,
        "10.0.2.50": WINDOWS_MSGS,
        "10.0.3.10": NVR_MSGS,
        "10.0.3.20": PBX_MSGS,
    }

    for src_ip, src_name, _, _ in SOURCES:
        msgs = msg_map.get(src_ip, WINDOWS_MSGS)
        # Generate logs at varying intervals
        t = now - datetime.timedelta(hours=hours)
        while t <= now:
            interval = random.randint(5, 120)  # 5s to 2min between logs
            t += datetime.timedelta(seconds=interval)
            if t > now:
                break

            sev_code, severity, facility, fac_code, app, msg_template = random.choice(msgs)
            rnd = str(random.randint(10, 254))
            msg = msg_template.replace("{rnd}", rnd)
            ts = t.isoformat()

            rows.append((ts, ts, src_ip, src_name, facility, fac_code,
                          severity, sev_code, app, "", msg, ""))

    random.shuffle(rows)
    conn.executemany(
        "INSERT INTO logs (timestamp,received_at,source_ip,source_name,facility,"
        "facility_code,severity,severity_code,app_name,process_id,message,raw) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    print(f"  Seeded {len(rows)} log entries ({hours}h history)")


def seed_alert_rules(conn):
    now = datetime.datetime.utcnow().isoformat()
    rules = [
        ("Brute Force Detection", "Alert on multiple failed login attempts",
         "failed to log on", "contains", "", "", "", 1, "log", 15),
        ("SQL Injection Blocked", "Firewall IPS SQL injection alerts",
         "SQL.Injection", "contains", "", "10.0.1.1", "", 1, "log", 5),
        ("Malware Detected", "Antivirus blocked malicious file",
         "Anti-virus", "contains", "", "", "", 1, "log", 10),
        ("SSH Root Login Attempt", "Root login attempts via SSH",
         "Failed password for root", "contains", "", "", "", 1, "log", 15),
        ("Service Crash", "Windows service terminated unexpectedly",
         "terminated unexpectedly", "contains", "", "", "", 1, "log", 30),
        ("DoS Attack", "Denial of Service anomaly detected",
         "DoS anomaly", "contains", "", "10.0.1.1", "", 1, "log", 5),
        ("Disk Health Warning", "Storage SMART or IO errors",
         "SMART status degraded", "contains", "", "", "", 1, "log", 60),
        ("SIP Attack", "VoIP SIP registration attack attempts",
         "SIP attack blocked", "contains", "", "10.0.3.20", "", 1, "log", 10),
    ]

    for name, desc, pattern, ptype, sev_f, src_f, fac_f, enabled, action, cooldown in rules:
        conn.execute(
            "INSERT INTO alert_rules (name,description,pattern,pattern_type,"
            "severity_filter,source_filter,facility_filter,enabled,action,"
            "cooldown_minutes,fire_count,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, desc, pattern, ptype, sev_f, src_f, fac_f, enabled,
             action, cooldown, random.randint(1, 20), now, now))
    conn.commit()
    print(f"  Seeded {len(rules)} alert rules")


def seed_alerts(conn):
    now = datetime.datetime.utcnow()
    alerts = [
        (1, "Brute Force Detection", None, (now - datetime.timedelta(hours=1)).isoformat(),
         "10.0.2.50", "warning", "Event 4625: Failed logon from 203.0.113.42", 0),
        (2, "SQL Injection Blocked", None, (now - datetime.timedelta(hours=3)).isoformat(),
         "10.0.1.1", "warning", "IPS: SQL.Injection attack blocked from 203.0.113.88", 1),
        (3, "Malware Detected", None, (now - datetime.timedelta(hours=8)).isoformat(),
         "10.0.1.1", "error", "Anti-virus: invoice.exe blocked (W32/Malware.ABC)", 1),
        (4, "SSH Root Login Attempt", None, (now - datetime.timedelta(hours=2)).isoformat(),
         "10.0.1.5", "notice", "Failed password for root from 203.0.113.105", 0),
        (6, "DoS Attack", None, (now - datetime.timedelta(hours=5)).isoformat(),
         "10.0.1.1", "warning", "DoS anomaly: tcp_syn_flood from 203.0.113.77, dropped 1500 pkts", 1),
        (7, "Disk Health Warning", None, (now - datetime.timedelta(hours=12)).isoformat(),
         "10.0.3.10", "error", "HDD 1 SMART status degraded, temperature=52C", 0),
        (8, "SIP Attack", None, (now - datetime.timedelta(hours=4)).isoformat(),
         "10.0.3.20", "warning", "SIP attack blocked from 203.0.113.200, 50 attempts", 0),
        (5, "Service Crash", None, (now - datetime.timedelta(hours=6)).isoformat(),
         "10.0.2.30", "error", "Print Spooler service terminated unexpectedly", 1),
    ]

    for rule_id, rule_name, log_id, ts, src_ip, severity, msg, acked in alerts:
        ack_at = (datetime.datetime.fromisoformat(ts) + datetime.timedelta(minutes=random.randint(5, 30))).isoformat() if acked else ""
        conn.execute(
            "INSERT INTO alerts (rule_id,rule_name,log_id,timestamp,source_ip,"
            "severity,message,acknowledged,ack_by,ack_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (rule_id, rule_name, log_id, ts, src_ip, severity, msg,
             acked, "demo" if acked else "", ack_at))
    conn.commit()
    print(f"  Seeded {len(alerts)} triggered alerts")


def main():
    print("=== MyClover.Tech.SentryLog Demo Seed ===")
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"  Removed old database: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    print("  Database initialized")

    seed_sources(conn)
    seed_logs(conn, hours=24)
    seed_alert_rules(conn)
    seed_alerts(conn)

    conn.close()
    print("=== SentryLog Seed complete ===")


if __name__ == "__main__":
    main()
