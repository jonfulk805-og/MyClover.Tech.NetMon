#!/usr/bin/env python3
"""
MyClover.Tech.netmon v5.7 - Network Monitoring System
Features: ICMP ping, TCP port, HTTP, SNMP checks; email alerts;
          Flask dashboard with device CRUD, links/notes, maintenance mode,
          device detail drawer, status filters/search,
          network discovery scanner, graphical network map,
          settings management, asset inventory,
          host dependencies, performance graphing,
          alert acknowledgment, scheduled downtime,
          NOC/TV display mode, multi-channel notifications,
          SLA/uptime reports, user authentication,
          custom check plugins, SNMP deep polling.
"""

import os
import sys
import time
import socket
import struct
import sqlite3
import smtplib
import hashlib
import hmac
import logging
import threading
import subprocess
import platform
import datetime
import email.mime.text
import email.mime.multipart
import ipaddress
import re
import json as json_mod
import secrets
import base64
import csv
import io
import zipfile
import glob as glob_mod
import functools
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------
try:
    import yaml
except ImportError:
    yaml = None
    print("[WARN] PyYAML not installed. Run: pip install pyyaml")

try:
    import requests as req_lib
except ImportError:
    req_lib = None
    print("[WARN] requests not installed. HTTP checks disabled. Run: pip install requests")

try:
    from flask import Flask, jsonify, request, render_template, abort, send_file
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("[WARN] Flask not installed. Dashboard disabled. Run: pip install flask")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "netmon.db"
DEFAULT_CFG = BASE_DIR / "config.yaml"

_config = {}
_config_lock = threading.Lock()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netmon")

# ---------------------------------------------------------------------------
# License / Tier System
# ---------------------------------------------------------------------------
# License keys are HMAC-SHA256 based. Format: TIER-XXXXXXXX-YYYYYYYY
# where TIER is PRO or ENT, X is a unique id, Y is the HMAC signature.
# Keys are validated locally -- no phone-home required.

_LICENSE_SECRET = b"clovertech-netmon-2026-salt"  # Change for production

TIER_FREE = "community"
TIER_PRO = "pro"
TIER_ENT = "enterprise"

# Features gated by tier
TIER_FEATURES = {
    TIER_FREE: {
        "max_devices": 10,
        "max_sensors": 100,
        "tabs": ["status", "alerts", "history", "devices", "settings"],
        "api_write": False,
        "multi_recipient": False,
    },
    TIER_PRO: {
        "max_devices": 0,  # 0 = unlimited
        "max_sensors": 0,
        "tabs": ["status", "alerts", "history", "devices", "settings",
                 "inventory", "map", "discovery", "downtime", "helpdesk"],
        "api_write": True,
        "multi_recipient": True,
    },
    TIER_ENT: {
        "max_devices": 0,
        "max_sensors": 0,
        "tabs": ["status", "alerts", "history", "devices", "settings",
                 "inventory", "map", "discovery", "downtime", "helpdesk",
                 "noc", "security", "reports", "ai_assistant"],
        "api_write": True,
        "multi_recipient": True,
        "noc_mode": True,
        "security_scan": True,
        "sla_reports": True,
        "user_auth": True,
        "custom_plugins": True,
        "snmp_deep": True,
        "multi_channel_notify": True,
    },
}

_current_tier = TIER_FREE


def _generate_license_key(tier_code, unique_id):
    """Generate a license key (admin/build tool only)."""
    payload = "%s-%s" % (tier_code, unique_id)
    sig = hashlib.sha256(_LICENSE_SECRET + payload.encode("utf-8")).hexdigest()[:16]
    return "%s-%s-%s" % (tier_code.upper(), unique_id.upper(), sig.upper())


def validate_license_key(key):
    """Validate a license key and return the tier, or None if invalid."""
    if not key or not isinstance(key, str):
        return None
    parts = key.strip().upper().split("-")
    if len(parts) != 3:
        return None
    tier_code, unique_id, provided_sig = parts
    tier_map = {"PRO": TIER_PRO, "ENT": TIER_ENT}
    if tier_code not in tier_map:
        return None
    payload = "%s-%s" % (tier_code, unique_id)
    expected_sig = hashlib.sha256(_LICENSE_SECRET + payload.encode("utf-8")).hexdigest()[:16].upper()
    if provided_sig != expected_sig:
        return None
    return tier_map[tier_code]


def get_tier():
    """Return the current license tier."""
    return _current_tier


def get_tier_features():
    """Return feature flags for the current tier."""
    return dict(TIER_FEATURES.get(_current_tier, TIER_FEATURES[TIER_FREE]))


def _load_license():
    """Load and validate the license key from config."""
    global _current_tier
    with _config_lock:
        key = _config.get("license_key", "").strip()
    tier = validate_license_key(key)
    if tier:
        _current_tier = tier
        log.info("License valid: %s tier", _current_tier)
    else:
        _current_tier = TIER_FREE
        if key:
            log.warning("Invalid license key -- running as Community (free) tier")
        else:
            log.info("No license key -- running as Community (free) tier")


def require_tier(min_tier):
    """Flask decorator to gate a route behind a minimum tier.

    Tier order: community < pro < enterprise
    """
    tier_order = [TIER_FREE, TIER_PRO, TIER_ENT]

    def decorator(f):
        def wrapper(*args, **kwargs):
            current = get_tier()
            if tier_order.index(current) < tier_order.index(min_tier):
                tier_name = min_tier.capitalize()
                return jsonify({
                    "error": "upgrade_required",
                    "message": "This feature requires a %s license or higher." % tier_name,
                    "current_tier": current,
                    "required_tier": min_tier,
                }), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def check_device_limit():
    """Return True if adding a device would exceed the free tier limit."""
    features = get_tier_features()
    max_dev = features["max_devices"]
    if max_dev == 0:
        return True  # unlimited
    with _config_lock:
        current_count = len(_config.get("devices", []))
    return current_count < max_dev


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(path=None):
    path = path or DEFAULT_CFG
    if yaml is None:
        log.error("PyYAML required. Install with: pip install pyyaml")
        sys.exit(1)
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    return cfg or {}


def save_config(cfg, path=None):
    path = path or DEFAULT_CFG
    if yaml is None:
        return
    with open(path, "w", encoding="utf-8") as fh:
        yaml.dump(cfg, fh, default_flow_style=False, sort_keys=False, allow_unicode=False)


def _sanitize_device(data):
    """Normalise a device dict coming from the API."""
    d = {
        "name": str(data.get("name", "")).strip(),
        "host": str(data.get("host", "")).strip(),
        "group": str(data.get("group", "Default")).strip() or "Default",
        "parent": str(data.get("parent", "")).strip(),
        "links": data.get("links") or [],
        "notes": str(data.get("notes", "")).strip(),
        "maintenance": bool(data.get("maintenance", False)),
        "checks": [],
    }
    for c in data.get("checks") or []:
        chk = {"type": c.get("type", "ping")}
        for k in ("label", "port", "url", "expected_code", "community", "oid",
                   "warning_ms", "critical_ms", "timeout_ms", "retries"):
            if k in c and c[k] not in (None, ""):
                chk[k] = c[k]
        d["checks"].append(chk)
    # Sanitize links list
    clean_links = []
    for lnk in d["links"]:
        if isinstance(lnk, dict) and lnk.get("url", "").strip():
            clean_links.append({
                "url": str(lnk["url"]).strip(),
                "label": str(lnk.get("label", "")).strip() or lnk["url"].strip(),
            })
    d["links"] = clean_links
    return d


def _reload_config():
    global _config
    with _config_lock:
        _config = load_config()
        # Load AI assistant config if present
        try:
            import ai_assistant as _ai_mod
            ai_cfg = _config.get("ai_assistant", {})
            if ai_cfg:
                _ai_mod.update_config(ai_cfg)
        except ImportError:
            pass
    _load_license()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS check_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        device_name TEXT NOT NULL,
        host TEXT NOT NULL,
        check_type TEXT NOT NULL,
        check_label TEXT,
        status TEXT NOT NULL,
        response_ms REAL,
        message TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        device_name TEXT NOT NULL,
        check_type TEXT NOT NULL,
        check_label TEXT,
        status TEXT NOT NULL,
        message TEXT,
        email_sent INTEGER DEFAULT 0,
        acknowledged INTEGER DEFAULT 0,
        acknowledged_by TEXT DEFAULT '',
        acknowledged_at TEXT DEFAULT ''
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        ip TEXT NOT NULL,
        hostname TEXT,
        is_alive INTEGER DEFAULT 0,
        open_ports TEXT,
        response_ms REAL,
        added_to_devices INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        hostname TEXT DEFAULT '',
        mac_address TEXT DEFAULT '',
        device_type TEXT DEFAULT '',
        vendor TEXT DEFAULT '',
        model TEXT DEFAULT '',
        os_info TEXT DEFAULT '',
        location TEXT DEFAULT '',
        serial_number TEXT DEFAULT '',
        purchase_date TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        open_ports TEXT DEFAULT '',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        last_scan_id TEXT DEFAULT '',
        monitored_device TEXT DEFAULT '',
        status TEXT DEFAULT 'active',
        custom_fields TEXT DEFAULT '{}'
    )""")
    # Performance data for time-series graphing
    c.execute("""CREATE TABLE IF NOT EXISTS perf_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        device_name TEXT NOT NULL,
        check_label TEXT NOT NULL,
        status TEXT NOT NULL,
        response_ms REAL
    )""")
    # Scheduled downtime windows
    c.execute("""CREATE TABLE IF NOT EXISTS scheduled_downtime (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        reason TEXT DEFAULT '',
        created_by TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        active INTEGER DEFAULT 1
    )""")
    # Indexes
    c.execute("""CREATE INDEX IF NOT EXISTS idx_results_ts
                 ON check_results(timestamp DESC)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_results_device
                 ON check_results(device_name, check_label)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_alerts_ts
                 ON alerts(timestamp DESC)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_scan_id
                 ON scan_results(scan_id)""")
    c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_ip
                 ON inventory(ip)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_perf_ts
                 ON perf_data(device_name, check_label, timestamp)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_downtime_device
                 ON scheduled_downtime(device_name, start_time)""")
    # Helpdesk ticket cache
    c.execute("""CREATE TABLE IF NOT EXISTS helpdesk_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        remote_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        subject TEXT NOT NULL,
        description TEXT DEFAULT '',
        status TEXT DEFAULT '',
        priority TEXT DEFAULT '',
        ticket_type TEXT DEFAULT '',
        assignee TEXT DEFAULT '',
        requester TEXT DEFAULT '',
        created_at TEXT DEFAULT '',
        updated_at TEXT DEFAULT '',
        due_date TEXT DEFAULT '',
        device_name TEXT DEFAULT '',
        url TEXT DEFAULT '',
        raw_json TEXT DEFAULT '{}',
        synced_at TEXT NOT NULL
    )""")
    c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_helpdesk_remote
                 ON helpdesk_tickets(provider, remote_id)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_helpdesk_device
                 ON helpdesk_tickets(device_name)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_helpdesk_status
                 ON helpdesk_tickets(status)""")
    c.execute("""CREATE TABLE IF NOT EXISTS security_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        targets TEXT NOT NULL,
        scan_types TEXT NOT NULL,
        status TEXT DEFAULT 'running',
        summary TEXT DEFAULT '{}'
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS security_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        target TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        details TEXT DEFAULT '{}',
        remediation TEXT DEFAULT ''
    )""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_secscans_id
                 ON security_scans(scan_id)""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_secfindings_scan
                 ON security_findings(scan_id)""")

    # Migrate: add acknowledged columns to alerts if missing
    try:
        c.execute("SELECT acknowledged FROM alerts LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE alerts ADD COLUMN acknowledged INTEGER DEFAULT 0")
        c.execute("ALTER TABLE alerts ADD COLUMN acknowledged_by TEXT DEFAULT ''")
        c.execute("ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT DEFAULT ''")
    conn.commit()
    conn.close()


def store_result(r):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO check_results (timestamp,device_name,host,check_type,check_label,status,response_ms,message) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (r["timestamp"], r["device_name"], r["host"], r["check_type"],
         r.get("check_label"), r["status"], r.get("response_ms"), r.get("message")))
    # Also store in perf_data for graphing
    conn.execute(
        "INSERT INTO perf_data (timestamp,device_name,check_label,status,response_ms) "
        "VALUES (?,?,?,?,?)",
        (r["timestamp"], r["device_name"], r.get("check_label", ""),
         r["status"], r.get("response_ms")))
    conn.commit()
    conn.close()


def store_alert(a, email_sent=False):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO alerts (timestamp,device_name,check_type,check_label,status,message,email_sent) "
        "VALUES (?,?,?,?,?,?,?)",
        (a["timestamp"], a["device_name"], a["check_type"],
         a.get("check_label"), a["status"], a.get("message"), int(email_sent)))
    conn.commit()
    conn.close()


def get_latest_per_check():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT cr.* FROM check_results cr
        INNER JOIN (
            SELECT device_name, check_label, MAX(id) as max_id
            FROM check_results GROUP BY device_name, check_label
        ) latest ON cr.id = latest.max_id
        ORDER BY cr.device_name, cr.check_label
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerts(hours=48):
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    since = (datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(hours=hours)).isoformat()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 500",
        (since,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_history(hours=24):
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    since = (datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(hours=hours)).isoformat()
    rows = conn.execute(
        "SELECT * FROM check_results WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 1000",
        (since,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_device_history(device_name, check_label=None, limit=50):
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    if check_label:
        rows = conn.execute(
            "SELECT * FROM check_results WHERE device_name=? AND check_label=? "
            "ORDER BY timestamp DESC LIMIT ?",
            (device_name, check_label, limit)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM check_results WHERE device_name=? "
            "ORDER BY timestamp DESC LIMIT ?",
            (device_name, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_device_uptime(device_name, hours=24):
    conn = sqlite3.connect(str(DB_PATH))
    since = (datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(hours=hours)).isoformat()
    total = conn.execute(
        "SELECT COUNT(*) FROM check_results WHERE device_name=? AND timestamp>=?",
        (device_name, since)).fetchone()[0]
    ok_count = conn.execute(
        "SELECT COUNT(*) FROM check_results WHERE device_name=? AND timestamp>=? AND status='OK'",
        (device_name, since)).fetchone()[0]
    conn.close()
    if total == 0:
        return None
    return round(100.0 * ok_count / total, 1)


def get_perf_data(device_name, check_label, hours=24, max_points=200):
    """Get performance time-series data for graphing."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    since = (datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(hours=hours)).isoformat()
    rows = conn.execute(
        "SELECT timestamp, status, response_ms FROM perf_data "
        "WHERE device_name=? AND check_label=? AND timestamp>=? "
        "ORDER BY timestamp ASC",
        (device_name, check_label, since)).fetchall()
    conn.close()
    result = [dict(r) for r in rows]
    # Downsample if too many points
    if len(result) > max_points:
        step = len(result) // max_points
        result = result[::step]
    return result


# ---------------------------------------------------------------------------
# Scheduled Downtime helpers
# ---------------------------------------------------------------------------

def get_active_downtimes():
    """Return list of device names currently in scheduled downtime."""
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT device_name FROM scheduled_downtime "
        "WHERE active=1 AND start_time<=? AND end_time>=?",
        (now, now)).fetchall()
    conn.close()
    return set(r["device_name"] for r in rows)


def get_all_downtimes():
    """Return all scheduled downtimes."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scheduled_downtime ORDER BY start_time DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------

def _get_parent_map(devices):
    """Build dict: device_name -> parent_name from config."""
    pm = {}
    for d in devices:
        parent = d.get("parent", "").strip()
        if parent:
            pm[d["name"]] = parent
    return pm


def _get_device_status_map(results):
    """Build dict: device_name -> worst status from latest check results."""
    sm = {}
    for r in results:
        name = r["device_name"]
        cur = sm.get(name, "OK")
        if r["status"] == "CRITICAL":
            sm[name] = "CRITICAL"
        elif r["status"] == "WARNING" and cur != "CRITICAL":
            sm[name] = "WARNING"
        elif name not in sm:
            sm[name] = r["status"]
    return sm


def is_parent_down(device_name, parent_map, status_map):
    """Check if any ancestor of device_name is CRITICAL (recursively)."""
    visited = set()
    current = device_name
    while current in parent_map:
        parent = parent_map[current]
        if parent in visited:
            break  # circular dependency guard
        visited.add(parent)
        if status_map.get(parent) == "CRITICAL":
            return True
        current = parent
    return False


# ---------------------------------------------------------------------------
# Inventory helpers
# ---------------------------------------------------------------------------

def import_scan_to_inventory(scan_id):
    """Import alive hosts from a scan into the inventory table."""
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scan_results WHERE scan_id=? AND is_alive=1",
        (scan_id,)).fetchall()

    imported = 0
    updated = 0
    for row in rows:
        ip = row["ip"]
        hostname = row["hostname"] or ""
        ports_str = row["open_ports"] or ""

        existing = conn.execute("SELECT id FROM inventory WHERE ip=?", (ip,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE inventory SET hostname=?, open_ports=?, last_seen=?, last_scan_id=? WHERE ip=?",
                (hostname or "", ports_str, now, scan_id, ip))
            updated += 1
        else:
            conn.execute(
                "INSERT INTO inventory (ip,hostname,open_ports,first_seen,last_seen,last_scan_id,status) "
                "VALUES (?,?,?,?,?,?,?)",
                (ip, hostname, ports_str, now, now, scan_id, "active"))
            imported += 1
    conn.commit()
    conn.close()
    return {"imported": imported, "updated": updated}


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def ping_check(host, timeout_ms=5000, retries=2):
    """ICMP ping using system ping command."""
    count = retries + 1
    is_win = platform.system().lower() == "windows"
    timeout_s = max(1, timeout_ms // 1000)
    if is_win:
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout_s), host]
    try:
        t0 = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 10,
                                encoding="utf-8", errors="replace")
        elapsed = (time.time() - t0) * 1000
        output = result.stdout + result.stderr
        if is_win:
            if "TTL=" not in output.upper():
                return {"ok": False, "ms": None, "msg": "Ping failed: host unreachable"}
            m = re.search(r"Average\s*=\s*(\d+)", output)
            ms = float(m.group(1)) if m else elapsed
            return {"ok": True, "ms": ms, "msg": "Ping OK"}
        else:
            if result.returncode == 0:
                m = re.search(r"rtt min/avg/max.*=\s*[\d.]+/([\d.]+)/", output)
                ms = float(m.group(1)) if m else elapsed
                return {"ok": True, "ms": ms, "msg": "Ping OK"}
            return {"ok": False, "ms": None, "msg": "Ping failed: host unreachable"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "ms": None, "msg": "Ping timeout"}
    except Exception as e:
        return {"ok": False, "ms": None, "msg": "Ping error: " + str(e)}


def ping_single(host, timeout_ms=2000):
    """Quick single-ping for scanner. Returns (alive, ms)."""
    is_win = platform.system().lower() == "windows"
    timeout_s = max(1, timeout_ms // 1000)
    if is_win:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), host]
    try:
        t0 = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 5,
                                encoding="utf-8", errors="replace")
        ms = (time.time() - t0) * 1000
        output = result.stdout
        if is_win:
            if "TTL=" not in output.upper():
                return (False, None)
            m = re.search(r"time[=<]\s*(\d+)", output)
            if m:
                ms = float(m.group(1))
            return (True, round(ms, 1))
        else:
            if result.returncode == 0:
                m = re.search(r"time=(\d+\.?\d*)", output)
                if m:
                    ms = float(m.group(1))
                return (True, round(ms, 1))
            return (False, None)
    except Exception:
        return (False, None)


def port_check(host, port, timeout_ms=5000):
    """TCP port connectivity check."""
    try:
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_ms / 1000.0)
        s.connect((host, int(port)))
        ms = (time.time() - t0) * 1000
        s.close()
        return {"ok": True, "ms": ms, "msg": "Port %d open" % int(port)}
    except socket.timeout:
        return {"ok": False, "ms": None, "msg": "Port %d timeout" % int(port)}
    except ConnectionRefusedError:
        return {"ok": False, "ms": None, "msg": "Port %d refused" % int(port)}
    except Exception as e:
        return {"ok": False, "ms": None, "msg": "Port check error: " + str(e)}


def scan_ports(host, ports, timeout_ms=1000):
    """Scan a list of TCP ports. Returns list of open port numbers."""
    open_ports = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_ms / 1000.0)
            s.connect((host, int(p)))
            s.close()
            open_ports.append(int(p))
        except Exception:
            pass
    return open_ports


def http_check(url, expected_code=200, timeout_ms=5000):
    """HTTP/HTTPS endpoint check."""
    if req_lib is None:
        return {"ok": False, "ms": None, "msg": "requests library not installed"}
    try:
        t0 = time.time()
        resp = req_lib.get(url, timeout=timeout_ms / 1000.0, verify=False, allow_redirects=True)
        ms = (time.time() - t0) * 1000
        if resp.status_code == int(expected_code):
            return {"ok": True, "ms": ms, "msg": "HTTP %d OK" % resp.status_code}
        else:
            return {"ok": False, "ms": ms,
                    "msg": "HTTP %d (expected %d)" % (resp.status_code, int(expected_code))}
    except req_lib.exceptions.Timeout:
        return {"ok": False, "ms": None, "msg": "HTTP timeout"}
    except Exception as e:
        return {"ok": False, "ms": None, "msg": "HTTP error: " + str(e)}


def snmp_check(host, community="public", oid="1.3.6.1.2.1.1.3.0", timeout_ms=5000):
    """SNMP GET check (requires pysnmp)."""
    try:
        from pysnmp.hlapi import (getCmd, SnmpEngine, CommunityData,
                                  UdpTransportTarget, ContextData, ObjectType, ObjectIdentity)
        t0 = time.time()
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((host, 161), timeout=timeout_ms / 1000.0, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        ms = (time.time() - t0) * 1000
        if errorIndication:
            return {"ok": False, "ms": ms, "msg": "SNMP: " + str(errorIndication)}
        elif errorStatus:
            return {"ok": False, "ms": ms, "msg": "SNMP error: " + str(errorStatus)}
        else:
            val = str(varBinds[0][1]) if varBinds else ""
            return {"ok": True, "ms": ms, "msg": "SNMP OK: " + val[:80]}
    except ImportError:
        return {"ok": False, "ms": None, "msg": "pysnmp not installed"}
    except Exception as e:
        return {"ok": False, "ms": None, "msg": "SNMP error: " + str(e)}


def run_check(device, check):
    """Run a single check and return a result dict."""
    host = device["host"]
    ctype = check.get("type", "ping")
    label = check.get("label", ctype.upper())
    timeout = check.get("timeout_ms", 5000)
    warning = check.get("warning_ms", 50)
    critical = check.get("critical_ms", 200)
    retries = check.get("retries", 2)

    if ctype == "ping":
        r = ping_check(host, timeout, retries)
    elif ctype == "port":
        r = port_check(host, check.get("port", 80), timeout)
    elif ctype == "http":
        r = http_check(check.get("url", "http://" + host), check.get("expected_code", 200), timeout)
    elif ctype == "snmp":
        r = snmp_check(host, check.get("community", "public"), check.get("oid", "1.3.6.1.2.1.1.3.0"), timeout)
    elif ctype == "plugin":
        pr = run_plugin_check(device, check)
        return {
            "timestamp": datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat(),
            "device_name": device["name"],
            "host": host,
            "check_type": ctype,
            "check_label": label,
            "status": pr["status"],
            "response_ms": pr["response_ms"],
            "message": pr["message"],
        }
    else:
        r = {"ok": False, "ms": None, "msg": "Unknown check type: " + ctype}

    if not r["ok"]:
        status = "CRITICAL"
    elif r["ms"] is not None and r["ms"] >= critical:
        status = "CRITICAL"
    elif r["ms"] is not None and r["ms"] >= warning:
        status = "WARNING"
    else:
        status = "OK"

    return {
        "timestamp": datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat(),
        "device_name": device["name"],
        "host": host,
        "check_type": ctype,
        "check_label": label,
        "status": status,
        "response_ms": r["ms"],
        "message": r["msg"],
    }


# ---------------------------------------------------------------------------
# Email alerts
# ---------------------------------------------------------------------------

_last_alert_email = {}

def send_alert_email(result, smtp_cfg):
    if not smtp_cfg or not smtp_cfg.get("recipients"):
        return False
    key = result["device_name"] + "|" + (result.get("check_label") or "")
    cooldown = smtp_cfg.get("cooldown_minutes", 15) * 60
    now = time.time()
    if key in _last_alert_email and (now - _last_alert_email[key]) < cooldown:
        return False

    subject = "[MyClover.Tech.netmon %s] %s - %s" % (result["status"], result["device_name"],
                                                     result.get("check_label", ""))
    body_text = (
        "Device: %s\nHost: %s\nCheck: %s\nStatus: %s\nMessage: %s\nTime: %s"
        % (result["device_name"], result["host"], result.get("check_label", ""),
           result["status"], result.get("message", ""), result["timestamp"])
    )
    body_html = (
        "<h2 style='color:%s;'>%s</h2>"
        "<table>"
        "<tr><td><b>Device</b></td><td>%s</td></tr>"
        "<tr><td><b>Host</b></td><td>%s</td></tr>"
        "<tr><td><b>Check</b></td><td>%s</td></tr>"
        "<tr><td><b>Status</b></td><td>%s</td></tr>"
        "<tr><td><b>Message</b></td><td>%s</td></tr>"
        "<tr><td><b>Time</b></td><td>%s</td></tr>"
        "</table>"
    ) % (
        "#e74c3c" if result["status"] == "CRITICAL" else "#f39c12",
        result["status"],
        result["device_name"], result["host"],
        result.get("check_label", ""), result["status"],
        result.get("message", ""), result["timestamp"],
    )

    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_cfg.get("from_addr", "netmon@localhost")
    msg["To"] = ", ".join(smtp_cfg["recipients"])
    msg.attach(email.mime.text.MIMEText(body_text, "plain"))
    msg.attach(email.mime.text.MIMEText(body_html, "html"))

    try:
        host = smtp_cfg.get("smtp_host", "localhost")
        port = smtp_cfg.get("smtp_port", 587)
        use_tls = smtp_cfg.get("use_tls", True)
        if use_tls:
            server = smtplib.SMTP(host, port, timeout=15)
            server.starttls()
        else:
            server = smtplib.SMTP(host, port, timeout=15)
        user = smtp_cfg.get("username", "")
        pwd = smtp_cfg.get("password", "")
        if user and pwd:
            server.login(user, pwd)
        server.sendmail(msg["From"], smtp_cfg["recipients"], msg.as_string())
        server.quit()
        _last_alert_email[key] = now
        log.info("Alert email sent for %s / %s", result["device_name"], result.get("check_label", ""))
        return True
    except Exception as e:
        log.error("Email send failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Multi-Channel Notifications (Enterprise)
# ---------------------------------------------------------------------------
_last_webhook_alert = {}


def send_webhook_notification(result, webhook_cfg):
    """Send alert to Slack, Teams, or PagerDuty webhook."""
    if not webhook_cfg or not isinstance(webhook_cfg, list):
        return
    if get_tier() != TIER_ENT:
        return

    key = result["device_name"] + "|" + (result.get("check_label") or "")
    cooldown = 15 * 60  # 15 min cooldown
    now = time.time()
    if key in _last_webhook_alert and (now - _last_webhook_alert[key]) < cooldown:
        return

    for hook in webhook_cfg:
        hook_type = hook.get("type", "").lower()
        url = hook.get("url", "").strip()
        if not url:
            continue
        try:
            if hook_type == "slack":
                _send_slack_webhook(result, url)
            elif hook_type == "teams":
                _send_teams_webhook(result, url)
            elif hook_type == "pagerduty":
                _send_pagerduty_event(result, hook)
            elif hook_type == "generic":
                _send_generic_webhook(result, url)
            else:
                log.warning("Unknown webhook type: %s", hook_type)
                continue
            log.info("Webhook (%s) sent for %s", hook_type, result["device_name"])
        except Exception as e:
            log.error("Webhook (%s) failed: %s", hook_type, e)

    _last_webhook_alert[key] = now


def _send_slack_webhook(result, url):
    """Send Slack-formatted webhook."""
    if not req_lib:
        return
    color = "#e74c3c" if result["status"] == "CRITICAL" else "#f39c12"
    payload = {
        "attachments": [{
            "color": color,
            "title": "[%s] %s - %s" % (result["status"], result["device_name"],
                                         result.get("check_label", "")),
            "fields": [
                {"title": "Host", "value": result.get("host", ""), "short": True},
                {"title": "Status", "value": result["status"], "short": True},
                {"title": "Message", "value": result.get("message", ""), "short": False},
            ],
            "footer": "MyClover.Tech.netmon",
            "ts": int(time.time()),
        }]
    }
    req_lib.post(url, json=payload, timeout=10)


def _send_teams_webhook(result, url):
    """Send Microsoft Teams webhook (Adaptive Card)."""
    if not req_lib:
        return
    color = "attention" if result["status"] == "CRITICAL" else "warning"
    payload = {
        "@type": "MessageCard",
        "summary": "[%s] %s" % (result["status"], result["device_name"]),
        "themeColor": "e74c3c" if result["status"] == "CRITICAL" else "f39c12",
        "sections": [{
            "activityTitle": "[%s] %s - %s" % (result["status"],
                                                result["device_name"],
                                                result.get("check_label", "")),
            "facts": [
                {"name": "Host", "value": result.get("host", "")},
                {"name": "Status", "value": result["status"]},
                {"name": "Message", "value": result.get("message", "")},
                {"name": "Time", "value": result.get("timestamp", "")},
            ],
        }]
    }
    req_lib.post(url, json=payload, timeout=10)


def _send_pagerduty_event(result, hook):
    """Send PagerDuty Events API v2 trigger."""
    if not req_lib:
        return
    routing_key = hook.get("routing_key", "")
    if not routing_key:
        return
    severity = "critical" if result["status"] == "CRITICAL" else "warning"
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": "[%s] %s - %s: %s" % (result["status"],
                                               result["device_name"],
                                               result.get("check_label", ""),
                                               result.get("message", "")),
            "source": result.get("host", "netmon"),
            "severity": severity,
            "component": result["device_name"],
            "class": result.get("check_type", ""),
        }
    }
    req_lib.post("https://events.pagerduty.com/v2/enqueue",
                 json=payload, timeout=10)


def _send_generic_webhook(result, url):
    """Send a generic JSON POST webhook."""
    if not req_lib:
        return
    req_lib.post(url, json=result, timeout=10)


# ---------------------------------------------------------------------------
# Custom Check Plugins (Enterprise)
# ---------------------------------------------------------------------------
PLUGIN_DIR = BASE_DIR / "plugins"


def run_plugin_check(device, check):
    """Run a custom plugin script.
    Plugin scripts must:
      - Accept --host <host> as argument
      - Print a JSON line: {"status":"OK|WARNING|CRITICAL","message":"...","response_ms":1.23}
      - Exit code 0
    """
    script = check.get("plugin", "")
    if not script:
        return {"status": "CRITICAL", "message": "No plugin specified",
                "response_ms": None}

    plugin_path = PLUGIN_DIR / script
    if not plugin_path.is_file():
        return {"status": "CRITICAL",
                "message": "Plugin not found: %s" % script,
                "response_ms": None}

    timeout_s = check.get("timeout_ms", 30000) / 1000.0
    host = device.get("host", "")
    args_extra = check.get("args", "")
    cmd = [sys.executable, str(plugin_path), "--host", host]
    if args_extra:
        cmd.extend(args_extra.split())

    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_s, encoding="utf-8")
        elapsed = (time.time() - start) * 1000
        output = proc.stdout.strip()
        if not output:
            return {"status": "CRITICAL",
                    "message": "Plugin returned no output (exit=%d)" % proc.returncode,
                    "response_ms": elapsed}
        data = json_mod.loads(output)
        return {
            "status": data.get("status", "CRITICAL"),
            "message": str(data.get("message", "")),
            "response_ms": data.get("response_ms", elapsed),
        }
    except subprocess.TimeoutExpired:
        return {"status": "CRITICAL", "message": "Plugin timed out",
                "response_ms": timeout_s * 1000}
    except json_mod.JSONDecodeError:
        return {"status": "CRITICAL",
                "message": "Plugin output is not valid JSON",
                "response_ms": (time.time() - start) * 1000}
    except Exception as e:
        return {"status": "CRITICAL", "message": "Plugin error: %s" % e,
                "response_ms": None}


# ---------------------------------------------------------------------------
# SNMP Deep Polling (Enterprise)
# ---------------------------------------------------------------------------
# Standard OIDs for system metrics
SNMP_OIDS = {
    "cpu_load_1m": "1.3.6.1.4.1.2021.10.1.3.1",
    "cpu_load_5m": "1.3.6.1.4.1.2021.10.1.3.2",
    "cpu_load_15m": "1.3.6.1.4.1.2021.10.1.3.3",
    "mem_total": "1.3.6.1.4.1.2021.4.5.0",
    "mem_avail": "1.3.6.1.4.1.2021.4.6.0",
    "disk_total": "1.3.6.1.4.1.2021.9.1.6.1",
    "disk_avail": "1.3.6.1.4.1.2021.9.1.7.1",
    "if_in_octets": "1.3.6.1.2.1.2.2.1.10",
    "if_out_octets": "1.3.6.1.2.1.2.2.1.16",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
}


def snmp_deep_poll(host, community="public", timeout_ms=5000):
    """Poll extended SNMP metrics. Returns dict of metric values.
    Uses snmpget/snmpwalk CLI tools if available, else net-snmp.
    """
    results = {}
    timeout_s = timeout_ms / 1000.0

    for metric, oid in SNMP_OIDS.items():
        try:
            cmd = ["snmpget", "-v2c", "-c", community,
                   "-t", str(int(timeout_s)), "-r", "1",
                   host, oid]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout_s + 2, encoding="utf-8")
            if proc.returncode == 0 and proc.stdout.strip():
                line = proc.stdout.strip()
                # Parse value after the = sign
                if "=" in line:
                    val_part = line.split("=", 1)[1].strip()
                    # Try to extract numeric value
                    num_match = re.search(r"[-+]?\d*\.?\d+", val_part)
                    if num_match:
                        results[metric] = float(num_match.group())
                    else:
                        results[metric] = val_part
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            continue

    # Calculate percentages if possible
    if "mem_total" in results and "mem_avail" in results:
        total = results["mem_total"]
        avail = results["mem_avail"]
        if total > 0:
            results["mem_used_pct"] = round(100.0 * (total - avail) / total, 1)

    if "disk_total" in results and "disk_avail" in results:
        total = results["disk_total"]
        avail = results["disk_avail"]
        if total > 0:
            results["disk_used_pct"] = round(100.0 * (total - avail) / total, 1)

    return results


# ---------------------------------------------------------------------------
# SLA / Uptime Report Generation (Enterprise)
# ---------------------------------------------------------------------------

def generate_sla_report(hours=720, device_filter=None):
    """Generate SLA/uptime report data for all or specific devices.
    Returns list of device reports with uptime %, MTTR, incident count.
    """
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    since = (datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(hours=hours)).isoformat()

    # Get all device names
    with _config_lock:
        devices = _config.get("devices", [])

    reports = []
    for dev in devices:
        name = dev["name"]
        if device_filter and name not in device_filter:
            continue

        # Total checks and OK checks
        row = conn.execute(
            "SELECT COUNT(*) as total, "
            "SUM(CASE WHEN status='OK' THEN 1 ELSE 0 END) as ok_count "
            "FROM check_results WHERE device_name=? AND timestamp>=?",
            (name, since)).fetchone()
        total = row["total"] or 0
        ok_count = row["ok_count"] or 0

        if total == 0:
            uptime_pct = None
            downtime_minutes = 0
        else:
            uptime_pct = round(100.0 * ok_count / total, 3)
            with _config_lock:
                interval = _config.get("check_interval_seconds", 60)
            downtime_minutes = round((total - ok_count) * interval / 60.0, 1)

        # Count incidents (transitions to WARNING/CRITICAL)
        alerts_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM alerts "
            "WHERE device_name=? AND timestamp>=?",
            (name, since)).fetchone()
        incident_count = alerts_row["cnt"] or 0

        # Calculate MTTR (mean time to recovery) in minutes
        alerts_data = conn.execute(
            "SELECT timestamp, status FROM check_results "
            "WHERE device_name=? AND timestamp>=? ORDER BY timestamp ASC",
            (name, since)).fetchall()

        recovery_times = []
        fail_start = None
        for row in alerts_data:
            if row["status"] in ("WARNING", "CRITICAL"):
                if fail_start is None:
                    fail_start = row["timestamp"]
            elif row["status"] == "OK" and fail_start is not None:
                try:
                    t1 = datetime.datetime.fromisoformat(fail_start)
                    t2 = datetime.datetime.fromisoformat(row["timestamp"])
                    recovery_times.append((t2 - t1).total_seconds() / 60.0)
                except Exception:
                    pass
                fail_start = None

        mttr = round(sum(recovery_times) / len(recovery_times), 1) if recovery_times else 0

        reports.append({
            "device_name": name,
            "host": dev.get("host", ""),
            "group": dev.get("group", "Default"),
            "total_checks": total,
            "ok_checks": ok_count,
            "uptime_pct": uptime_pct,
            "downtime_minutes": downtime_minutes,
            "incident_count": incident_count,
            "mttr_minutes": mttr,
            "period_hours": hours,
        })

    conn.close()
    return reports


def generate_sla_csv(reports):
    """Generate CSV string from SLA report data."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Device", "Host", "Group", "Uptime %", "Downtime (min)",
        "Incidents", "MTTR (min)", "Total Checks", "OK Checks",
        "Period (hours)",
    ])
    for r in reports:
        writer.writerow([
            r["device_name"], r["host"], r["group"],
            r["uptime_pct"] if r["uptime_pct"] is not None else "N/A",
            r["downtime_minutes"], r["incident_count"], r["mttr_minutes"],
            r["total_checks"], r["ok_checks"], r["period_hours"],
        ])
    return output.getvalue()


# ---------------------------------------------------------------------------
# User Authentication (Enterprise)
# ---------------------------------------------------------------------------
# Simple JWT-like token auth. Users are stored in config.yaml.
# Tokens are HMAC-SHA256 signed. No external dependencies.

_AUTH_SECRET = b"netmon-auth-secret-2026"  # Change for production
_AUTH_TOKEN_EXPIRY = 86400  # 24 hours

# Roles: admin (full access), operator (can ack alerts, toggle maint),
#         viewer (read-only)
AUTH_ROLES = {
    "admin": {"read", "write", "config", "users"},
    "operator": {"read", "write"},
    "viewer": {"read"},
}


def _generate_auth_token(username, role):
    """Generate a signed token for a user."""
    expires = int(time.time()) + _AUTH_TOKEN_EXPIRY
    payload = "%s:%s:%d" % (username, role, expires)
    sig = hmac.new(_AUTH_SECRET, payload.encode("utf-8"),
                   hashlib.sha256).hexdigest()[:32]
    token = base64.urlsafe_b64encode(
        ("%s:%s" % (payload, sig)).encode("utf-8")).decode("ascii")
    return token


def _validate_auth_token(token):
    """Validate a token. Returns (username, role) or (None, None)."""
    try:
        decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        parts = decoded.rsplit(":", 1)
        if len(parts) != 2:
            return None, None
        payload, provided_sig = parts
        expected_sig = hmac.new(_AUTH_SECRET, payload.encode("utf-8"),
                                hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(provided_sig, expected_sig):
            return None, None
        username, role, expires_str = payload.split(":")
        if int(expires_str) < int(time.time()):
            return None, None
        return username, role
    except Exception:
        return None, None


def _check_auth(required_perm="read"):
    """Check if auth is enabled and if so, validate the request.
    Returns (username, role) or aborts with 401.
    If auth is disabled (not Enterprise or no users configured), returns guest access.
    """
    if get_tier() != TIER_ENT:
        return ("guest", "admin")  # No auth on non-enterprise tiers

    with _config_lock:
        users = _config.get("users", [])
    if not users:
        return ("admin", "admin")  # No users configured = open access

    # Check Authorization header or cookie
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        token = request.cookies.get("netmon_token", "")
    if not token:
        abort(401)

    username, role = _validate_auth_token(token)
    if not username:
        abort(401)

    perms = AUTH_ROLES.get(role, set())
    if required_perm not in perms:
        abort(403)

    return (username, role)


# ---------------------------------------------------------------------------
# Network Discovery Scanner
# ---------------------------------------------------------------------------

COMMON_PORTS = [22, 23, 53, 80, 443, 161, 445, 3389, 5900, 8080, 8443]
PORT_NAMES = {
    22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    161: "SNMP", 445: "SMB", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

_scan_lock = threading.Lock()
_scan_state = {
    "running": False,
    "scan_id": None,
    "total": 0,
    "scanned": 0,
    "alive": 0,
    "target": "",
    "started_at": None,
    "finished_at": None,
    "results": [],
}


def parse_ip_range(range_str):
    """Parse CIDR, range (1.1.1.1-1.1.1.254), or single IP into list of IPs."""
    range_str = range_str.strip()
    ips = []
    if "/" in range_str:
        try:
            net = ipaddress.ip_network(range_str, strict=False)
            for addr in net.hosts():
                ips.append(str(addr))
        except ValueError as e:
            raise ValueError("Invalid CIDR: " + str(e))
    elif "-" in range_str:
        parts = range_str.split("-")
        start_str = parts[0].strip()
        end_str = parts[1].strip()
        try:
            start_ip = ipaddress.ip_address(start_str)
        except ValueError:
            raise ValueError("Invalid start IP: " + start_str)
        if "." in end_str:
            try:
                end_ip = ipaddress.ip_address(end_str)
            except ValueError:
                raise ValueError("Invalid end IP: " + end_str)
        else:
            base = ".".join(start_str.split(".")[:-1])
            try:
                end_ip = ipaddress.ip_address(base + "." + end_str)
            except ValueError:
                raise ValueError("Invalid end octet: " + end_str)
        if int(end_ip) < int(start_ip):
            raise ValueError("End IP must be >= start IP")
        count = int(end_ip) - int(start_ip) + 1
        if count > 1024:
            raise ValueError("Range too large (max 1024 IPs)")
        for i in range(count):
            ips.append(str(ipaddress.ip_address(int(start_ip) + i)))
    else:
        try:
            ipaddress.ip_address(range_str)
            ips.append(range_str)
        except ValueError:
            try:
                resolved = socket.gethostbyname(range_str)
                ips.append(resolved)
            except Exception:
                raise ValueError("Invalid IP or hostname: " + range_str)
    return ips


def reverse_dns(ip):
    """Attempt reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return ""


def _scan_worker(ip, scan_ports_list, port_timeout, results_list, results_lock):
    """Scan a single IP: ping + port scan + reverse DNS."""
    alive, ms = ping_single(ip, timeout_ms=2000)
    hostname = ""
    open_ports = []

    if alive:
        hostname = reverse_dns(ip)
        if scan_ports_list:
            open_ports = scan_ports(ip, scan_ports_list, timeout_ms=port_timeout)

    entry = {
        "ip": ip,
        "hostname": hostname,
        "is_alive": alive,
        "open_ports": open_ports,
        "response_ms": ms,
    }

    with results_lock:
        results_list.append(entry)
    with _scan_lock:
        _scan_state["scanned"] += 1
        if alive:
            _scan_state["alive"] += 1


def run_scan(ip_range_str, scan_port_list=None, port_timeout=1000, max_threads=50,
             auto_inventory=True):
    """Run a network scan in background."""
    global _scan_state

    try:
        ips = parse_ip_range(ip_range_str)
    except ValueError as e:
        with _scan_lock:
            _scan_state["running"] = False
            _scan_state["finished_at"] = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat()
        log.error("Scan parse error: %s", e)
        return

    scan_id = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).strftime("%Y%m%d_%H%M%S")

    with _scan_lock:
        _scan_state["running"] = True
        _scan_state["scan_id"] = scan_id
        _scan_state["total"] = len(ips)
        _scan_state["scanned"] = 0
        _scan_state["alive"] = 0
        _scan_state["target"] = ip_range_str
        _scan_state["started_at"] = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat()
        _scan_state["finished_at"] = None
        _scan_state["results"] = []

    log.info("Scan started: %s (%d IPs)", ip_range_str, len(ips))

    results_list = []
    results_lock = threading.Lock()
    active_threads = []

    for ip in ips:
        while len(active_threads) >= max_threads:
            active_threads = [t for t in active_threads if t.is_alive()]
            if len(active_threads) >= max_threads:
                time.sleep(0.1)

        t = threading.Thread(target=_scan_worker,
                             args=(ip, scan_port_list or COMMON_PORTS, port_timeout,
                                   results_list, results_lock))
        t.start()
        active_threads.append(t)

    for t in active_threads:
        t.join(timeout=30)

    results_list.sort(key=lambda x: tuple(int(p) for p in x["ip"].split(".")))

    # Only keep alive hosts
    alive_results = [r for r in results_list if r["is_alive"]]

    conn = sqlite3.connect(str(DB_PATH))
    for r in alive_results:
        conn.execute(
            "INSERT INTO scan_results (scan_id,timestamp,ip,hostname,is_alive,open_ports,response_ms,added_to_devices) "
            "VALUES (?,?,?,?,?,?,?,0)",
            (scan_id, datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat(), r["ip"], r["hostname"],
             int(r["is_alive"]), ",".join(str(p) for p in r["open_ports"]),
             r["response_ms"]))
    conn.commit()
    conn.close()

    with _scan_lock:
        _scan_state["running"] = False
        _scan_state["finished_at"] = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat()
        _scan_state["results"] = alive_results

    if auto_inventory:
        result = import_scan_to_inventory(scan_id)
        log.info("Inventory updated: %d new, %d updated", result["imported"], result["updated"])

    log.info("Scan complete: %d/%d alive", _scan_state["alive"], _scan_state["total"])


# ---------------------------------------------------------------------------
# Monitoring loop
# ---------------------------------------------------------------------------
_prev_status = {}
_acked_keys = set()   # keys that have been acknowledged (suppress re-alert)

def monitoring_loop():
    while True:
        _reload_config()
        with _config_lock:
            cfg = dict(_config)
        devices = cfg.get("devices", [])
        interval = cfg.get("check_interval_seconds", 60)
        smtp_cfg = cfg.get("smtp", {})

        # Build dependency data
        parent_map = _get_parent_map(devices)
        status_list = get_latest_per_check()
        status_map = _get_device_status_map(status_list)

        # Get devices currently in scheduled downtime
        downtime_devices = get_active_downtimes()

        log.info("-- Check cycle: %d devices --", len(devices))
        threads = []
        results = []
        results_lock = threading.Lock()

        def _run(dev, chk):
            r = run_check(dev, chk)
            with results_lock:
                results.append((dev, r))

        for dev in devices:
            dev_name = dev["name"]
            # Skip if in maintenance mode or scheduled downtime
            if dev.get("maintenance", False) or dev_name in downtime_devices:
                reason = "maintenance mode" if dev.get("maintenance") else "scheduled downtime"
                log.info("  [SKIP] %s -- %s", dev_name, reason)
                continue
            # Skip if parent is down (dependency suppression)
            if is_parent_down(dev_name, parent_map, status_map):
                log.info("  [PARENT DOWN] %s -- parent unreachable, skipping", dev_name)
                continue
            for chk in dev.get("checks", []):
                t = threading.Thread(target=_run, args=(dev, chk))
                t.start()
                threads.append(t)

        for t in threads:
            t.join(timeout=30)

        for dev, r in results:
            store_result(r)
            key = r["device_name"] + "|" + (r.get("check_label") or "")
            prev = _prev_status.get(key)
            status_str = r["status"]
            ms_str = ("%.1fms" % r["response_ms"]) if r["response_ms"] is not None else "N/A"
            log.info("  [%s] %s / %s  %s  %s",
                     status_str, r["device_name"], r.get("check_label", ""), ms_str,
                     r.get("message", ""))

            if status_str in ("WARNING", "CRITICAL"):
                # Only alert if status changed AND not acknowledged
                if prev != status_str and key not in _acked_keys:
                    emailed = send_alert_email(r, smtp_cfg)
                    store_alert(r, email_sent=emailed)
                    # Multi-channel webhooks (Enterprise)
                    webhooks = cfg.get("webhooks", [])
                    if webhooks:
                        send_webhook_notification(r, webhooks)
                    # Auto-create helpdesk ticket (Pro+)
                    if status_str == "CRITICAL":
                        threading.Thread(
                            target=create_ticket_from_alert,
                            args=(dict(r),),
                            daemon=True,
                        ).start()
            elif status_str == "OK" and prev in ("WARNING", "CRITICAL"):
                # Recovery: clear ack so future failures trigger alerts again
                _acked_keys.discard(key)

            _prev_status[key] = status_str

        log.info("-- Cycle done. Next in %ds --", interval)
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Helpdesk Connector (Pro+)
# ---------------------------------------------------------------------------
# Integrates with Freshservice and ConnectWise Manage to pull tickets into
# the dashboard and optionally auto-create tickets from Critical alerts.
# ---------------------------------------------------------------------------

_helpdesk_sync_state = {
    "running": False,
    "last_sync": None,
    "last_error": None,
    "ticket_count": 0,
}
_helpdesk_lock = threading.Lock()


def _get_helpdesk_config():
    """Get helpdesk config from main config."""
    with _config_lock:
        return dict(_config.get("helpdesk", {}))


def _freshservice_fetch_tickets(cfg):
    """Fetch tickets from Freshservice REST API v2."""
    if not req_lib:
        raise RuntimeError("requests library required for helpdesk integration")

    domain = cfg.get("domain", "").strip()
    api_key = cfg.get("api_key", "").strip()
    if not domain or not api_key:
        raise ValueError("Freshservice domain and API key are required")

    # Ensure domain format
    if not domain.startswith("http"):
        domain = "https://%s" % domain
    if ".freshservice.com" not in domain:
        domain = domain.rstrip("/") + ".freshservice.com"

    base_url = domain.rstrip("/")
    headers = {"Content-Type": "application/json"}
    auth = (api_key, "X")  # Freshservice uses API key as username, X as password

    tickets = []
    page = 1
    per_page = 100
    max_pages = 10  # Safety limit

    while page <= max_pages:
        url = "%s/api/v2/tickets?per_page=%d&page=%d&include=requester" % (
            base_url, per_page, page)
        resp = req_lib.get(url, auth=auth, headers=headers, timeout=30)
        if resp.status_code == 401:
            raise ValueError("Freshservice authentication failed -- check API key")
        if resp.status_code == 404:
            raise ValueError("Freshservice domain not found -- check domain setting")
        resp.raise_for_status()

        data = resp.json()
        page_tickets = data.get("tickets", [])
        if not page_tickets:
            break

        for t in page_tickets:
            priority_map = {1: "Low", 2: "Medium", 3: "High", 4: "Urgent"}
            status_map = {2: "Open", 3: "Pending", 4: "Resolved", 5: "Closed"}
            tickets.append({
                "remote_id": str(t.get("id", "")),
                "provider": "freshservice",
                "subject": t.get("subject", ""),
                "description": (t.get("description_text") or "")[:2000],
                "status": status_map.get(t.get("status"), str(t.get("status", ""))),
                "priority": priority_map.get(t.get("priority"), str(t.get("priority", ""))),
                "ticket_type": t.get("type") or "",
                "assignee": "",
                "requester": t.get("requester", {}).get("name", "") if isinstance(t.get("requester"), dict) else "",
                "created_at": t.get("created_at", ""),
                "updated_at": t.get("updated_at", ""),
                "due_date": t.get("due_by", ""),
                "url": "%s/a/tickets/%s" % (base_url, t.get("id", "")),
                "raw_json": json_mod.dumps(t, default=str),
            })

        if len(page_tickets) < per_page:
            break
        page += 1

    return tickets


def _freshservice_create_ticket(cfg, subject, description, priority="Medium",
                                 requester_email=""):
    """Create a ticket in Freshservice."""
    if not req_lib:
        raise RuntimeError("requests library required")

    domain = cfg.get("domain", "").strip()
    api_key = cfg.get("api_key", "").strip()
    if not domain or not api_key:
        raise ValueError("Freshservice domain and API key are required")

    if not domain.startswith("http"):
        domain = "https://%s" % domain
    if ".freshservice.com" not in domain:
        domain = domain.rstrip("/") + ".freshservice.com"

    base_url = domain.rstrip("/")
    auth = (api_key, "X")

    priority_map = {"Low": 1, "Medium": 2, "High": 3, "Urgent": 4}
    payload = {
        "subject": subject,
        "description": description,
        "priority": priority_map.get(priority, 2),
        "status": 2,  # Open
    }
    if requester_email:
        payload["email"] = requester_email
    else:
        payload["email"] = cfg.get("default_requester_email", "netmon@localhost")

    resp = req_lib.post(
        "%s/api/v2/tickets" % base_url,
        auth=auth,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("ticket", {})


def _connectwise_fetch_tickets(cfg):
    """Fetch tickets from ConnectWise Manage REST API."""
    if not req_lib:
        raise RuntimeError("requests library required for helpdesk integration")

    site_url = cfg.get("site_url", "").strip().rstrip("/")
    company_id = cfg.get("company_id", "").strip()
    public_key = cfg.get("public_key", "").strip()
    private_key = cfg.get("private_key", "").strip()
    client_id = cfg.get("client_id", "").strip()

    if not all([site_url, company_id, public_key, private_key, client_id]):
        raise ValueError(
            "ConnectWise requires site_url, company_id, public_key, "
            "private_key, and client_id"
        )

    # ConnectWise uses Basic auth: company_id+public_key:private_key
    auth_token = base64.b64encode(
        ("%s+%s:%s" % (company_id, public_key, private_key)).encode()
    ).decode()

    headers = {
        "Authorization": "Basic %s" % auth_token,
        "Content-Type": "application/json",
        "clientId": client_id,
    }

    tickets = []
    page = 1
    page_size = 200
    max_pages = 10

    while page <= max_pages:
        url = "%s/v4_6_release/apis/3.0/service/tickets" % site_url
        params = {
            "pageSize": page_size,
            "page": page,
            "orderBy": "id desc",
        }
        resp = req_lib.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 401:
            raise ValueError("ConnectWise authentication failed -- check credentials")
        resp.raise_for_status()

        page_tickets = resp.json()
        if not page_tickets:
            break

        for t in page_tickets:
            priority_name = ""
            if isinstance(t.get("priority"), dict):
                priority_name = t["priority"].get("name", "")
            status_name = ""
            if isinstance(t.get("status"), dict):
                status_name = t["status"].get("name", "")
            assignee_name = ""
            if isinstance(t.get("owner"), dict):
                assignee_name = t["owner"].get("name", "")
            requester_name = ""
            if isinstance(t.get("contact"), dict):
                requester_name = t["contact"].get("name", "")
            company_name = ""
            if isinstance(t.get("company"), dict):
                company_name = t["company"].get("name", "")

            tickets.append({
                "remote_id": str(t.get("id", "")),
                "provider": "connectwise",
                "subject": t.get("summary", ""),
                "description": (t.get("initialDescription") or "")[:2000],
                "status": status_name,
                "priority": priority_name,
                "ticket_type": t.get("type", {}).get("name", "") if isinstance(t.get("type"), dict) else "",
                "assignee": assignee_name,
                "requester": requester_name or company_name,
                "created_at": t.get("dateEntered", ""),
                "updated_at": t.get("lastUpdated", ""),
                "due_date": t.get("requiredDate", ""),
                "url": "%s/v4_6_release/services/system_io/Service/fv_sr100_request.rails?service_recid=%s" % (
                    site_url, t.get("id", "")),
                "raw_json": json_mod.dumps(t, default=str),
            })

        if len(page_tickets) < page_size:
            break
        page += 1

    return tickets


def _connectwise_create_ticket(cfg, subject, description, priority="Medium",
                                company_id_ref=None):
    """Create a ticket in ConnectWise Manage."""
    if not req_lib:
        raise RuntimeError("requests library required")

    site_url = cfg.get("site_url", "").strip().rstrip("/")
    company_id = cfg.get("company_id", "").strip()
    public_key = cfg.get("public_key", "").strip()
    private_key = cfg.get("private_key", "").strip()
    client_id = cfg.get("client_id", "").strip()

    auth_token = base64.b64encode(
        ("%s+%s:%s" % (company_id, public_key, private_key)).encode()
    ).decode()

    headers = {
        "Authorization": "Basic %s" % auth_token,
        "Content-Type": "application/json",
        "clientId": client_id,
    }

    payload = {
        "summary": subject,
        "initialDescription": description,
    }
    if company_id_ref:
        payload["company"] = {"id": company_id_ref}
    default_board = cfg.get("default_board_id")
    if default_board:
        payload["board"] = {"id": int(default_board)}

    resp = req_lib.post(
        "%s/v4_6_release/apis/3.0/service/tickets" % site_url,
        headers=headers,
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def sync_helpdesk_tickets(force=False):
    """Sync tickets from the configured helpdesk provider into local DB."""
    hd_cfg = _get_helpdesk_config()
    provider = hd_cfg.get("provider", "").strip().lower()

    if not provider:
        return {"ok": False, "error": "No helpdesk provider configured"}

    with _helpdesk_lock:
        if _helpdesk_sync_state["running"] and not force:
            return {"ok": False, "error": "Sync already in progress"}
        _helpdesk_sync_state["running"] = True

    try:
        if provider == "freshservice":
            fs_cfg = hd_cfg.get("freshservice", {})
            tickets = _freshservice_fetch_tickets(fs_cfg)
        elif provider == "connectwise":
            cw_cfg = hd_cfg.get("connectwise", {})
            tickets = _connectwise_fetch_tickets(cw_cfg)
        else:
            raise ValueError("Unknown helpdesk provider: %s" % provider)

        # Upsert into local DB
        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        conn = sqlite3.connect(str(DB_PATH))
        c = conn.cursor()

        for t in tickets:
            c.execute(
                "SELECT id FROM helpdesk_tickets WHERE provider=? AND remote_id=?",
                (t["provider"], t["remote_id"]),
            )
            existing = c.fetchone()
            if existing:
                c.execute(
                    """UPDATE helpdesk_tickets SET
                        subject=?, description=?, status=?, priority=?,
                        ticket_type=?, assignee=?, requester=?,
                        created_at=?, updated_at=?, due_date=?,
                        url=?, raw_json=?, synced_at=?
                    WHERE provider=? AND remote_id=?""",
                    (
                        t["subject"], t["description"], t["status"], t["priority"],
                        t["ticket_type"], t["assignee"], t["requester"],
                        t["created_at"], t["updated_at"], t["due_date"],
                        t["url"], t["raw_json"], now,
                        t["provider"], t["remote_id"],
                    ),
                )
            else:
                c.execute(
                    """INSERT INTO helpdesk_tickets
                        (remote_id, provider, subject, description, status,
                         priority, ticket_type, assignee, requester,
                         created_at, updated_at, due_date, url, raw_json, synced_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        t["remote_id"], t["provider"], t["subject"],
                        t["description"], t["status"], t["priority"],
                        t["ticket_type"], t["assignee"], t["requester"],
                        t["created_at"], t["updated_at"], t["due_date"],
                        t["url"], t["raw_json"], now,
                    ),
                )

        conn.commit()
        conn.close()

        with _helpdesk_lock:
            _helpdesk_sync_state["running"] = False
            _helpdesk_sync_state["last_sync"] = now
            _helpdesk_sync_state["last_error"] = None
            _helpdesk_sync_state["ticket_count"] = len(tickets)

        log.info("Helpdesk sync complete: %d tickets from %s", len(tickets), provider)
        return {"ok": True, "synced": len(tickets), "provider": provider}

    except Exception as e:
        log.error("Helpdesk sync failed: %s", e)
        with _helpdesk_lock:
            _helpdesk_sync_state["running"] = False
            _helpdesk_sync_state["last_error"] = str(e)
        return {"ok": False, "error": str(e)}


def helpdesk_sync_loop():
    """Background thread that periodically syncs helpdesk tickets."""
    time.sleep(10)  # Initial delay
    while True:
        hd_cfg = _get_helpdesk_config()
        provider = hd_cfg.get("provider", "").strip()
        interval = int(hd_cfg.get("sync_interval_minutes", 5))
        if interval < 1:
            interval = 1

        if provider:
            sync_helpdesk_tickets()

        time.sleep(interval * 60)


def create_ticket_from_alert(result):
    """Auto-create a helpdesk ticket from a monitoring alert result."""
    hd_cfg = _get_helpdesk_config()
    provider = hd_cfg.get("provider", "").strip().lower()
    if not hd_cfg.get("auto_create_tickets", False) or not provider:
        return None

    subject = "[NetMon Alert] %s -- %s %s" % (
        result.get("device_name", "Unknown"),
        result.get("status", "CRITICAL"),
        result.get("check_label", ""),
    )
    description = (
        "MyClover.Tech.netmon auto-generated ticket\n\n"
        "Device: %s\n"
        "Host: %s\n"
        "Check: %s (%s)\n"
        "Status: %s\n"
        "Message: %s\n"
        "Response Time: %s\n"
        "Timestamp: %s"
    ) % (
        result.get("device_name", ""),
        result.get("host", ""),
        result.get("check_label", ""),
        result.get("check_type", ""),
        result.get("status", ""),
        result.get("message", ""),
        ("%.1fms" % result["response_ms"]) if result.get("response_ms") is not None else "N/A",
        result.get("timestamp", ""),
    )
    priority = "Urgent" if result.get("status") == "CRITICAL" else "High"

    try:
        if provider == "freshservice":
            fs_cfg = hd_cfg.get("freshservice", {})
            ticket = _freshservice_create_ticket(fs_cfg, subject, description, priority)
            log.info("Auto-created Freshservice ticket #%s for %s",
                     ticket.get("id", "?"), result.get("device_name", ""))
            return ticket
        elif provider == "connectwise":
            cw_cfg = hd_cfg.get("connectwise", {})
            ticket = _connectwise_create_ticket(cw_cfg, subject, description, priority)
            log.info("Auto-created ConnectWise ticket #%s for %s",
                     ticket.get("id", "?"), result.get("device_name", ""))
            return ticket
    except Exception as e:
        log.error("Failed to auto-create helpdesk ticket: %s", e)
    return None


# ---------------------------------------------------------------------------
# Flask dashboard + API
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Security Scanner (Enterprise)
# ---------------------------------------------------------------------------

_secscan_lock = threading.Lock()
_secscan_state = {}  # current running scan state

SEC_COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "WebUI",
    9200: "Elasticsearch", 27017: "MongoDB",
}

WEAK_SSL_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

HTTP_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

SNMP_DEFAULT_COMMUNITIES = ["public", "private", "community", "snmp", "monitor",
                            "admin", "default", "test", "read", "write"]


def _sec_port_scan(host, timeout_s=2):
    """Scan common ports on a host. Returns list of (port, service, banner)."""
    open_ports = []
    for port, svc in sorted(SEC_COMMON_PORTS.items()):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_s)
            result = s.connect_ex((host, port))
            if result == 0:
                banner = ""
                try:
                    if port not in (80, 443, 8080, 8443):
                        s.settimeout(2)
                        s.sendall(b"\r\n")
                        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                        banner = banner[:200]
                except Exception:
                    pass
                open_ports.append({"port": port, "service": svc, "banner": banner})
            s.close()
        except Exception:
            pass
    return open_ports


def _sec_ssl_check(host, port=443, timeout_s=5):
    """Check SSL/TLS configuration. Returns dict of findings."""
    findings = []
    cert_info = {}
    try:
        ctx = ssl_mod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                protocol = ssock.version()
                cert_info["protocol"] = protocol or "Unknown"
                cert_info["cipher"] = cipher[0] if cipher else "Unknown"
                cert_info["bits"] = cipher[2] if cipher and len(cipher) > 2 else 0
                if cert:
                    not_after = cert.get("notAfter", "")
                    not_before = cert.get("notBefore", "")
                    subject = dict(x[0] for x in cert.get("subject", ()) if x)
                    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
                    cert_info["subject_cn"] = subject.get("commonName", "")
                    cert_info["issuer_cn"] = issuer.get("commonName", "")
                    cert_info["not_before"] = not_before
                    cert_info["not_after"] = not_after
                    if not_after:
                        try:
                            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp - datetime.datetime.now(datetime.UTC).replace(tzinfo=None)).days
                            cert_info["days_until_expiry"] = days_left
                            if days_left < 0:
                                findings.append({
                                    "severity": "critical",
                                    "title": "SSL certificate expired",
                                    "description": "Certificate expired %d days ago" % abs(days_left),
                                    "remediation": "Renew the SSL certificate immediately.",
                                })
                            elif days_left < 30:
                                findings.append({
                                    "severity": "high",
                                    "title": "SSL certificate expiring soon",
                                    "description": "Certificate expires in %d days (on %s)" % (days_left, not_after),
                                    "remediation": "Renew the SSL certificate before it expires.",
                                })
                        except Exception:
                            pass
                else:
                    findings.append({
                        "severity": "high",
                        "title": "No SSL certificate presented",
                        "description": "The server did not present a certificate.",
                        "remediation": "Configure a valid SSL certificate.",
                    })
                if protocol in WEAK_SSL_PROTOCOLS:
                    findings.append({
                        "severity": "high",
                        "title": "Weak SSL/TLS protocol: %s" % protocol,
                        "description": "Server uses %s which has known vulnerabilities." % protocol,
                        "remediation": "Disable %s and use TLS 1.2 or 1.3." % protocol,
                    })
                if cipher and cipher[2] < 128:
                    findings.append({
                        "severity": "high",
                        "title": "Weak cipher: %s (%d-bit)" % (cipher[0], cipher[2]),
                        "description": "Cipher uses less than 128-bit encryption.",
                        "remediation": "Configure stronger cipher suites (AES-128 or AES-256).",
                    })
    except ssl_mod.SSLError as e:
        findings.append({
            "severity": "medium",
            "title": "SSL connection error",
            "description": str(e)[:200],
            "remediation": "Check SSL/TLS configuration on the server.",
        })
    except (socket.timeout, ConnectionRefusedError, OSError):
        cert_info["error"] = "Cannot connect to %s:%d" % (host, port)
    try:
        ctx2 = ssl_mod.create_default_context()
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                pass
        cert_info["trusted"] = True
    except ssl_mod.SSLCertVerificationError as e:
        cert_info["trusted"] = False
        findings.append({
            "severity": "medium",
            "title": "SSL certificate not trusted",
            "description": str(e)[:200],
            "remediation": "Use a certificate from a trusted CA (e.g., Let's Encrypt).",
        })
    except Exception:
        pass
    return {"cert_info": cert_info, "findings": findings}


def _sec_http_headers(host, port=80, use_ssl=False, timeout_s=5):
    """Check HTTP security headers. Returns list of findings."""
    findings = []
    headers_found = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        if use_ssl:
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.connect((host, port))
        req = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host
        s.sendall(req.encode("utf-8"))
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 16384:
                break
        s.close()
        header_block = response.split(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers_found[k.strip()] = v.strip()
        for hdr in HTTP_SECURITY_HEADERS:
            found = False
            for k in headers_found:
                if k.lower() == hdr.lower():
                    found = True
                    break
            if not found:
                sev = "high" if hdr in ("Strict-Transport-Security", "Content-Security-Policy") else "medium"
                findings.append({
                    "severity": sev,
                    "title": "Missing HTTP header: %s" % hdr,
                    "description": "The %s header is not set." % hdr,
                    "remediation": "Add the %s header to your web server configuration." % hdr,
                })
        server_hdr = headers_found.get("Server", "")
        if not server_hdr:
            for k, v in headers_found.items():
                if k.lower() == "server":
                    server_hdr = v
                    break
        if server_hdr and any(s in server_hdr.lower() for s in ["apache/", "nginx/", "iis/", "lighttpd/"]):
            findings.append({
                "severity": "low",
                "title": "Server version disclosed: %s" % server_hdr,
                "description": "The Server header reveals software version information.",
                "remediation": "Remove or obfuscate the Server header to reduce information leakage.",
            })
        powered = headers_found.get("X-Powered-By", "")
        if not powered:
            for k, v in headers_found.items():
                if k.lower() == "x-powered-by":
                    powered = v
                    break
        if powered:
            findings.append({
                "severity": "low",
                "title": "X-Powered-By disclosed: %s" % powered,
                "description": "The X-Powered-By header reveals technology stack.",
                "remediation": "Remove the X-Powered-By header.",
            })
    except Exception:
        pass
    return {"headers": headers_found, "findings": findings}


def _sec_snmp_check(host, timeout_s=3):
    """Check for default SNMP community strings."""
    findings = []
    weak_communities = []
    for community in SNMP_DEFAULT_COMMUNITIES:
        try:
            result = subprocess.run(
                ["snmpget", "-v2c", "-c", community, "-t", str(timeout_s),
                 "-r", "0", host, "1.3.6.1.2.1.1.1.0"],
                capture_output=True, text=True, timeout=timeout_s + 2
            )
            if result.returncode == 0 and "SNMPv2" in result.stdout:
                weak_communities.append(community)
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
    if weak_communities:
        findings.append({
            "severity": "critical" if "public" in weak_communities or "private" in weak_communities else "high",
            "title": "Default SNMP community string(s) accepted",
            "description": "The following default community strings are accepted: %s" % ", ".join(weak_communities),
            "remediation": "Change SNMP community strings to unique, complex values. "
                           "Consider using SNMPv3 with authentication and encryption.",
        })
    return {"weak_communities": weak_communities, "findings": findings}


def _sec_dns_check(host, timeout_s=5):
    """Check DNS for zone transfer vulnerability."""
    findings = []
    try:
        result = subprocess.run(
            ["nslookup", "-type=AXFR", host, host],
            capture_output=True, text=True, timeout=timeout_s + 2
        )
        output = result.stdout + result.stderr
        if "transfer" in output.lower() and "failed" not in output.lower():
            findings.append({
                "severity": "high",
                "title": "DNS zone transfer may be allowed",
                "description": "The DNS server at %s may allow zone transfers (AXFR)." % host,
                "remediation": "Restrict DNS zone transfers to authorized secondary servers only.",
            })
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    return {"findings": findings}


def _sec_service_checks(host, open_ports):
    """Check for risky service configurations on open ports."""
    findings = []
    port_numbers = [p["port"] for p in open_ports]
    if 21 in port_numbers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, 21))
            banner = s.recv(1024).decode("utf-8", errors="replace")
            s.sendall(b"USER anonymous\r\n")
            resp = s.recv(1024).decode("utf-8", errors="replace")
            if "331" in resp:
                s.sendall(b"PASS anonymous@\r\n")
                resp2 = s.recv(1024).decode("utf-8", errors="replace")
                if "230" in resp2:
                    findings.append({
                        "severity": "critical",
                        "title": "FTP anonymous login enabled",
                        "description": "The FTP server allows anonymous login.",
                        "remediation": "Disable anonymous FTP access unless explicitly required.",
                    })
            s.close()
        except Exception:
            pass
    if 23 in port_numbers:
        findings.append({
            "severity": "high",
            "title": "Telnet service running (port 23)",
            "description": "Telnet transmits data in cleartext including credentials.",
            "remediation": "Replace Telnet with SSH. Disable the Telnet service.",
        })
    if 3389 in port_numbers:
        findings.append({
            "severity": "medium",
            "title": "RDP service exposed (port 3389)",
            "description": "Remote Desktop is accessible. Verify NLA is enabled.",
            "remediation": "Enable Network Level Authentication (NLA). Use VPN to restrict RDP access.",
        })
    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
                1521: "Oracle", 6379: "Redis", 27017: "MongoDB",
                9200: "Elasticsearch"}
    for p, name in db_ports.items():
        if p in port_numbers:
            findings.append({
                "severity": "high",
                "title": "%s exposed (port %d)" % (name, p),
                "description": "%s is listening on a network interface." % name,
                "remediation": "Bind %s to localhost or use firewall rules. "
                               "Never expose databases directly to the network." % name,
            })
    if 6379 in port_numbers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((host, 6379))
            s.sendall(b"PING\r\n")
            resp = s.recv(1024).decode("utf-8", errors="replace")
            s.close()
            if "+PONG" in resp:
                findings.append({
                    "severity": "critical",
                    "title": "Redis accessible without authentication",
                    "description": "Redis responds to PING without credentials.",
                    "remediation": "Enable Redis AUTH and bind to localhost.",
                })
        except Exception:
            pass
    if 5900 in port_numbers:
        findings.append({
            "severity": "high",
            "title": "VNC service exposed (port 5900)",
            "description": "VNC is accessible on the network.",
            "remediation": "Restrict VNC access via VPN or firewall. Use SSH tunneling.",
        })
    if 445 in port_numbers:
        findings.append({
            "severity": "medium",
            "title": "SMB service exposed (port 445)",
            "description": "SMB/CIFS is accessible. Check for SMBv1 and guest access.",
            "remediation": "Disable SMBv1. Require authentication. Restrict via firewall.",
        })
    return findings


def run_security_scan(targets, scan_types, scan_id=None):
    """Run a security scan against one or more targets."""
    if scan_id is None:
        scan_id = "sec-%s" % secrets.token_hex(6)
    started = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO security_scans (scan_id, started_at, targets, scan_types, status) "
        "VALUES (?, ?, ?, ?, 'running')",
        (scan_id, started, json_mod.dumps(targets), json_mod.dumps(scan_types))
    )
    conn.commit()
    conn.close()
    with _secscan_lock:
        _secscan_state["scan_id"] = scan_id
        _secscan_state["status"] = "running"
        _secscan_state["targets"] = targets
        _secscan_state["progress"] = 0
        _secscan_state["current_target"] = ""
        _secscan_state["current_test"] = ""
    all_findings = []
    total_steps = len(targets) * len(scan_types)
    step = 0
    def _cancelled():
        with _secscan_lock:
            return _secscan_state.get("status") == "cancelling"
    for target in targets:
        if _cancelled():
            break
        with _secscan_lock:
            _secscan_state["current_target"] = target
        target_findings = []
        open_ports = []
        if "ports" in scan_types and not _cancelled():
            with _secscan_lock:
                _secscan_state["current_test"] = "Port scan"
            open_ports = _sec_port_scan(target)
            if not open_ports:
                target_findings.append({
                    "target": target, "category": "ports", "severity": "info",
                    "title": "No common ports open",
                    "description": "None of the %d scanned common ports are open." % len(SEC_COMMON_PORTS),
                    "details": json_mod.dumps({"scanned_count": len(SEC_COMMON_PORTS)}),
                    "remediation": "",
                })
            else:
                target_findings.append({
                    "target": target, "category": "ports", "severity": "info",
                    "title": "%d open port(s) found" % len(open_ports),
                    "description": "Open: %s" % ", ".join(
                        "%d/%s" % (p["port"], p["service"]) for p in open_ports),
                    "details": json_mod.dumps({"open_ports": open_ports}),
                    "remediation": "Review each open port and close unnecessary services.",
                })
                if len(open_ports) > 10:
                    target_findings.append({
                        "target": target, "category": "ports", "severity": "medium",
                        "title": "Large number of open ports (%d)" % len(open_ports),
                        "description": "Having many open ports increases the attack surface.",
                        "remediation": "Close unnecessary ports. Apply firewall rules.",
                    })
            step += 1
            with _secscan_lock:
                _secscan_state["progress"] = int(step * 100 / total_steps)
        if "ssl" in scan_types and not _cancelled():
            with _secscan_lock:
                _secscan_state["current_test"] = "SSL/TLS analysis"
            ssl_ports = [p["port"] for p in open_ports if p["port"] in (443, 8443, 993, 995, 636)]
            if not ssl_ports and not open_ports:
                ssl_ports = [443]
            for sp in ssl_ports:
                ssl_result = _sec_ssl_check(target, sp)
                for f in ssl_result.get("findings", []):
                    f["target"] = target
                    f["category"] = "ssl"
                    f["details"] = json_mod.dumps(ssl_result.get("cert_info", {}))
                    target_findings.append(f)
                if ssl_result.get("cert_info") and not ssl_result.get("cert_info", {}).get("error"):
                    ci = ssl_result["cert_info"]
                    target_findings.append({
                        "target": target, "category": "ssl", "severity": "info",
                        "title": "SSL certificate on port %d" % sp,
                        "description": "Protocol: %s, Cipher: %s (%s-bit), CN: %s, Issuer: %s" % (
                            ci.get("protocol", "?"), ci.get("cipher", "?"),
                            ci.get("bits", "?"), ci.get("subject_cn", "?"),
                            ci.get("issuer_cn", "?")),
                        "details": json_mod.dumps(ci),
                        "remediation": "",
                    })
            step += 1
            with _secscan_lock:
                _secscan_state["progress"] = int(step * 100 / total_steps)
        if "http" in scan_types and not _cancelled():
            with _secscan_lock:
                _secscan_state["current_test"] = "HTTP headers"
            http_ports = [(p["port"], p["port"] in (443, 8443))
                          for p in open_ports if p["port"] in (80, 443, 8080, 8443)]
            if not http_ports and not open_ports:
                http_ports = [(80, False)]
            for hp, use_ssl in http_ports:
                hdr_result = _sec_http_headers(target, hp, use_ssl)
                for f in hdr_result.get("findings", []):
                    f["target"] = target
                    f["category"] = "http"
                    f["details"] = json_mod.dumps({"port": hp, "headers": hdr_result.get("headers", {})})
                    target_findings.append(f)
            step += 1
            with _secscan_lock:
                _secscan_state["progress"] = int(step * 100 / total_steps)
        if "snmp" in scan_types and not _cancelled():
            with _secscan_lock:
                _secscan_state["current_test"] = "SNMP community"
            snmp_result = _sec_snmp_check(target)
            for f in snmp_result.get("findings", []):
                f["target"] = target
                f["category"] = "snmp"
                f["details"] = json_mod.dumps({"weak_communities": snmp_result.get("weak_communities", [])})
                target_findings.append(f)
            step += 1
            with _secscan_lock:
                _secscan_state["progress"] = int(step * 100 / total_steps)
        if "dns" in scan_types and not _cancelled():
            with _secscan_lock:
                _secscan_state["current_test"] = "DNS security"
            dns_result = _sec_dns_check(target)
            for f in dns_result.get("findings", []):
                f["target"] = target
                f["category"] = "dns"
                f["details"] = "{}"
                target_findings.append(f)
            step += 1
            with _secscan_lock:
                _secscan_state["progress"] = int(step * 100 / total_steps)
        if "services" in scan_types and not _cancelled():
            with _secscan_lock:
                _secscan_state["current_test"] = "Service vulnerabilities"
            svc_findings = _sec_service_checks(target, open_ports)
            for f in svc_findings:
                f["target"] = target
                f["category"] = "services"
                f["details"] = "{}"
                target_findings.append(f)
            step += 1
            with _secscan_lock:
                _secscan_state["progress"] = int(step * 100 / total_steps)
        all_findings.extend(target_findings)
    was_cancelled = _cancelled()
    final_status = "cancelled" if was_cancelled else "completed"
    finished = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%SZ")
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    conn = sqlite3.connect(str(DB_PATH))
    for f in all_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        conn.execute(
            "INSERT INTO security_findings "
            "(scan_id, target, category, severity, title, description, details, remediation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, f["target"], f["category"], sev,
             f["title"], f["description"], f.get("details", "{}"),
             f.get("remediation", ""))
        )
    summary = {
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "targets_scanned": len(targets),
        "scan_types": scan_types,
    }
    conn.execute(
        "UPDATE security_scans SET finished_at=?, status=?, summary=? "
        "WHERE scan_id=?",
        (finished, final_status, json_mod.dumps(summary), scan_id)
    )
    conn.commit()
    conn.close()
    with _secscan_lock:
        _secscan_state["status"] = final_status
        _secscan_state["progress"] = 100 if not was_cancelled else _secscan_state.get("progress", 0)
        _secscan_state["current_test"] = ""
    log.info("Security scan %s %s: %d findings across %d targets",
             scan_id, final_status, len(all_findings), len(targets))
    return {"scan_id": scan_id, "summary": summary}

def create_app():
    app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    # --- License / Tier info ---

    @app.route("/api/license")
    def api_license():
        tier = get_tier()
        features = get_tier_features()
        with _config_lock:
            dev_count = len(_config.get("devices", []))
            sensor_count = sum(len(d.get("checks", []))
                               for d in _config.get("devices", []))
        return jsonify({
            "tier": tier,
            "features": features,
            "usage": {
                "devices": dev_count,
                "sensors": sensor_count,
                "max_devices": features["max_devices"],
                "max_sensors": features["max_sensors"],
            },
        })

    @app.route("/api/license", methods=["POST"])
    def api_activate_license():
        data = request.get_json(force=True) if request.data else {}
        key = str(data.get("license_key", "")).strip()
        tier = validate_license_key(key)
        if not tier:
            return jsonify({"error": "Invalid license key"}), 400
        with _config_lock:
            _config["license_key"] = key
            save_config(_config)
        _load_license()
        return jsonify({
            "status": "activated",
            "tier": get_tier(),
            "features": get_tier_features(),
        })

    # --- Status / History / Alerts ---

    @app.route("/api/status")
    def api_status():
        return jsonify(get_latest_per_check())

    @app.route("/api/alerts")
    def api_alerts():
        hours = request.args.get("hours", 48, type=int)
        return jsonify(get_alerts(hours))

    @app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
    def api_acknowledge_alert(alert_id):
        """Acknowledge an alert to suppress repeat notifications."""
        data = request.get_json(force=True) if request.data else {}
        ack_by = str(data.get("by", "dashboard")).strip() or "dashboard"
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat()
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute("SELECT device_name, check_label FROM alerts WHERE id=?",
                           (alert_id,)).fetchone()
        if not row:
            conn.close()
            abort(404, description="Alert not found")
        conn.execute(
            "UPDATE alerts SET acknowledged=1, acknowledged_by=?, acknowledged_at=? WHERE id=?",
            (ack_by, now, alert_id))
        conn.commit()
        conn.close()
        # Add to in-memory ack set so monitoring loop stops re-alerting
        key = row[0] + "|" + (row[1] or "")
        _acked_keys.add(key)
        return jsonify({"status": "acknowledged"})

    @app.route("/api/alerts/acknowledge-all", methods=["POST"])
    def api_acknowledge_all():
        """Acknowledge all unacknowledged alerts."""
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat()
        data = request.get_json(force=True) if request.data else {}
        ack_by = str(data.get("by", "dashboard")).strip() or "dashboard"
        conn = sqlite3.connect(str(DB_PATH))
        rows = conn.execute(
            "SELECT id, device_name, check_label FROM alerts WHERE acknowledged=0"
        ).fetchall()
        for row in rows:
            key = row[1] + "|" + (row[2] or "")
            _acked_keys.add(key)
        conn.execute(
            "UPDATE alerts SET acknowledged=1, acknowledged_by=?, acknowledged_at=? "
            "WHERE acknowledged=0", (ack_by, now))
        conn.commit()
        count = conn.total_changes
        conn.close()
        return jsonify({"status": "acknowledged", "count": count})

    @app.route("/api/history")
    def api_history():
        hours = request.args.get("hours", 24, type=int)
        return jsonify(get_history(hours))

    # --- Performance data for graphing (Pro+) ---

    @app.route("/api/devices/<name>/perf")
    @require_tier(TIER_PRO)
    def api_device_perf(name):
        """Get performance time-series data for graphing."""
        hours = request.args.get("hours", 24, type=int)
        check_label = request.args.get("check_label", None)
        if check_label:
            data = get_perf_data(name, check_label, hours=hours)
            return jsonify({check_label: data})
        # Return all checks for this device
        with _config_lock:
            dev = None
            for d in _config.get("devices", []):
                if d["name"] == name:
                    dev = d
                    break
        if not dev:
            abort(404, description="Device not found")
        result = {}
        for chk in dev.get("checks", []):
            label = chk.get("label", chk.get("type", "ping").upper())
            result[label] = get_perf_data(name, label, hours=hours)
        return jsonify(result)

    # --- Device detail ---

    @app.route("/api/devices/<name>/history")
    def api_device_history(name):
        label = request.args.get("check_label", None)
        limit = request.args.get("limit", 50, type=int)
        rows = get_device_history(name, check_label=label, limit=limit)
        return jsonify(rows)

    @app.route("/api/devices/<name>/uptime")
    def api_device_uptime(name):
        h24 = get_device_uptime(name, 24)
        h168 = get_device_uptime(name, 168)
        h720 = get_device_uptime(name, 720)
        return jsonify({"24h": h24, "7d": h168, "30d": h720})

    # --- Device CRUD ---

    @app.route("/api/devices", methods=["GET"])
    def api_get_devices():
        with _config_lock:
            devices = list(_config.get("devices", []))
        return jsonify(devices)

    @app.route("/api/devices/<name>", methods=["GET"])
    def api_get_device(name):
        with _config_lock:
            for d in _config.get("devices", []):
                if d["name"] == name:
                    return jsonify(d)
        abort(404, description="Device not found")

    @app.route("/api/devices", methods=["POST"])
    def api_add_device():
        data = request.get_json(force=True)
        dev = _sanitize_device(data)
        if not dev["name"] or not dev["host"]:
            abort(400, description="Name and host are required")
        # Enforce device limit for free tier
        if not check_device_limit():
            features = get_tier_features()
            return jsonify({
                "error": "device_limit",
                "message": "Community tier is limited to %d devices. "
                           "Upgrade to Pro for unlimited devices." % features["max_devices"],
                "current_tier": get_tier(),
            }), 403
        with _config_lock:
            devices = _config.setdefault("devices", [])
            for d in devices:
                if d["name"] == dev["name"]:
                    abort(409, description="Device already exists")
            devices.append(dev)
            save_config(_config)
        return jsonify({"status": "created", "device": dev}), 201

    @app.route("/api/devices/<name>", methods=["PUT"])
    def api_update_device(name):
        data = request.get_json(force=True)
        dev = _sanitize_device(data)
        if not dev["name"] or not dev["host"]:
            abort(400, description="Name and host are required")
        with _config_lock:
            devices = _config.setdefault("devices", [])
            for i, d in enumerate(devices):
                if d["name"] == name:
                    devices[i] = dev
                    save_config(_config)
                    return jsonify({"status": "updated", "device": dev})
            abort(404, description="Device not found")

    @app.route("/api/devices/<name>", methods=["DELETE"])
    def api_delete_device(name):
        with _config_lock:
            devices = _config.setdefault("devices", [])
            for i, d in enumerate(devices):
                if d["name"] == name:
                    devices.pop(i)
                    save_config(_config)
                    return jsonify({"status": "deleted"})
            abort(404, description="Device not found")

    # --- Maintenance mode toggle ---

    @app.route("/api/devices/<name>/maintenance", methods=["POST"])
    def api_toggle_maintenance(name):
        data = request.get_json(force=True)
        enabled = bool(data.get("enabled", False))
        with _config_lock:
            devices = _config.setdefault("devices", [])
            for d in devices:
                if d["name"] == name:
                    d["maintenance"] = enabled
                    save_config(_config)
                    return jsonify({"status": "ok", "maintenance": enabled})
            abort(404, description="Device not found")

    # --- Scheduled Downtime API (Pro+) ---

    @app.route("/api/downtime", methods=["GET"])
    @require_tier(TIER_PRO)
    def api_get_downtimes():
        return jsonify(get_all_downtimes())

    @app.route("/api/downtime", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_add_downtime():
        data = request.get_json(force=True)
        device_name = str(data.get("device_name", "")).strip()
        start_time = str(data.get("start_time", "")).strip()
        end_time = str(data.get("end_time", "")).strip()
        reason = str(data.get("reason", "")).strip()
        created_by = str(data.get("created_by", "dashboard")).strip()
        if not device_name or not start_time or not end_time:
            abort(400, description="device_name, start_time and end_time are required")
        # Validate device exists
        with _config_lock:
            found = any(d["name"] == device_name for d in _config.get("devices", []))
        if not found:
            abort(404, description="Device not found")
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat()
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute(
            "INSERT INTO scheduled_downtime (device_name,start_time,end_time,reason,created_by,created_at,active) "
            "VALUES (?,?,?,?,?,?,1)",
            (device_name, start_time, end_time, reason, created_by, now))
        conn.commit()
        dt_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return jsonify({"status": "created", "id": dt_id}), 201

    @app.route("/api/downtime/<int:dt_id>", methods=["DELETE"])
    @require_tier(TIER_PRO)
    def api_delete_downtime(dt_id):
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("DELETE FROM scheduled_downtime WHERE id=?", (dt_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    @app.route("/api/downtime/<int:dt_id>/cancel", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_cancel_downtime(dt_id):
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("UPDATE scheduled_downtime SET active=0 WHERE id=?", (dt_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "cancelled"})

    # --- Dependencies info (Pro+) ---

    @app.route("/api/dependencies")
    @require_tier(TIER_PRO)
    def api_dependencies():
        """Return parent-child dependency info for all devices."""
        with _config_lock:
            devices = list(_config.get("devices", []))
        deps = []
        for d in devices:
            parent = d.get("parent", "").strip()
            deps.append({"name": d["name"], "parent": parent})
        return jsonify(deps)

    # --- Scanner API (Pro+) ---

    @app.route("/api/scan", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_start_scan():
        with _scan_lock:
            if _scan_state["running"]:
                return jsonify({"error": "A scan is already running"}), 409

        data = request.get_json(force=True)
        ip_range = data.get("range", "").strip()
        if not ip_range:
            abort(400, description="IP range is required")

        try:
            test_ips = parse_ip_range(ip_range)
            if len(test_ips) > 1024:
                abort(400, description="Range too large (max 1024 IPs)")
        except ValueError as e:
            abort(400, description=str(e))

        ports = data.get("ports", COMMON_PORTS)
        port_timeout = data.get("port_timeout", 1000)

        t = threading.Thread(target=run_scan, args=(ip_range, ports, port_timeout))
        t.daemon = True
        t.start()

        return jsonify({"status": "started", "target": ip_range, "total_ips": len(test_ips)})

    @app.route("/api/scan/status")
    @require_tier(TIER_PRO)
    def api_scan_status():
        with _scan_lock:
            return jsonify({
                "running": _scan_state["running"],
                "scan_id": _scan_state["scan_id"],
                "total": _scan_state["total"],
                "scanned": _scan_state["scanned"],
                "alive": _scan_state["alive"],
                "target": _scan_state["target"],
                "started_at": _scan_state["started_at"],
                "finished_at": _scan_state["finished_at"],
            })

    @app.route("/api/scan/results")
    @require_tier(TIER_PRO)
    def api_scan_results():
        with _scan_lock:
            results = list(_scan_state.get("results", []))
        with _config_lock:
            monitored_hosts = set()
            for d in _config.get("devices", []):
                monitored_hosts.add(d.get("host", ""))
        for r in results:
            r["is_monitored"] = r["ip"] in monitored_hosts
        return jsonify(results)

    @app.route("/api/scan/history")
    @require_tier(TIER_PRO)
    def api_scan_history():
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT scan_id, MIN(timestamp) as started, COUNT(*) as total_ips,
                   SUM(is_alive) as alive_count
            FROM scan_results GROUP BY scan_id ORDER BY started DESC LIMIT 20
        """).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])

    @app.route("/api/scan/<scan_id>/results")
    @require_tier(TIER_PRO)
    def api_scan_id_results(scan_id):
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scan_results WHERE scan_id=? ORDER BY ip",
            (scan_id,)).fetchall()
        conn.close()
        results = [dict(r) for r in rows]
        with _config_lock:
            monitored_hosts = set()
            for d in _config.get("devices", []):
                monitored_hosts.add(d.get("host", ""))
        for r in results:
            ports_str = r.get("open_ports", "")
            r["open_ports"] = [int(p) for p in ports_str.split(",") if p.strip()] if ports_str else []
            r["is_alive"] = bool(r["is_alive"])
            r["is_monitored"] = r["ip"] in monitored_hosts
        return jsonify(results)

    # --- Network Map API (Pro+) ---

    @app.route("/api/map/data")
    @require_tier(TIER_PRO)
    def api_map_data():
        with _config_lock:
            devices = list(_config.get("devices", []))

        status_list = get_latest_per_check()
        status_map = {}
        for s in status_list:
            key = s["device_name"]
            cur = status_map.get(key, "OK")
            if s["status"] == "CRITICAL":
                status_map[key] = "CRITICAL"
            elif s["status"] == "WARNING" and cur != "CRITICAL":
                status_map[key] = "WARNING"
            elif key not in status_map:
                status_map[key] = s["status"]

        parent_map = _get_parent_map(devices)
        downtime_devices = get_active_downtimes()

        nodes = []
        edges = []

        nodes.append({
            "id": "__netmon__",
            "label": platform.node() or socket.gethostname() or "NetMon Server",
            "type": "hub",
            "status": "hub",
            "group": "",
            "host": "",
        })

        monitored_ips = set()
        device_names = set()
        for dev in devices:
            nid = "dev_" + dev["name"]
            device_names.add(dev["name"])
            in_downtime = dev["name"] in downtime_devices
            if dev.get("maintenance") or in_downtime:
                status = "MAINTENANCE"
            elif is_parent_down(dev["name"], parent_map, status_map):
                status = "PARENT_DOWN"
            else:
                status = status_map.get(dev["name"], "PENDING")
            nodes.append({
                "id": nid,
                "label": dev["name"],
                "type": "monitored",
                "status": status,
                "group": dev.get("group", "Default"),
                "host": dev.get("host", ""),
                "maintenance": dev.get("maintenance", False),
                "in_downtime": in_downtime,
                "parent": dev.get("parent", ""),
                "checks": len(dev.get("checks", [])),
            })
            # Edge: connect to parent if set, otherwise to hub
            parent_name = dev.get("parent", "").strip()
            if parent_name and parent_name in device_names:
                edges.append({"from": "dev_" + parent_name, "to": nid})
            else:
                edges.append({"from": "__netmon__", "to": nid})
            monitored_ips.add(dev.get("host", ""))

        # Fix edges for devices whose parents were declared after them
        for dev in devices:
            parent_name = dev.get("parent", "").strip()
            if parent_name and parent_name in device_names:
                nid = "dev_" + dev["name"]
                # Remove existing hub edge if any
                edges = [e for e in edges if not (e["from"] == "__netmon__" and e["to"] == nid)]
                # Ensure parent edge exists
                parent_edge = {"from": "dev_" + parent_name, "to": nid}
                if parent_edge not in edges:
                    edges.append(parent_edge)

        with _scan_lock:
            scan_results = list(_scan_state.get("results", []))

        for r in scan_results:
            if r["is_alive"] and r["ip"] not in monitored_ips:
                nid = "disc_" + r["ip"]
                label = r["hostname"] or r["ip"]
                nodes.append({
                    "id": nid,
                    "label": label,
                    "type": "discovered",
                    "status": "discovered",
                    "group": "Discovered",
                    "host": r["ip"],
                    "open_ports": r.get("open_ports", []),
                })
                edges.append({"from": "__netmon__", "to": nid})

        return jsonify({"nodes": nodes, "edges": edges})

    # --- Settings API ---

    @app.route("/api/settings", methods=["GET"])
    def api_get_settings():
        with _config_lock:
            cfg = dict(_config)
        smtp = cfg.get("smtp", {})
        dash = cfg.get("dashboard", {})
        settings = {
            "check_interval_seconds": cfg.get("check_interval_seconds", 60),
            "dashboard_host": dash.get("host", "0.0.0.0"),
            "dashboard_port": dash.get("port", 8080),
            "smtp_host": smtp.get("smtp_host", ""),
            "smtp_port": smtp.get("smtp_port", 587),
            "use_tls": smtp.get("use_tls", True),
            "smtp_username": smtp.get("username", ""),
            "smtp_password": smtp.get("password", ""),
            "from_addr": smtp.get("from_addr", ""),
            "recipients": smtp.get("recipients", []),
            "cooldown_minutes": smtp.get("cooldown_minutes", 15),
        }
        return jsonify(settings)

    @app.route("/api/settings", methods=["PUT"])
    def api_update_settings():
        data = request.get_json(force=True)
        with _config_lock:
            cfg = _config
            if "check_interval_seconds" in data:
                val = int(data["check_interval_seconds"])
                if val < 5:
                    val = 5
                cfg["check_interval_seconds"] = val
            if "dashboard" not in cfg:
                cfg["dashboard"] = {}
            if "dashboard_host" in data:
                cfg["dashboard"]["host"] = str(data["dashboard_host"]).strip() or "0.0.0.0"
            if "dashboard_port" in data:
                cfg["dashboard"]["port"] = int(data["dashboard_port"])
            if "smtp" not in cfg:
                cfg["smtp"] = {}
            sm = cfg["smtp"]
            field_map = {
                "smtp_host": "smtp_host",
                "smtp_port": "smtp_port",
                "use_tls": "use_tls",
                "smtp_username": "username",
                "smtp_password": "password",
                "from_addr": "from_addr",
                "cooldown_minutes": "cooldown_minutes",
            }
            for api_key, cfg_key in field_map.items():
                if api_key in data:
                    val = data[api_key]
                    if api_key == "smtp_port":
                        val = int(val)
                    elif api_key == "cooldown_minutes":
                        val = int(val)
                    elif api_key == "use_tls":
                        val = bool(val)
                    else:
                        val = str(val).strip()
                    sm[cfg_key] = val
            if "recipients" in data:
                rcpts = data["recipients"]
                if isinstance(rcpts, str):
                    rcpts = [r.strip() for r in rcpts.split(",") if r.strip()]
                sm["recipients"] = rcpts
            save_config(cfg)
        return jsonify({"ok": True})

    @app.route("/api/settings/test-email", methods=["POST"])
    def api_test_email():
        with _config_lock:
            smtp_cfg = dict(_config.get("smtp", {}))
        if not smtp_cfg.get("smtp_host"):
            return jsonify({"ok": False, "error": "SMTP host not configured"}), 400
        recipients = smtp_cfg.get("recipients", [])
        if not recipients:
            return jsonify({"ok": False, "error": "No recipients configured"}), 400
        try:
            from_addr = smtp_cfg.get("from_addr", smtp_cfg.get("username", "netmon@localhost"))
            subject = "MyClover.Tech.netmon Test Alert"
            body = "This is a test alert from MyClover.Tech.netmon. If you received this, your email settings are working correctly."
            msg = email.mime.multipart.MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_addr
            msg["To"] = ", ".join(recipients)
            msg.attach(email.mime.text.MIMEText(body, "plain"))
            host = smtp_cfg.get("smtp_host", "localhost")
            port = int(smtp_cfg.get("smtp_port", 25))
            use_tls = smtp_cfg.get("use_tls", False)
            if use_tls:
                server = smtplib.SMTP(host, port, timeout=15)
                server.starttls()
            else:
                server = smtplib.SMTP(host, port, timeout=15)
            user = smtp_cfg.get("username", "")
            pwd = smtp_cfg.get("password", "")
            if user and pwd:
                server.login(user, pwd)
            server.sendmail(from_addr, recipients, msg.as_string())
            server.quit()
            return jsonify({"ok": True, "message": "Test email sent successfully"})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

    # --- NOC / TV Display Mode (Enterprise) ---

    @app.route("/noc")
    def noc_dashboard():
        """Serve the NOC/TV full-screen display."""
        return render_template("noc.html")

    @app.route("/api/noc/data")
    @require_tier(TIER_ENT)
    def api_noc_data():
        """Get NOC summary data -- devices, status counts, recent alerts."""
        results = get_latest_per_check()
        with _config_lock:
            devices = list(_config.get("devices", []))

        # Build status summary
        dev_status = {}
        for r in results:
            dn = r["device_name"]
            cur = dev_status.get(dn, "OK")
            if r["status"] == "CRITICAL":
                dev_status[dn] = "CRITICAL"
            elif r["status"] == "WARNING" and cur != "CRITICAL":
                dev_status[dn] = "WARNING"
            elif dn not in dev_status:
                dev_status[dn] = r["status"]

        ok = sum(1 for v in dev_status.values() if v == "OK")
        warn = sum(1 for v in dev_status.values() if v == "WARNING")
        crit = sum(1 for v in dev_status.values() if v == "CRITICAL")

        # Recent alerts
        alerts = get_alerts(hours=4)[:20]

        # Device list with status
        dev_list = []
        for d in devices:
            st = dev_status.get(d["name"], "UNKNOWN")
            dev_list.append({
                "name": d["name"],
                "host": d.get("host", ""),
                "group": d.get("group", "Default"),
                "status": st,
                "maintenance": d.get("maintenance", False),
            })

        return jsonify({
            "summary": {"total": len(devices), "ok": ok, "warning": warn,
                         "critical": crit},
            "devices": dev_list,
            "alerts": alerts,
            "timestamp": datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat(),
        })

    # --- SLA / Uptime Reports (Enterprise) ---

    @app.route("/api/reports/sla")
    @require_tier(TIER_ENT)
    def api_sla_report():
        hours = int(request.args.get("hours", 720))
        fmt = request.args.get("format", "json")
        device = request.args.get("device", None)
        device_filter = [device] if device else None
        reports = generate_sla_report(hours=hours, device_filter=device_filter)

        if fmt == "csv":
            csv_data = generate_sla_csv(reports)
            from flask import Response
            return Response(csv_data, mimetype="text/csv",
                           headers={"Content-Disposition":
                                    "attachment; filename=sla_report.csv"})

        return jsonify({
            "period_hours": hours,
            "generated_at": datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat(),
            "devices": reports,
        })

    # --- SNMP Deep Polling (Enterprise) ---

    @app.route("/api/devices/<name>/snmp")
    @require_tier(TIER_ENT)
    def api_device_snmp(name):
        """Get SNMP deep poll data for a device."""
        with _config_lock:
            devices = _config.get("devices", [])
            dev = None
            for d in devices:
                if d["name"] == name:
                    dev = d
                    break
        if not dev:
            return jsonify({"error": "Device not found"}), 404
        community = "public"
        for chk in dev.get("checks", []):
            if chk.get("type") == "snmp":
                community = chk.get("community", "public")
                break
        data = snmp_deep_poll(dev["host"], community=community)
        return jsonify(data)

    # --- User Authentication (Enterprise) ---

    @app.route("/api/auth/login", methods=["POST"])
    def api_auth_login():
        """Login and get a token."""
        data = request.get_json(force=True) if request.data else {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        with _config_lock:
            users = _config.get("users", [])

        for u in users:
            if u.get("username") == username and u.get("password") == password:
                role = u.get("role", "viewer")
                token = _generate_auth_token(username, role)
                resp = jsonify({"token": token, "username": username,
                                "role": role, "expires_in": _AUTH_TOKEN_EXPIRY})
                resp.set_cookie("netmon_token", token, max_age=_AUTH_TOKEN_EXPIRY,
                                httponly=True, samesite="Lax")
                return resp

        return jsonify({"error": "Invalid credentials"}), 401

    @app.route("/api/auth/logout", methods=["POST"])
    def api_auth_logout():
        resp = jsonify({"status": "logged_out"})
        resp.delete_cookie("netmon_token")
        return resp

    @app.route("/api/auth/me")
    def api_auth_me():
        username, role = _check_auth()
        return jsonify({"username": username, "role": role})

    @app.route("/api/users", methods=["GET"])
    @require_tier(TIER_ENT)
    def api_get_users():
        _check_auth("users")
        with _config_lock:
            users = _config.get("users", [])
        safe = [{"username": u["username"], "role": u.get("role", "viewer")}
                for u in users]
        return jsonify(safe)

    @app.route("/api/users", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_add_user():
        _check_auth("users")
        data = request.get_json(force=True) if request.data else {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()
        role = str(data.get("role", "viewer")).strip()
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
        if role not in AUTH_ROLES:
            return jsonify({"error": "Invalid role"}), 400
        with _config_lock:
            users = _config.get("users", [])
            for u in users:
                if u["username"] == username:
                    return jsonify({"error": "User already exists"}), 409
            users.append({"username": username, "password": password, "role": role})
            _config["users"] = users
            save_config(_config)
        return jsonify({"status": "created", "username": username, "role": role})

    @app.route("/api/users/<username>", methods=["DELETE"])
    @require_tier(TIER_ENT)
    def api_delete_user(username):
        _check_auth("users")
        with _config_lock:
            users = _config.get("users", [])
            _config["users"] = [u for u in users if u["username"] != username]
            save_config(_config)
        return jsonify({"status": "deleted"})

    # --- Custom Check Plugins (Enterprise) ---

    @app.route("/api/plugins")
    @require_tier(TIER_ENT)
    def api_list_plugins():
        """List available plugin scripts."""
        plugins = []
        if PLUGIN_DIR.is_dir():
            for f in sorted(PLUGIN_DIR.iterdir()):
                if f.suffix == ".py" and f.is_file():
                    plugins.append({
                        "name": f.name,
                        "path": str(f.relative_to(BASE_DIR)),
                        "size": f.stat().st_size,
                    })
        return jsonify(plugins)

    # --- Webhook Configuration API (Enterprise) ---

    @app.route("/api/webhooks", methods=["GET"])
    @require_tier(TIER_ENT)
    def api_get_webhooks():
        with _config_lock:
            hooks = _config.get("webhooks", [])
        return jsonify(hooks)

    @app.route("/api/webhooks", methods=["PUT"])
    @require_tier(TIER_ENT)
    def api_update_webhooks():
        data = request.get_json(force=True) if request.data else []
        with _config_lock:
            _config["webhooks"] = data
            save_config(_config)
        return jsonify({"status": "saved"})

    @app.route("/api/webhooks/test", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_test_webhook():
        data = request.get_json(force=True) if request.data else {}
        test_result = {
            "timestamp": datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat(),
            "device_name": "Test Device",
            "host": "127.0.0.1",
            "check_type": "test",
            "check_label": "Test Check",
            "status": "WARNING",
            "response_ms": 42.0,
            "message": "This is a test notification from MyClover.Tech.netmon",
        }
        try:
            hook_type = data.get("type", "generic")
            url = data.get("url", "")
            if hook_type == "slack":
                _send_slack_webhook(test_result, url)
            elif hook_type == "teams":
                _send_teams_webhook(test_result, url)
            elif hook_type == "pagerduty":
                _send_pagerduty_event(test_result, data)
            else:
                _send_generic_webhook(test_result, url)
            return jsonify({"ok": True, "message": "Test webhook sent"})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

    # --- Inventory API (Pro+) ---

    @app.route("/api/inventory", methods=["GET"])
    @require_tier(TIER_PRO)
    def api_get_inventory():
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM inventory ORDER BY last_seen DESC"
        ).fetchall()
        conn.close()
        with _config_lock:
            monitored_map = {}
            for d in _config.get("devices", []):
                monitored_map[d.get("host", "")] = d["name"]
        result = []
        for r in rows:
            d = dict(r)
            ports_str = d.get("open_ports", "")
            d["open_ports_list"] = [int(p) for p in ports_str.split(",") if p.strip()] if ports_str else []
            d["is_monitored"] = d["ip"] in monitored_map
            d["monitored_device"] = monitored_map.get(d["ip"], d.get("monitored_device", ""))
            try:
                d["custom_fields"] = json_mod.loads(d.get("custom_fields", "{}"))
            except Exception:
                d["custom_fields"] = {}
            result.append(d)
        return jsonify(result)

    @app.route("/api/inventory/<int:asset_id>", methods=["GET"])
    @require_tier(TIER_PRO)
    def api_get_asset(asset_id):
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM inventory WHERE id=?", (asset_id,)).fetchone()
        conn.close()
        if not row:
            abort(404, description="Asset not found")
        d = dict(row)
        ports_str = d.get("open_ports", "")
        d["open_ports_list"] = [int(p) for p in ports_str.split(",") if p.strip()] if ports_str else []
        try:
            d["custom_fields"] = json_mod.loads(d.get("custom_fields", "{}"))
        except Exception:
            d["custom_fields"] = {}
        return jsonify(d)

    @app.route("/api/inventory", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_add_asset():
        data = request.get_json(force=True)
        ip = str(data.get("ip", "")).strip()
        if not ip:
            abort(400, description="IP address is required")
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat()
        conn = sqlite3.connect(str(DB_PATH))
        existing = conn.execute("SELECT id FROM inventory WHERE ip=?", (ip,)).fetchone()
        if existing:
            conn.close()
            abort(409, description="Asset with this IP already exists")
        conn.execute(
            "INSERT INTO inventory (ip,hostname,mac_address,device_type,vendor,model,"
            "os_info,location,serial_number,purchase_date,notes,open_ports,"
            "first_seen,last_seen,monitored_device,status,custom_fields) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ip,
             str(data.get("hostname", "")).strip(),
             str(data.get("mac_address", "")).strip(),
             str(data.get("device_type", "")).strip(),
             str(data.get("vendor", "")).strip(),
             str(data.get("model", "")).strip(),
             str(data.get("os_info", "")).strip(),
             str(data.get("location", "")).strip(),
             str(data.get("serial_number", "")).strip(),
             str(data.get("purchase_date", "")).strip(),
             str(data.get("notes", "")).strip(),
             str(data.get("open_ports", "")).strip(),
             now, now,
             str(data.get("monitored_device", "")).strip(),
             str(data.get("status", "active")).strip(),
             json_mod.dumps(data.get("custom_fields", {}))))
        conn.commit()
        conn.close()
        return jsonify({"status": "created"}), 201

    @app.route("/api/inventory/<int:asset_id>", methods=["PUT"])
    @require_tier(TIER_PRO)
    def api_update_asset(asset_id):
        data = request.get_json(force=True)
        conn = sqlite3.connect(str(DB_PATH))
        existing = conn.execute("SELECT id FROM inventory WHERE id=?", (asset_id,)).fetchone()
        if not existing:
            conn.close()
            abort(404, description="Asset not found")
        fields = []
        values = []
        updatable = ["ip", "hostname", "mac_address", "device_type", "vendor", "model",
                      "os_info", "location", "serial_number", "purchase_date", "notes",
                      "open_ports", "monitored_device", "status"]
        for f in updatable:
            if f in data:
                fields.append(f + "=?")
                values.append(str(data[f]).strip())
        if "custom_fields" in data:
            fields.append("custom_fields=?")
            values.append(json_mod.dumps(data["custom_fields"]))
        if fields:
            values.append(asset_id)
            conn.execute("UPDATE inventory SET " + ",".join(fields) + " WHERE id=?", values)
            conn.commit()
        conn.close()
        return jsonify({"status": "updated"})

    @app.route("/api/inventory/<int:asset_id>", methods=["DELETE"])
    @require_tier(TIER_PRO)
    def api_delete_asset(asset_id):
        conn = sqlite3.connect(str(DB_PATH))
        existing = conn.execute("SELECT id FROM inventory WHERE id=?", (asset_id,)).fetchone()
        if not existing:
            conn.close()
            abort(404, description="Asset not found")
        conn.execute("DELETE FROM inventory WHERE id=?", (asset_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    @app.route("/api/inventory/batch-delete", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_batch_delete_assets():
        data = request.get_json(force=True)
        ids = data.get("ids", [])
        if not ids:
            abort(400, description="No asset IDs provided")
        conn = sqlite3.connect(str(DB_PATH))
        placeholders = ",".join("?" for _ in ids)
        conn.execute("DELETE FROM inventory WHERE id IN (%s)" % placeholders, ids)
        conn.commit()
        deleted = conn.total_changes
        conn.close()
        return jsonify({"status": "deleted", "count": deleted})

    @app.route("/api/inventory/import-scan", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_import_scan_to_inventory():
        data = request.get_json(force=True)
        scan_id = data.get("scan_id", "")
        if not scan_id:
            with _scan_lock:
                scan_id = _scan_state.get("scan_id", "")
        if not scan_id:
            abort(400, description="No scan_id provided and no scans have been run")
        result = import_scan_to_inventory(scan_id)
        return jsonify(result)

    @app.route("/api/inventory/stats")
    @require_tier(TIER_PRO)
    def api_inventory_stats():
        conn = sqlite3.connect(str(DB_PATH))
        total = conn.execute("SELECT COUNT(*) FROM inventory").fetchone()[0]
        active = conn.execute("SELECT COUNT(*) FROM inventory WHERE status='active'").fetchone()[0]
        retired = conn.execute("SELECT COUNT(*) FROM inventory WHERE status='retired'").fetchone()[0]
        types = {}
        for row in conn.execute("SELECT device_type, COUNT(*) as cnt FROM inventory GROUP BY device_type"):
            types[row[0] or "Unknown"] = row[1]
        conn.close()
        with _config_lock:
            monitored_ips = set()
            for d in _config.get("devices", []):
                monitored_ips.add(d.get("host", ""))
        return jsonify({
            "total": total,
            "active": active,
            "retired": retired,
            "by_type": types,
            "monitored_count": len(monitored_ips),
        })

    # --- Backup & Restore ---

    @app.route("/api/backup", methods=["GET"])
    def api_backup():
        """Create a zip backup of the database and config."""
        import sqlite3 as _sqlite3
        ts = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).strftime("%Y%m%d_%H%M%S")
        buf = io.BytesIO()
        tmp_db = DB_PATH.parent / ".netmon_backup_tmp.db"
        try:
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                # Database -- use SQLite backup API for a consistent snapshot
                if DB_PATH.exists():
                    try:
                        src = _sqlite3.connect(str(DB_PATH))
                        dst = _sqlite3.connect(str(tmp_db))
                        src.backup(dst)
                        dst.close()
                        src.close()
                        zf.write(str(tmp_db), "netmon.db")
                    finally:
                        if tmp_db.exists():
                            tmp_db.unlink()
                # Config
                cfg_path = DEFAULT_CFG
                if cfg_path.exists():
                    zf.write(str(cfg_path), "config.yaml")
                # Plugins
                if PLUGIN_DIR.exists():
                    for pf in PLUGIN_DIR.glob("*.py"):
                        zf.write(str(pf), "plugins/" + pf.name)
            buf.seek(0)
            return send_file(
                buf,
                mimetype="application/zip",
                as_attachment=True,
                download_name="netmon_backup_%s.zip" % ts,
            )
        except Exception as exc:
            log.exception("Backup failed: %s", exc)
            return jsonify({"error": "Backup failed: %s" % str(exc)}), 500

    @app.route("/api/restore", methods=["POST"])
    def api_restore():
        """Restore from a backup zip uploaded via multipart form."""
        if "file" not in request.files:
            abort(400, description="No file uploaded.")
        f = request.files["file"]
        if not f.filename or not f.filename.lower().endswith(".zip"):
            abort(400, description="Upload must be a .zip file.")
        buf = io.BytesIO(f.read())
        try:
            zf = zipfile.ZipFile(buf, "r")
        except zipfile.BadZipFile:
            abort(400, description="Invalid zip file.")
        names = zf.namelist()
        restored = []
        # Restore database
        if "netmon.db" in names:
            db_bytes = zf.read("netmon.db")
            with open(str(DB_PATH), "wb") as out:
                out.write(db_bytes)
            restored.append("netmon.db")
        # Restore config
        if "config.yaml" in names:
            cfg_bytes = zf.read("config.yaml")
            with open(str(DEFAULT_CFG), "wb") as out:
                out.write(cfg_bytes)
            restored.append("config.yaml")
            _reload_config()
        # Restore plugins
        for n in names:
            if n.startswith("plugins/") and n.endswith(".py"):
                PLUGIN_DIR.mkdir(exist_ok=True)
                plugin_bytes = zf.read(n)
                dest = PLUGIN_DIR / Path(n).name
                with open(str(dest), "wb") as out:
                    out.write(plugin_bytes)
                restored.append(n)
        zf.close()
        if not restored:
            abort(400, description="Zip contained no recognized files (netmon.db, config.yaml, plugins/*.py).")
        return jsonify({"status": "restored", "files": restored,
                        "message": "Restored %d file(s). Restart netmon for full effect." % len(restored)})



    # --- Security Scanner API (Enterprise) ---

    @app.route("/api/security/scan", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_security_scan():
        """Start a security scan."""
        with _secscan_lock:
            if _secscan_state.get("status") == "running":
                return jsonify({"error": "A scan is already running",
                                "scan_id": _secscan_state.get("scan_id", "")}), 409
        data = request.get_json(force=True) if request.data else {}
        targets = data.get("targets", [])
        scan_types = data.get("scan_types", ["ports", "ssl", "http", "services"])
        if not targets:
            with _config_lock:
                targets = list(set(d.get("host", "") for d in _config.get("devices", []) if d.get("host")))
        if not targets:
            return jsonify({"error": "No targets specified and no devices configured"}), 400
        valid_types = ["ports", "ssl", "http", "snmp", "dns", "services"]
        scan_types = [t for t in scan_types if t in valid_types]
        if not scan_types:
            scan_types = ["ports", "ssl", "http", "services"]
        scan_id = "sec-%s" % secrets.token_hex(6)
        t = threading.Thread(target=run_security_scan,
                             args=(targets, scan_types, scan_id), daemon=True)
        t.start()
        return jsonify({
            "scan_id": scan_id,
            "targets": targets,
            "scan_types": scan_types,
            "status": "started",
        })

    @app.route("/api/security/status")
    @require_tier(TIER_ENT)
    def api_security_status():
        """Get current scan progress."""
        with _secscan_lock:
            state = dict(_secscan_state)
        return jsonify(state)

    @app.route("/api/security/cancel", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_security_cancel():
        """Cancel a running security scan."""
        with _secscan_lock:
            if _secscan_state.get("status") != "running":
                return jsonify({"error": "No scan is currently running"}), 400
            _secscan_state["status"] = "cancelling"
        return jsonify({"status": "cancelling",
                        "scan_id": _secscan_state.get("scan_id", "")})

    @app.route("/api/security/scans")
    @require_tier(TIER_ENT)
    def api_security_scans():
        """List all security scans."""
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM security_scans ORDER BY id DESC LIMIT 50"
        ).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["targets"] = json_mod.loads(d.get("targets", "[]"))
            d["scan_types"] = json_mod.loads(d.get("scan_types", "[]"))
            d["summary"] = json_mod.loads(d.get("summary", "{}"))
            results.append(d)
        return jsonify(results)

    @app.route("/api/security/scans/<scan_id>")
    @require_tier(TIER_ENT)
    def api_security_scan_detail(scan_id):
        """Get scan details with all findings."""
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        scan = conn.execute(
            "SELECT * FROM security_scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not scan:
            conn.close()
            return jsonify({"error": "Scan not found"}), 404
        findings = conn.execute(
            "SELECT * FROM security_findings WHERE scan_id = ? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id",
            (scan_id,)
        ).fetchall()
        conn.close()
        scan_dict = dict(scan)
        scan_dict["targets"] = json_mod.loads(scan_dict.get("targets", "[]"))
        scan_dict["scan_types"] = json_mod.loads(scan_dict.get("scan_types", "[]"))
        scan_dict["summary"] = json_mod.loads(scan_dict.get("summary", "{}"))
        findings_list = []
        for f in findings:
            fd = dict(f)
            fd["details"] = json_mod.loads(fd.get("details", "{}"))
            findings_list.append(fd)
        scan_dict["findings"] = findings_list
        return jsonify(scan_dict)

    @app.route("/api/security/scans/<scan_id>", methods=["DELETE"])
    @require_tier(TIER_ENT)
    def api_security_scan_delete(scan_id):
        """Delete a security scan and its findings."""
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("DELETE FROM security_findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM security_scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted", "scan_id": scan_id})

    # --- Helpdesk Connector API (Pro+) ---

    @app.route("/api/helpdesk/tickets", methods=["GET"])
    @require_tier(TIER_PRO)
    def api_helpdesk_tickets():
        """List cached helpdesk tickets with optional filters."""
        status_filter = request.args.get("status", "").strip()
        priority_filter = request.args.get("priority", "").strip()
        assignee_filter = request.args.get("assignee", "").strip()
        search = request.args.get("search", "").strip()
        device_filter = request.args.get("device", "").strip()
        limit = min(int(request.args.get("limit", 500)), 2000)
        offset = int(request.args.get("offset", 0))

        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM helpdesk_tickets WHERE 1=1"
        params = []

        if status_filter:
            query += " AND LOWER(status) = LOWER(?)"
            params.append(status_filter)
        if priority_filter:
            query += " AND LOWER(priority) = LOWER(?)"
            params.append(priority_filter)
        if assignee_filter:
            query += " AND LOWER(assignee) LIKE LOWER(?)"
            params.append("%" + assignee_filter + "%")
        if device_filter:
            query += " AND LOWER(device_name) LIKE LOWER(?)"
            params.append("%" + device_filter + "%")
        if search:
            query += " AND (LOWER(subject) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?) OR LOWER(requester) LIKE LOWER(?))"
            params.extend(["%" + search + "%"] * 3)

        # Count total
        count_q = query.replace("SELECT *", "SELECT COUNT(*)", 1)
        total = conn.execute(count_q, params).fetchone()[0]

        query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        conn.close()

        tickets = []
        for r in rows:
            d = dict(r)
            d.pop("raw_json", None)  # Don't send raw JSON in list view
            tickets.append(d)

        return jsonify({"tickets": tickets, "total": total})

    @app.route("/api/helpdesk/tickets/<int:ticket_id>", methods=["GET"])
    @require_tier(TIER_PRO)
    def api_helpdesk_ticket_detail(ticket_id):
        """Get a single cached ticket with full details."""
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM helpdesk_tickets WHERE id=?", (ticket_id,)
        ).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "Ticket not found"}), 404
        d = dict(row)
        try:
            d["raw_json"] = json_mod.loads(d.get("raw_json", "{}"))
        except Exception:
            d["raw_json"] = {}
        return jsonify(d)

    @app.route("/api/helpdesk/tickets/<int:ticket_id>/link", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_helpdesk_link_device(ticket_id):
        """Link a ticket to a monitored device."""
        data = request.get_json(force=True)
        device_name = data.get("device_name", "").strip()
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute(
            "UPDATE helpdesk_tickets SET device_name=? WHERE id=?",
            (device_name, ticket_id),
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})

    @app.route("/api/helpdesk/sync", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_helpdesk_sync():
        """Force a helpdesk ticket sync."""
        result = sync_helpdesk_tickets(force=True)
        return jsonify(result)

    @app.route("/api/helpdesk/status", methods=["GET"])
    @require_tier(TIER_PRO)
    def api_helpdesk_status():
        """Get helpdesk connector status."""
        with _helpdesk_lock:
            state = dict(_helpdesk_sync_state)
        hd_cfg = _get_helpdesk_config()
        state["provider"] = hd_cfg.get("provider", "")
        state["auto_create_tickets"] = hd_cfg.get("auto_create_tickets", False)
        state["sync_interval_minutes"] = hd_cfg.get("sync_interval_minutes", 5)
        return jsonify(state)

    @app.route("/api/helpdesk/settings", methods=["GET"])
    @require_tier(TIER_PRO)
    def api_helpdesk_settings():
        """Get helpdesk configuration (masks sensitive fields)."""
        hd_cfg = _get_helpdesk_config()
        result = {
            "provider": hd_cfg.get("provider", ""),
            "sync_interval_minutes": hd_cfg.get("sync_interval_minutes", 5),
            "auto_create_tickets": hd_cfg.get("auto_create_tickets", False),
            "freshservice": {
                "domain": hd_cfg.get("freshservice", {}).get("domain", ""),
                "api_key": "***" if hd_cfg.get("freshservice", {}).get("api_key") else "",
                "default_requester_email": hd_cfg.get("freshservice", {}).get("default_requester_email", ""),
            },
            "connectwise": {
                "site_url": hd_cfg.get("connectwise", {}).get("site_url", ""),
                "company_id": hd_cfg.get("connectwise", {}).get("company_id", ""),
                "public_key": "***" if hd_cfg.get("connectwise", {}).get("public_key") else "",
                "private_key": "***" if hd_cfg.get("connectwise", {}).get("private_key") else "",
                "client_id": hd_cfg.get("connectwise", {}).get("client_id", ""),
                "default_board_id": hd_cfg.get("connectwise", {}).get("default_board_id", ""),
            },
        }
        return jsonify(result)

    @app.route("/api/helpdesk/settings", methods=["PUT"])
    @require_tier(TIER_PRO)
    def api_helpdesk_settings_update():
        """Update helpdesk configuration."""
        data = request.get_json(force=True)
        with _config_lock:
            cfg = _config
            if "helpdesk" not in cfg:
                cfg["helpdesk"] = {}
            hd = cfg["helpdesk"]

            if "provider" in data:
                hd["provider"] = str(data["provider"]).strip().lower()
            if "sync_interval_minutes" in data:
                hd["sync_interval_minutes"] = max(1, int(data["sync_interval_minutes"]))
            if "auto_create_tickets" in data:
                hd["auto_create_tickets"] = bool(data["auto_create_tickets"])

            # Freshservice settings
            if "freshservice" in data:
                if "freshservice" not in hd:
                    hd["freshservice"] = {}
                fs = data["freshservice"]
                if "domain" in fs:
                    hd["freshservice"]["domain"] = str(fs["domain"]).strip()
                if "api_key" in fs and fs["api_key"] != "***":
                    hd["freshservice"]["api_key"] = str(fs["api_key"]).strip()
                if "default_requester_email" in fs:
                    hd["freshservice"]["default_requester_email"] = str(
                        fs["default_requester_email"]
                    ).strip()

            # ConnectWise settings
            if "connectwise" in data:
                if "connectwise" not in hd:
                    hd["connectwise"] = {}
                cw = data["connectwise"]
                for field in ["site_url", "company_id", "client_id", "default_board_id"]:
                    if field in cw:
                        hd["connectwise"][field] = str(cw[field]).strip()
                if "public_key" in cw and cw["public_key"] != "***":
                    hd["connectwise"]["public_key"] = str(cw["public_key"]).strip()
                if "private_key" in cw and cw["private_key"] != "***":
                    hd["connectwise"]["private_key"] = str(cw["private_key"]).strip()

            save_config(cfg)
        return jsonify({"ok": True})

    @app.route("/api/helpdesk/test", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_helpdesk_test():
        """Test helpdesk connection with current settings."""
        hd_cfg = _get_helpdesk_config()
        provider = hd_cfg.get("provider", "").strip().lower()
        if not provider:
            return jsonify({"ok": False, "error": "No provider configured"}), 400

        try:
            if provider == "freshservice":
                fs_cfg = hd_cfg.get("freshservice", {})
                tickets = _freshservice_fetch_tickets(fs_cfg)
                return jsonify({
                    "ok": True,
                    "message": "Connected to Freshservice -- found %d tickets" % len(tickets),
                    "ticket_count": len(tickets),
                })
            elif provider == "connectwise":
                cw_cfg = hd_cfg.get("connectwise", {})
                tickets = _connectwise_fetch_tickets(cw_cfg)
                return jsonify({
                    "ok": True,
                    "message": "Connected to ConnectWise -- found %d tickets" % len(tickets),
                    "ticket_count": len(tickets),
                })
            else:
                return jsonify({"ok": False, "error": "Unknown provider: %s" % provider}), 400
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/helpdesk/create-ticket", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_helpdesk_create_ticket():
        """Manually create a ticket in the helpdesk from the dashboard."""
        data = request.get_json(force=True)
        subject = data.get("subject", "").strip()
        description = data.get("description", "").strip()
        priority = data.get("priority", "Medium")

        if not subject:
            return jsonify({"ok": False, "error": "Subject is required"}), 400

        hd_cfg = _get_helpdesk_config()
        provider = hd_cfg.get("provider", "").strip().lower()
        if not provider:
            return jsonify({"ok": False, "error": "No helpdesk provider configured"}), 400

        try:
            if provider == "freshservice":
                fs_cfg = hd_cfg.get("freshservice", {})
                ticket = _freshservice_create_ticket(
                    fs_cfg, subject, description, priority,
                    data.get("requester_email", ""),
                )
                return jsonify({"ok": True, "ticket": ticket})
            elif provider == "connectwise":
                cw_cfg = hd_cfg.get("connectwise", {})
                ticket = _connectwise_create_ticket(
                    cw_cfg, subject, description, priority,
                )
                return jsonify({"ok": True, "ticket": ticket})
            else:
                return jsonify({"ok": False, "error": "Unknown provider"}), 400
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/helpdesk/stats", methods=["GET"])
    @require_tier(TIER_PRO)
    def api_helpdesk_stats():
        """Get ticket statistics for dashboard widgets."""
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            total = conn.execute("SELECT COUNT(*) FROM helpdesk_tickets").fetchone()[0]
            open_count = conn.execute(
                "SELECT COUNT(*) FROM helpdesk_tickets WHERE LOWER(status) IN ('open','new','pending')"
            ).fetchone()[0]
            urgent_count = conn.execute(
                "SELECT COUNT(*) FROM helpdesk_tickets WHERE LOWER(priority) IN ('urgent','critical','high') AND LOWER(status) IN ('open','new','pending')"
            ).fetchone()[0]
            by_status = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM helpdesk_tickets GROUP BY status ORDER BY cnt DESC"
            ).fetchall()
            by_priority = conn.execute(
                "SELECT priority, COUNT(*) as cnt FROM helpdesk_tickets WHERE LOWER(status) IN ('open','new','pending') GROUP BY priority ORDER BY cnt DESC"
            ).fetchall()
            by_assignee = conn.execute(
                "SELECT assignee, COUNT(*) as cnt FROM helpdesk_tickets WHERE LOWER(status) IN ('open','new','pending') AND assignee != '' GROUP BY assignee ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
        finally:
            conn.close()

        return jsonify({
            "total": total,
            "open": open_count,
            "urgent": urgent_count,
            "by_status": [{"status": r["status"], "count": r["cnt"]} for r in by_status],
            "by_priority": [{"priority": r["priority"], "count": r["cnt"]} for r in by_priority],
            "by_assignee": [{"assignee": r["assignee"], "count": r["cnt"]} for r in by_assignee],
        })

    # ------------------------------------------------------------------
    # AI Assistant (Enterprise only)
    # ------------------------------------------------------------------

    @app.route("/api/ai/status")
    def api_ai_status():
        """Return AI assistant availability."""
        try:
            import ai_assistant
            status = ai_assistant.get_status()
            status["tier_ok"] = get_tier() == TIER_ENT
            return jsonify(status)
        except ImportError:
            return jsonify({"available": False, "error": "ai_assistant module not found"})

    @app.route("/api/ai/settings", methods=["GET"])
    @require_tier(TIER_ENT)
    def api_ai_settings_get():
        """Return current AI provider settings (keys masked)."""
        import ai_assistant
        cfg = ai_assistant.get_config()
        for prov in ["openai", "anthropic"]:
            if prov in cfg and cfg[prov].get("api_key"):
                key = cfg[prov]["api_key"]
                if len(key) > 8:
                    cfg[prov]["api_key"] = key[:4] + "..." + key[-4:]
                else:
                    cfg[prov]["api_key"] = "****"
        return jsonify(cfg)

    @app.route("/api/ai/settings", methods=["PUT"])
    @require_tier(TIER_ENT)
    def api_ai_settings_update():
        """Update AI provider settings."""
        import ai_assistant
        data = request.get_json(force=True, silent=True) or {}
        update = {}
        if "provider" in data:
            prov = str(data["provider"]).strip().lower()
            if prov in ai_assistant.SUPPORTED_PROVIDERS:
                update["provider"] = prov
        for pname in ["ollama", "openai", "anthropic"]:
            if pname in data and isinstance(data[pname], dict):
                oc = {}
                for fld in ["base_url", "model"]:
                    if fld in data[pname]:
                        oc[fld] = str(data[pname][fld]).strip()
                if "api_key" in data[pname]:
                    key = str(data[pname]["api_key"]).strip()
                    if key and "..." not in key and key != "****":
                        oc["api_key"] = key
                if oc:
                    update[pname] = oc
        if update:
            ai_assistant.update_config(update)
            with _config_lock:
                cfg = _config
                cfg["ai_assistant"] = ai_assistant.get_config()
                save_config(cfg)
        return jsonify({"ok": True})

    @app.route("/api/ai/test", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_ai_test():
        """Test connection to an AI provider."""
        import ai_assistant
        data = request.get_json(force=True, silent=True) or {}
        provider = data.get("provider")
        config = data.get("config", {})
        result = ai_assistant.test_connection(provider=provider, config=config or None)
        return jsonify(result)

    @app.route("/api/ai/chat", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_ai_chat():
        """Send a message to the AI assistant."""
        import ai_assistant
        data = request.get_json(force=True, silent=True) or {}
        user_msg = str(data.get("message", "")).strip()
        session_id = str(data.get("session_id", "default"))
        if not user_msg:
            return jsonify({"error": "No message provided"}), 400

        # Build context from current state
        with _config_lock:
            cfg = dict(_config)
        config_context = {
            "tier": get_tier(),
            "device_count": len(cfg.get("devices", [])),
            "alerts_configured": "email" if cfg.get("alerts", {}).get("email", {}).get("enabled") else "none",
            "helpdesk_provider": cfg.get("helpdesk", {}).get("provider", ""),
        }

        result = ai_assistant.chat(session_id, user_msg, config_context=config_context)
        return jsonify(result)

    @app.route("/api/ai/stream", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_ai_stream():
        """Stream a response from the AI assistant."""
        import ai_assistant
        data = request.get_json(force=True, silent=True) or {}
        user_msg = str(data.get("message", "")).strip()
        session_id = str(data.get("session_id", "default"))
        if not user_msg:
            return jsonify({"error": "No message provided"}), 400

        with _config_lock:
            cfg = dict(_config)
        config_context = {
            "tier": get_tier(),
            "device_count": len(cfg.get("devices", [])),
        }

        def generate():
            for chunk in ai_assistant.chat_stream(session_id, user_msg,
                                                  config_context=config_context):
                yield "data: " + json_mod.dumps(chunk) + "\n\n"

        return app.response_class(generate(), mimetype="text/event-stream")

    @app.route("/api/ai/clear", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_ai_clear():
        """Clear AI conversation history."""
        import ai_assistant
        data = request.get_json(force=True, silent=True) or {}
        session_id = str(data.get("session_id", "default"))
        return jsonify(ai_assistant.clear_conversation(session_id))

    return app


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("MyClover.Tech.netmon v5.7 starting...")
    _reload_config()

    with _config_lock:
        cfg = dict(_config)

    devices = cfg.get("devices", [])
    total_checks = sum(len(d.get("checks", [])) for d in devices)
    log.info("Loaded %d devices, %d checks", len(devices), total_checks)

    init_db()
    log.info("Database ready: %s", DB_PATH)

    mon = threading.Thread(target=monitoring_loop, daemon=True)
    mon.start()
    log.info("Monitoring thread started")

    # Start helpdesk sync thread
    hd_provider = cfg.get("helpdesk", {}).get("provider", "")
    if hd_provider:
        hd_thread = threading.Thread(target=helpdesk_sync_loop, daemon=True)
        hd_thread.start()
        log.info("Helpdesk sync thread started (provider: %s)", hd_provider)
    else:
        log.info("Helpdesk integration not configured -- skipping sync thread")

    if HAS_FLASK:
        dash_cfg = cfg.get("dashboard", {})
        host = dash_cfg.get("host", "0.0.0.0")
        port = dash_cfg.get("port", 8080)
        log.info("Dashboard: http://%s:%d", host, port)
        app = create_app()
        app.run(host=host, port=port, debug=False, use_reloader=False)
    else:
        log.info("Flask not installed -- running checks only (no dashboard)")
        mon.join()


if __name__ == "__main__":
    main()
