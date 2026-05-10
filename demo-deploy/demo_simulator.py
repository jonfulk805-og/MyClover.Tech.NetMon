#!/usr/bin/env python3
"""
demo_simulator.py -- Generates live simulated monitoring data for the demo.
Runs alongside netmon.py in the container. Inserts realistic check results,
fires occasional alerts, and keeps the dashboard feeling alive.
"""

import sqlite3
import datetime
import random
import time
import os
import sys
import signal

DB_PATH = os.environ.get("DEMO_DB_PATH", "/app/netmon.db")
CHECK_INTERVAL = 30  # seconds between simulated check rounds

DEVICES = [
    {"name": "Optimus (Edge Firewall)", "host": "10.0.1.1", "group": "Network",
     "checks": [("ping", "ICMP")], "base_ms": 2, "fail_rate": 0.005},
    {"name": "Megatron (Core Switch)", "host": "10.0.1.2", "group": "Network",
     "checks": [("ping", "ICMP")], "base_ms": 1.5, "fail_rate": 0.003},
    {"name": "Bender (Switch Floor 1)", "host": "10.0.1.3", "group": "Network",
     "checks": [("ping", "ICMP")], "base_ms": 2, "fail_rate": 0.005},
    {"name": "Fry (Switch Floor 2)", "host": "10.0.1.4", "group": "Network",
     "checks": [("ping", "ICMP")], "base_ms": 2, "fail_rate": 0.005},
    {"name": "Jarvis (Wireless Controller)", "host": "10.0.1.10", "group": "Network",
     "checks": [("ping", "ICMP")], "base_ms": 3, "fail_rate": 0.005},
    {"name": "Groot (AP Lobby)", "host": "10.0.1.11", "group": "Wireless",
     "checks": [("ping", "ICMP")], "base_ms": 8, "fail_rate": 0.01},
    {"name": "Rocket (AP Office)", "host": "10.0.1.12", "group": "Wireless",
     "checks": [("ping", "ICMP")], "base_ms": 8, "fail_rate": 0.01},
    {"name": "Chewy (AP Warehouse)", "host": "10.0.1.13", "group": "Wireless",
     "checks": [("ping", "ICMP")], "base_ms": 12, "fail_rate": 0.02},
    {"name": "Picard (Primary DC)", "host": "10.0.2.10", "group": "Servers",
     "checks": [("ping", "ICMP"), ("port", "DNS"), ("port", "LDAP")], "base_ms": 3, "fail_rate": 0.002},
    {"name": "Data (Backup DC)", "host": "10.0.2.11", "group": "Servers",
     "checks": [("ping", "ICMP"), ("port", "DNS"), ("port", "LDAP")], "base_ms": 3, "fail_rate": 0.002},
    {"name": "Yoda (File Server)", "host": "10.0.2.20", "group": "Servers",
     "checks": [("ping", "ICMP"), ("port", "SMB")], "base_ms": 4, "fail_rate": 0.005},
    {"name": "Wolverine (Web Server)", "host": "10.0.2.30", "group": "Servers",
     "checks": [("ping", "ICMP"), ("http", "HTTP"), ("port", "HTTPS")], "base_ms": 5, "fail_rate": 0.008},
    {"name": "Spock (SQL Server)", "host": "10.0.2.40", "group": "Servers",
     "checks": [("ping", "ICMP"), ("port", "SQL")], "base_ms": 3, "fail_rate": 0.005},
    {"name": "C3PO (Exchange Server)", "host": "10.0.2.50", "group": "Servers",
     "checks": [("ping", "ICMP"), ("port", "SMTP"), ("port", "HTTPS")], "base_ms": 5, "fail_rate": 0.008},
    {"name": "R2D2 (Backup Server)", "host": "10.0.2.60", "group": "Servers",
     "checks": [("ping", "ICMP")], "base_ms": 4, "fail_rate": 0.003},
    {"name": "Thanos (Hypervisor-01)", "host": "10.0.2.70", "group": "Servers",
     "checks": [("ping", "ICMP"), ("port", "Web UI")], "base_ms": 2, "fail_rate": 0.003},
    {"name": "Galactus (Hypervisor-02)", "host": "10.0.2.71", "group": "Servers",
     "checks": [("ping", "ICMP"), ("port", "Web UI")], "base_ms": 2, "fail_rate": 0.003},
    {"name": "Neo (VPN Gateway)", "host": "10.0.1.5", "group": "Network",
     "checks": [("ping", "ICMP"), ("port", "WireGuard")], "base_ms": 3, "fail_rate": 0.005},
    {"name": "Batman (NVR)", "host": "10.0.3.10", "group": "Security",
     "checks": [("ping", "ICMP"), ("port", "RTSP")], "base_ms": 5, "fail_rate": 0.01},
    {"name": "Scotty (VoIP PBX)", "host": "10.0.3.20", "group": "Infrastructure",
     "checks": [("ping", "ICMP"), ("port", "SIP")], "base_ms": 4, "fail_rate": 0.005},
    {"name": "Scooby (Printer Office)", "host": "10.0.3.30", "group": "Peripherals",
     "checks": [("ping", "ICMP")], "base_ms": 12, "fail_rate": 0.015},
    {"name": "Shaggy (Printer Warehouse)", "host": "10.0.3.31", "group": "Peripherals",
     "checks": [("ping", "ICMP")], "base_ms": 20, "fail_rate": 0.15},  # In maintenance, flaky
    {"name": "Thor (UPS Server Room)", "host": "10.0.3.40", "group": "Infrastructure",
     "checks": [("ping", "ICMP"), ("port", "SNMP")], "base_ms": 4, "fail_rate": 0.005},
]

running = True


def handle_signal(signum, frame):
    global running
    running = False
    print("[SIMULATOR] Shutting down...")


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


def simulate_round():
    """Run one round of simulated checks for all devices."""
    now = datetime.datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    results = []
    perf_rows = []
    alerts = []

    for dev in DEVICES:
        for check_type, check_label in dev["checks"]:
            roll = random.random()
            base = dev["base_ms"]
            fail_rate = dev["fail_rate"]

            if roll < fail_rate:
                status = "critical"
                resp_ms = None
                if check_type == "ping":
                    msg = "Request timed out"
                elif check_type == "http":
                    msg = "HTTP 503 Service Unavailable"
                else:
                    msg = "Connection refused"
                # Generate alert
                alerts.append((now, dev["name"], check_type, check_label,
                               status, msg, 0, 0, "", ""))
            elif roll < fail_rate + 0.03:
                status = "warning"
                resp_ms = round(random.uniform(base * 3, base * 8), 1)
                msg = "High latency: %.1fms" % resp_ms
            else:
                status = "ok"
                if check_type == "ping":
                    resp_ms = round(random.gauss(base, base * 0.25), 1)
                    resp_ms = max(0.3, resp_ms)
                elif check_type == "http":
                    resp_ms = round(random.gauss(40 + base, 12), 1)
                    resp_ms = max(5, resp_ms)
                else:
                    resp_ms = round(random.gauss(base * 0.5, base * 0.2), 1)
                    resp_ms = max(0.2, resp_ms)
                msg = "OK"

            results.append((now, dev["name"], dev["host"], check_type,
                            check_label, status, resp_ms, msg))
            perf_rows.append((now, dev["name"], check_label, status, resp_ms))

    conn.executemany(
        "INSERT INTO check_results (timestamp,device_name,host,check_type,"
        "check_label,status,response_ms,message) VALUES (?,?,?,?,?,?,?,?)",
        results)
    conn.executemany(
        "INSERT INTO perf_data (timestamp,device_name,check_label,status,response_ms) "
        "VALUES (?,?,?,?,?)", perf_rows)
    if alerts:
        conn.executemany(
            "INSERT INTO alerts (timestamp,device_name,check_type,check_label,"
            "status,message,email_sent,acknowledged,acknowledged_by,acknowledged_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)", alerts)

    conn.commit()

    # Prune old data to prevent DB bloat (keep 72h of check results, 7d alerts)
    cutoff_results = (datetime.datetime.utcnow() - datetime.timedelta(hours=72)).isoformat()
    cutoff_alerts = (datetime.datetime.utcnow() - datetime.timedelta(days=7)).isoformat()
    conn.execute("DELETE FROM check_results WHERE timestamp < ?", (cutoff_results,))
    conn.execute("DELETE FROM perf_data WHERE timestamp < ?", (cutoff_results,))
    conn.execute("DELETE FROM alerts WHERE timestamp < ? AND acknowledged = 0", (cutoff_alerts,))
    conn.commit()
    conn.close()

    alert_count = len(alerts)
    crit = sum(1 for r in results if r[5] == "critical")
    warn = sum(1 for r in results if r[5] == "warning")
    ok = sum(1 for r in results if r[5] == "ok")
    print(f"[SIMULATOR] Round complete: {ok} ok, {warn} warn, {crit} crit, {alert_count} alerts")


def main():
    print("[SIMULATOR] MyClover.Tech.NetMon Demo Simulator starting...")
    print(f"[SIMULATOR] DB: {DB_PATH}, interval: {CHECK_INTERVAL}s")

    # Wait for the database to be ready
    retries = 0
    while not os.path.exists(DB_PATH) and retries < 30:
        print("[SIMULATOR] Waiting for database...")
        time.sleep(2)
        retries += 1

    if not os.path.exists(DB_PATH):
        print("[SIMULATOR] ERROR: Database not found after 60s. Exiting.")
        sys.exit(1)

    print("[SIMULATOR] Database found. Starting simulation loop.")

    while running:
        try:
            simulate_round()
        except Exception as e:
            print(f"[SIMULATOR] Error in round: {e}")
        time.sleep(CHECK_INTERVAL)

    print("[SIMULATOR] Stopped.")


if __name__ == "__main__":
    main()
