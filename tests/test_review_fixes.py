"""Regressions for the three issues raised in the review of PR #17.

1. A slow check must not stall the whole monitoring cycle.
2. Editing a device through the API must not silently drop its TLS overrides.
3. A cancelled maintenance window must stop excusing downtime.
"""
import datetime
import sqlite3
import time

BASE = datetime.datetime(2026, 1, 1, 0, 0, 0)


def ts(minutes):
    return (BASE + datetime.timedelta(minutes=minutes)).isoformat()


# --------------------------------------------------------------------------
# 1. Cycle deadline
# --------------------------------------------------------------------------

def test_slow_check_does_not_hold_the_cycle(netmon, monkeypatch):
    """The cycle returns at its budget even while a check is still running."""
    cfg = {"check_interval_seconds": 60, "max_check_workers": 4,
           "max_cycle_seconds": 0.2}
    devices = [{"name": "slow", "host": "10.0.0.1",
                "checks": [{"type": "ping", "label": "ICMP"}]},
               {"name": "fast", "host": "10.0.0.2",
                "checks": [{"type": "ping", "label": "ICMP"}]}]

    started = {}

    def fake_run_check(device, check):
        if device["name"] == "slow":
            started["slow"] = True
            time.sleep(1.5)
            return {"timestamp": ts(0), "device_name": "slow",
                    "host": device["host"], "check_type": "ping",
                    "status": "OK", "message": "late"}
        return {"timestamp": ts(0), "device_name": device["name"],
                "host": device["host"], "check_type": "ping",
                "status": "OK", "message": "quick"}

    monkeypatch.setattr(netmon, "run_check", fake_run_check)
    monkeypatch.setattr(netmon, "_collect_due_checks",
                        lambda *a, **k: [(d, d["checks"][0]) for d in devices])
    monkeypatch.setattr(netmon, "get_active_downtimes", lambda: set())

    t0 = time.monotonic()
    results, timed_out = netmon.run_check_cycle(cfg, devices)
    elapsed = time.monotonic() - t0

    assert started.get("slow"), "the slow check should have started"
    assert elapsed < 1.0, (
        "cycle waited %.2fs for a 1.5s check -- the deadline is not enforced"
        % elapsed)
    assert timed_out >= 1
    # The fast check's result is not thrown away.
    assert any(r[1]["device_name"] == "fast" for r in results)


def test_late_result_is_recovered_by_the_next_cycle(netmon, monkeypatch):
    """A check that overruns delivers into the next cycle, not into the void."""
    cfg = {"check_interval_seconds": 60, "max_check_workers": 4,
           "max_cycle_seconds": 0.2}
    device = {"name": "slow", "host": "10.0.0.1",
              "checks": [{"type": "ping", "label": "ICMP"}]}

    def fake_run_check(dev, chk):
        time.sleep(0.4)
        return {"timestamp": ts(0), "device_name": "slow", "host": dev["host"],
                "check_type": "ping", "status": "OK", "message": "late"}

    monkeypatch.setattr(netmon, "run_check", fake_run_check)
    monkeypatch.setattr(netmon, "_collect_due_checks",
                        lambda *a, **k: [(device, device["checks"][0])])
    monkeypatch.setattr(netmon, "get_active_downtimes", lambda: set())

    results, timed_out = netmon.run_check_cycle(cfg, devices=[device])
    assert results == [] and timed_out == 1

    time.sleep(0.6)  # the straggler finishes in the background
    results2, _ = netmon.run_check_cycle(cfg, devices=[device])
    assert any(r[1]["message"] == "late" for r in results2), \
        "the overrunning check's result was lost"


def test_inflight_check_is_not_started_twice(netmon, monkeypatch):
    """Consecutive cycles must not pile up duplicate runs of one check."""
    cfg = {"check_interval_seconds": 60, "max_check_workers": 4,
           "max_cycle_seconds": 0.2}
    device = {"name": "slow", "host": "10.0.0.1",
              "checks": [{"type": "ping", "label": "ICMP"}]}
    calls = []

    def fake_run_check(dev, chk):
        calls.append(1)
        time.sleep(0.5)
        return {"timestamp": ts(0), "device_name": "slow", "host": dev["host"],
                "check_type": "ping", "status": "OK", "message": "ok"}

    monkeypatch.setattr(netmon, "run_check", fake_run_check)
    monkeypatch.setattr(netmon, "_collect_due_checks",
                        lambda *a, **k: [(device, device["checks"][0])])
    monkeypatch.setattr(netmon, "get_active_downtimes", lambda: set())

    netmon.run_check_cycle(cfg, devices=[device])
    netmon.run_check_cycle(cfg, devices=[device])
    assert len(calls) == 1, "the same check ran twice concurrently"
    time.sleep(0.7)


# --------------------------------------------------------------------------
# 2. TLS overrides survive an edit
# --------------------------------------------------------------------------

def test_sanitize_device_keeps_tls_overrides(netmon):
    out = netmon._sanitize_device({
        "name": "intranet", "host": "10.0.0.5",
        "checks": [{"type": "http", "url": "https://10.0.0.5/",
                    "verify_tls": False,
                    "ca_bundle": "/app/data/corp-ca.pem"}]})
    chk = out["checks"][0]
    assert chk["verify_tls"] is False
    assert chk["ca_bundle"] == "/app/data/corp-ca.pem"


def test_device_edit_round_trip_preserves_tls(netmon):
    """GET the device, PUT it back unchanged: TLS settings must survive."""
    device = {"name": "intranet", "host": "10.0.0.5", "group": "Internal",
              "checks": [{"type": "http", "label": "WEB",
                          "url": "https://10.0.0.5/", "verify_tls": False,
                          "ca_bundle": "/app/data/corp-ca.pem"}]}
    sanitized = netmon._sanitize_device(device)
    # Simulate the dashboard sending back exactly what it was given.
    again = netmon._sanitize_device(sanitized)
    assert again["checks"][0]["verify_tls"] is False
    assert again["checks"][0]["ca_bundle"] == "/app/data/corp-ca.pem"
    # And the resolved verification setting still points at the custom CA.
    assert netmon._tls_verify_setting(again["checks"][0]) == \
        "/app/data/corp-ca.pem"
    no_ca = dict(again["checks"][0])
    no_ca.pop("ca_bundle")
    assert netmon._tls_verify_setting(no_ca) is False


# --------------------------------------------------------------------------
# 3. Cancelled maintenance windows
# --------------------------------------------------------------------------

def _insert_downtime(netmon, start_min, end_min, active=1, cancelled_at=None):
    conn = sqlite3.connect(str(netmon.DB_PATH))
    conn.execute(
        "INSERT INTO scheduled_downtime (device_name,start_time,end_time,"
        "reason,created_by,created_at,active,cancelled_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        ("srv1", ts(start_min), ts(end_min), "patching", "admin", ts(0),
         active, cancelled_at or ""))
    conn.commit()
    conn.close()


def _windows(netmon, hours=2):
    conn = sqlite3.connect(str(netmon.DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        return netmon._maintenance_windows(
            conn, "srv1", BASE, BASE + datetime.timedelta(hours=hours))
    finally:
        conn.close()


def test_active_window_is_still_maintenance(netmon):
    _insert_downtime(netmon, 0, 30, active=1)
    assert netmon._interval_minutes(_windows(netmon)) == 30


def test_cancelled_window_does_not_hide_downtime(netmon):
    """A window cancelled before it began excuses nothing."""
    _insert_downtime(netmon, 0, 30, active=0, cancelled_at=ts(-10))
    assert _windows(netmon) == []


def test_cancelled_window_without_timestamp_is_ignored(netmon):
    """Legacy cancellations have no recorded time: ignore, do not excuse."""
    _insert_downtime(netmon, 0, 30, active=0, cancelled_at="")
    assert _windows(netmon) == []


def test_window_cancelled_midway_excuses_only_up_to_cancellation(netmon):
    _insert_downtime(netmon, 0, 30, active=0, cancelled_at=ts(10))
    assert netmon._interval_minutes(_windows(netmon)) == 10


def test_cancel_endpoint_records_the_cancellation_time(netmon, client,
                                                       monkeypatch):
    # Scheduled downtime is a Pro feature.
    monkeypatch.setattr(netmon, "_current_tier", netmon.TIER_PRO)
    _insert_downtime(netmon, 0, 30, active=1)
    conn = sqlite3.connect(str(netmon.DB_PATH))
    dt_id = conn.execute("SELECT id FROM scheduled_downtime").fetchone()[0]
    conn.close()

    resp = client.post("/api/downtime/%d/cancel" % dt_id)
    assert resp.status_code == 200, resp.data

    conn = sqlite3.connect(str(netmon.DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT active, cancelled_at FROM scheduled_downtime "
                       "WHERE id=?", (dt_id,)).fetchone()
    conn.close()
    assert row["active"] == 0
    assert row["cancelled_at"], "cancellation time was not recorded"
