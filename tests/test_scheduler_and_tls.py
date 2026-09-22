"""Bounded concurrency, schedule adherence, stale display, TLS verification."""
import datetime
import threading
import time


def configure(netmon, devices, **extra):
    cfg = netmon.load_config()
    cfg["devices"] = devices
    cfg.update(extra)
    netmon.save_config(cfg)
    netmon._reload_config()


def test_concurrency_is_bounded(netmon, monkeypatch):
    devices = [{"name": "d%d" % i, "host": "10.0.0.%d" % i,
                "checks": [{"type": "ping", "label": "ICMP"}]}
               for i in range(40)]
    configure(netmon, devices, max_check_workers=5)

    live = {"now": 0, "peak": 0}
    lock = threading.Lock()

    def fake_run_check(device, check):
        with lock:
            live["now"] += 1
            live["peak"] = max(live["peak"], live["now"])
        time.sleep(0.02)
        with lock:
            live["now"] -= 1
        return {"timestamp": datetime.datetime.now().isoformat(),
                "device_name": device["name"], "host": device["host"],
                "check_type": "ping", "check_label": "ICMP", "status": "OK",
                "response_ms": 1.0, "message": "ok"}

    monkeypatch.setattr(netmon, "run_check", fake_run_check)
    with netmon._config_lock:
        cfg = dict(netmon._config)
    results, timed_out = netmon.run_check_cycle(cfg, devices)
    assert len(results) == 40
    assert timed_out == 0
    assert live["peak"] <= 5, "worker pool was not bounded (peak %d)" % live["peak"]


def test_maintenance_and_parent_suppression_still_apply(netmon):
    devices = [
        {"name": "up", "host": "10.0.0.1", "checks": [{"type": "ping"}]},
        {"name": "maint", "host": "10.0.0.2", "maintenance": True,
         "checks": [{"type": "ping"}]},
    ]
    configure(netmon, devices)
    tasks = netmon._collect_due_checks(devices, set(), {}, {})
    assert [d["name"] for d, _ in tasks] == ["up"]
    tasks = netmon._collect_due_checks(devices, {"up"}, {}, {})
    assert tasks == []


def test_interval_is_a_deadline_not_a_trailing_sleep(netmon, monkeypatch):
    """Cycle work must be subtracted from the sleep, not added to the interval."""
    configure(netmon, [{"name": "d", "host": "10.0.0.1",
                        "checks": [{"type": "ping"}]}],
              check_interval_seconds=5)
    def slow_cycle(cfg, devices):
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline:  # busy work, no sleep to intercept
            pass
        return [], 0

    monkeypatch.setattr(netmon, "run_check_cycle", slow_cycle)
    slept = []
    monkeypatch.setattr(netmon.time, "sleep", lambda s: slept.append(s))
    netmon.monitoring_loop(max_cycles=2)
    assert slept, "loop never slept"
    # 5s interval minus ~0.3s of work.
    assert 4.0 < slept[0] < 5.0


def test_overrun_is_recorded_not_silently_absorbed(netmon, monkeypatch):
    configure(netmon, [], check_interval_seconds=5)
    monkeypatch.setattr(netmon, "run_check_cycle", lambda cfg, devices: ([], 0))
    monkeypatch.setattr(netmon.time, "monotonic",
                        lambda counter=iter(range(0, 2000, 100)): next(counter))
    monkeypatch.setattr(netmon.time, "sleep", lambda s: None)
    netmon.monitoring_loop(max_cycles=2)
    assert netmon._cycle_stats["overruns"] >= 1


def test_notifications_do_not_block_the_cycle(netmon, monkeypatch):
    sent = threading.Event()
    monkeypatch.setattr(netmon, "send_alert_email",
                        lambda result, cfg: (time.sleep(0.05), sent.set(), True)[2])
    monkeypatch.setattr(netmon, "store_alert", lambda result, email_sent=False: None)
    netmon.start_notification_worker()
    result = {"timestamp": datetime.datetime.now().isoformat(),
              "device_name": "d", "host": "10.0.0.1", "check_type": "ping",
              "check_label": "ICMP", "status": "CRITICAL", "response_ms": None,
              "message": "down"}
    t0 = time.monotonic()
    netmon.queue_notification(result, {}, [])
    assert time.monotonic() - t0 < 0.02, "queueing blocked the caller"
    assert sent.wait(2), "notification worker never delivered"


def test_monitoring_health_reports_staleness(netmon):
    health = netmon.get_monitoring_health()
    assert health["stale"] is True  # no cycle has run yet
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    with netmon._cycle_stats_lock:
        netmon._cycle_stats.update({
            "last_finished_at": now.isoformat(), "interval_seconds": 60})
    assert netmon.get_monitoring_health(now=now)["stale"] is False
    later = now + datetime.timedelta(seconds=600)
    assert netmon.get_monitoring_health(now=later)["stale"] is True


def test_status_rows_are_marked_stale(netmon):
    now = datetime.datetime(2026, 1, 1, 12, 0, 0)
    rows = [{"timestamp": (now - datetime.timedelta(seconds=30)).isoformat()},
            {"timestamp": (now - datetime.timedelta(seconds=900)).isoformat()},
            {"timestamp": None}]
    marked = netmon.annotate_staleness(rows, interval=60, now=now)
    assert marked[0]["stale"] is False
    assert marked[1]["stale"] is True
    assert marked[2]["stale"] is True


def test_status_and_health_endpoints(client):
    assert client.get("/api/status").status_code == 200
    health = client.get("/api/monitoring-health").get_json()
    assert "stale" in health and "notify_queue_depth" in health


# --- TLS -------------------------------------------------------------------

def test_tls_is_verified_by_default(netmon):
    assert netmon._tls_verify_setting({}) is True
    assert netmon._tls_verify_setting({"type": "http"}) is True


def test_per_check_override_and_custom_ca(netmon):
    assert netmon._tls_verify_setting({"verify_tls": False}) is False
    assert netmon._tls_verify_setting({"ca_bundle": "/etc/ssl/corp.pem"}) == \
        "/etc/ssl/corp.pem"


def test_account_wide_default_can_opt_out(netmon):
    cfg = netmon.load_config()
    cfg["http_verify_tls"] = False
    netmon.save_config(cfg)
    netmon._reload_config()
    assert netmon._tls_verify_setting({}) is False
    assert netmon._tls_verify_setting({"verify_tls": True}) is True


def test_http_check_passes_verify_through(netmon, monkeypatch):
    seen = {}

    class FakeResp:
        status_code = 200

    def fake_get(url, timeout=None, verify=None, allow_redirects=None):
        seen["verify"] = verify
        return FakeResp()

    monkeypatch.setattr(netmon.req_lib, "get", fake_get)
    netmon.http_check("https://example.com", 200, 1000, verify=True)
    assert seen["verify"] is True
    netmon.run_check({"name": "d", "host": "example.com"},
                     {"type": "http", "url": "https://example.com"})
    assert seen["verify"] is True, "run_check must not disable verification"


def test_no_unverified_requests_left_in_source():
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent.joinpath("netmon.py").read_text(
        encoding="utf-8")
    assert "verify=False" not in src
