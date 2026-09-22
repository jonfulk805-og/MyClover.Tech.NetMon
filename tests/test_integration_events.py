"""Tests for the /api/integration/events feed used by SentryLog's timeline.

The feed exports state *transitions*, not raw check results, and is the only
endpoint that accepts the shared integration token. Both of those properties are
load-bearing, so both are pinned here.
"""
import datetime


def _utc_now():
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


def _stored_ts(minutes_ago):
    """The format NetMon really writes: naive UTC isoformat (see run_check)."""
    return (_utc_now() - datetime.timedelta(minutes=minutes_ago)).isoformat()


def _wire_bound(minutes_ago):
    """The format a consumer sends: timezone-aware UTC."""
    return (_utc_now() - datetime.timedelta(minutes=minutes_ago)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _insert_result(netmon, device, label, status, minutes_ago, host="10.0.0.5",
                   check_type="ping", message=""):
    ts = _stored_ts(minutes_ago)
    conn = netmon.sqlite3.connect(str(netmon.DB_PATH))
    conn.execute(
        "INSERT INTO check_results (timestamp, device_name, host, check_type,"
        " check_label, status, response_ms, message) VALUES (?,?,?,?,?,?,?,?)",
        (ts, device, host, check_type, label, status, 12.5, message))
    conn.commit()
    conn.close()
    return ts


def _insert_alert(netmon, device, status, minutes_ago, label="ping"):
    ts = _stored_ts(minutes_ago)
    conn = netmon.sqlite3.connect(str(netmon.DB_PATH))
    conn.execute(
        "INSERT INTO alerts (timestamp, device_name, check_type, check_label,"
        " status, message) VALUES (?,?,?,?,?,?)",
        (ts, device, "ping", label, status, "went " + status))
    conn.commit()
    conn.close()
    return ts


def _enable_integration(netmon, token="tok-123"):
    with netmon._config_lock:
        netmon._config["integration"] = {"read_token": token}
    return token


# --------------------------------------------------------------------------
# Event extraction
# --------------------------------------------------------------------------

def test_only_state_changes_are_reported(netmon):
    """A check that keeps reporting the same status is not an event."""
    for minutes in (50, 45, 40):
        _insert_result(netmon, "router", "ping", "ok", minutes)
    _insert_result(netmon, "router", "ping", "critical", 35)
    for minutes in (30, 25):
        _insert_result(netmon, "router", "ping", "critical", minutes)
    _insert_result(netmon, "router", "ping", "ok", 20)

    events = netmon.get_device_events()["events"]
    statuses = [(e["previous_status"], e["status"]) for e in events]
    # critical->... transitions only: 6 rows collapse to 2 changes, and the
    # opening "ok" baseline is not reported as a change.
    assert statuses == [("ok", "critical"), ("critical", "ok")]


def test_a_bad_first_observation_is_reported_but_a_good_one_is_not(netmon):
    """A fresh database must not look like a recovery storm."""
    _insert_result(netmon, "switch", "ping", "ok", 30)
    _insert_result(netmon, "fileserver", "ping", "critical", 30)

    devices = [e["device"] for e in netmon.get_device_events()["events"]]
    assert devices == ["fileserver"]


def test_state_before_the_window_is_used_so_transitions_are_not_missed(netmon):
    """A change on the first in-window row is still a change."""
    _insert_result(netmon, "router", "ping", "ok", 120)
    _insert_result(netmon, "router", "ping", "critical", 30)

    start = _wire_bound(60)
    events = netmon.get_device_events(start=start)["events"]
    assert len(events) == 1
    assert events[0]["previous_status"] == "ok", (
        "pre-window status was ignored, so the outage looks like a baseline")
    assert events[0]["status"] == "critical"


def test_events_include_the_host_for_log_correlation(netmon):
    _insert_result(netmon, "router", "ping", "critical", 10, host="192.168.1.1")
    events = netmon.get_device_events()["events"]
    assert events[0]["host"] == "192.168.1.1"


def test_alerts_are_merged_in_chronological_order(netmon):
    _insert_result(netmon, "router", "ping", "critical", 30)
    _insert_alert(netmon, "router", "critical", 29)
    _insert_result(netmon, "router", "ping", "ok", 10)

    events = netmon.get_device_events()["events"]
    assert [e["type"] for e in events] == ["state_change", "alert",
                                           "state_change"]
    assert all(e["timestamp"].endswith("Z") for e in events)
    assert events == sorted(events, key=lambda e: e["timestamp"])


def test_device_filter_and_window_are_applied(netmon):
    _insert_result(netmon, "router", "ping", "critical", 30)
    _insert_result(netmon, "switch", "ping", "critical", 30)
    _insert_result(netmon, "router", "ping", "warning", 5)

    start = _wire_bound(10)
    result = netmon.get_device_events(start=start, device_filter=["router"])
    assert [e["device"] for e in result["events"]] == ["router"]
    assert result["events"][0]["status"] == "warning"


def test_limit_is_bounded_and_keeps_the_newest_events(netmon):
    for i in range(20):
        _insert_result(netmon, "router", "ping",
                       "critical" if i % 2 else "ok", 100 - i)

    result = netmon.get_device_events(limit=5)
    assert result["truncated"] is True
    assert len(result["events"]) == 5
    newest = netmon.get_device_events()["events"][-5:]
    assert result["events"] == newest, "trimming dropped the newest events"

    # A caller cannot ask for an unbounded dump.
    assert netmon.get_device_events(limit=999999)["limit"] == \
        netmon._EVENTS_MAX_LIMIT
    assert netmon.get_device_events(limit="nonsense")["limit"] == \
        netmon._EVENTS_DEFAULT_LIMIT


# --------------------------------------------------------------------------
# Time contract (review round 1, P1): real stored rows vs real consumer bounds
# --------------------------------------------------------------------------

def _real_result(netmon, status, name="router", host="10.0.0.5"):
    """A result produced by NetMon's own code path, not a hand-written row."""
    r = netmon.run_check({"name": name, "host": host},
                         {"type": "unknown-type", "label": "ping"})
    r["status"] = status
    netmon.store_result(r)
    return r


def test_window_encloses_a_real_run_check_result(netmon):
    """The reported bug: T-format rows fell outside a space-format end bound."""
    _real_result(netmon, "CRITICAL")
    start = _wire_bound(5)
    end = (_utc_now() + datetime.timedelta(minutes=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    events = netmon.get_device_events(start=start, end=end)["events"]
    assert len(events) == 1, "a result inside the window was dropped"

    # A bound written with a space instead of a T is the same instant.
    events = netmon.get_device_events(
        start=start.replace("T", " "), end=end.replace("T", " "))["events"]
    assert len(events) == 1


def test_offset_bounds_are_converted_to_utc(netmon):
    """-07:00 bounds must mean the same instant, not the same wall clock."""
    _insert_result(netmon, "router", "ping", "critical", 30)
    pdt = datetime.timezone(datetime.timedelta(hours=-7))
    now_pdt = datetime.datetime.now(pdt)
    start = (now_pdt - datetime.timedelta(minutes=45)).isoformat()
    end = (now_pdt - datetime.timedelta(minutes=15)).isoformat()
    assert len(netmon.get_device_events(start=start, end=end)["events"]) == 1

    # The same wall-clock numbers without the offset are 7 hours earlier in
    # UTC and must NOT match -- this is the offset half of the bug.
    naive_start = (now_pdt - datetime.timedelta(minutes=45)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    naive_end = (now_pdt - datetime.timedelta(minutes=15)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    assert netmon.get_device_events(start=naive_start,
                                    end=naive_end)["events"] == []


def test_emitted_timestamps_are_canonical_utc(netmon):
    r = _real_result(netmon, "CRITICAL")
    ev = netmon.get_device_events()["events"][0]
    assert ev["timestamp"] == r["timestamp"] + "Z"


def test_ordering_uses_instants_not_mixed_strings(netmon):
    """A legacy space-format row must still sort by time, not by character."""
    conn = netmon.sqlite3.connect(str(netmon.DB_PATH))
    older = (_utc_now() - datetime.timedelta(minutes=20)).isoformat()
    newer = (_utc_now() - datetime.timedelta(minutes=10)).strftime(
        "%Y-%m-%d %H:%M:%S")
    for ts, dev in ((older, "a-router"), (newer, "b-switch")):
        conn.execute(
            "INSERT INTO check_results (timestamp, device_name, host,"
            " check_type, check_label, status) VALUES (?,?,?,?,?,?)",
            (ts, dev, "10.0.0.5", "ping", "ping", "critical"))
    conn.commit()
    conn.close()
    events = netmon.get_device_events()["events"]
    assert [e["device"] for e in events] == ["a-router", "b-switch"]


def test_unparseable_bound_is_a_400_not_an_empty_window(netmon, client):
    resp = client.get("/api/integration/events?from=yesterday-ish")
    assert resp.status_code == 400


# --------------------------------------------------------------------------
# Host scoping (review round 1, P2 x2)
# --------------------------------------------------------------------------

def test_host_filter_restricts_events(netmon):
    _insert_result(netmon, "router", "ping", "critical", 20, host="10.0.0.5")
    _insert_result(netmon, "nas", "ping", "critical", 20, host="10.0.0.9")
    events = netmon.get_device_events(host_filter=["10.0.0.5"])["events"]
    assert [e["host"] for e in events] == ["10.0.0.5"]

    none = netmon.get_device_events(host_filter=["10.9.9.9"])["events"]
    assert none == [], "an unknown host widened to every device"


def test_steady_device_still_reports_its_host(netmon):
    """No transitions is the healthy case, and the consumer still needs the host."""
    with netmon._config_lock:
        netmon._config["devices"] = [{"name": "router", "host": "10.0.0.5",
                                      "checks": []}]
    for minutes in (30, 20, 10):
        _insert_result(netmon, "router", "ping", "ok", minutes)
    result = netmon.get_device_events(start=_wire_bound(25),
                                      device_filter=["router", "ghost"])
    assert result["events"] == []
    assert result["device_hosts"] == {"router": "10.0.0.5"}, (
        "unknown devices must not appear; known ones must")


# --------------------------------------------------------------------------
# Authorization
# --------------------------------------------------------------------------

def _enable_auth(netmon):
    with netmon._config_lock:
        netmon._config["auth_enabled"] = True
        netmon._config["users"] = [{
            "username": "admin", "role": "admin",
            "password_hash": netmon.hash_password("pw")
            if hasattr(netmon, "hash_password") else "",
        }]


def test_integration_token_reaches_the_event_feed_when_auth_is_on(netmon,
                                                                  client):
    _insert_result(netmon, "router", "ping", "critical", 10)
    token = _enable_integration(netmon)
    _enable_auth(netmon)

    assert client.get("/api/integration/events").status_code == 401
    resp = client.get("/api/integration/events",
                      headers={"X-Netmon-Integration-Token": token})
    assert resp.status_code == 200
    assert resp.get_json()["events"][0]["device"] == "router"


def test_integration_token_is_not_a_key_to_the_rest_of_the_api(netmon, client):
    token = _enable_integration(netmon)
    _enable_auth(netmon)
    for path in ("/api/status", "/api/settings", "/api/devices"):
        resp = client.get(path, headers={"X-Netmon-Integration-Token": token})
        assert resp.status_code in (401, 403, 404), (
            "%s accepted the integration token" % path)


def test_wrong_or_unconfigured_token_is_refused(netmon, client):
    _enable_integration(netmon, "right-token")
    _enable_auth(netmon)
    assert client.get("/api/integration/events",
                      headers={"X-Netmon-Integration-Token": "wrong"}
                      ).status_code == 401

    # No token configured must not mean "everything matches".
    with netmon._config_lock:
        netmon._config["integration"] = {"read_token": ""}
    assert client.get("/api/integration/events",
                      headers={"X-Netmon-Integration-Token": ""}
                      ).status_code == 401
    assert netmon._integration_token_ok.__doc__  # documented behaviour
