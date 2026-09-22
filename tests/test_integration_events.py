"""Tests for the /api/integration/events feed used by SentryLog's timeline.

The feed exports state *transitions*, not raw check results, and is the only
endpoint that accepts the shared integration token. Both of those properties are
load-bearing, so both are pinned here.
"""
import datetime


def _insert_result(netmon, device, label, status, minutes_ago, host="10.0.0.5",
                   check_type="ping", message=""):
    ts = (datetime.datetime.now() - datetime.timedelta(minutes=minutes_ago)
          ).strftime("%Y-%m-%d %H:%M:%S")
    conn = netmon.sqlite3.connect(str(netmon.DB_PATH))
    conn.execute(
        "INSERT INTO check_results (timestamp, device_name, host, check_type,"
        " check_label, status, response_ms, message) VALUES (?,?,?,?,?,?,?,?)",
        (ts, device, host, check_type, label, status, 12.5, message))
    conn.commit()
    conn.close()
    return ts


def _insert_alert(netmon, device, status, minutes_ago, label="ping"):
    ts = (datetime.datetime.now() - datetime.timedelta(minutes=minutes_ago)
          ).strftime("%Y-%m-%d %H:%M:%S")
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

    start = (datetime.datetime.now() - datetime.timedelta(minutes=60)
             ).strftime("%Y-%m-%d %H:%M:%S")
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
    assert events == sorted(events, key=lambda e: e["timestamp"])


def test_device_filter_and_window_are_applied(netmon):
    _insert_result(netmon, "router", "ping", "critical", 30)
    _insert_result(netmon, "switch", "ping", "critical", 30)
    _insert_result(netmon, "router", "ping", "warning", 5)

    start = (datetime.datetime.now() - datetime.timedelta(minutes=10)
             ).strftime("%Y-%m-%d %H:%M:%S")
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
