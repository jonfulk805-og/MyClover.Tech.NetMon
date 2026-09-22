"""SLA maths: durations come from state transitions, per sensor."""
import datetime
import sqlite3

BASE = datetime.datetime(2026, 1, 1, 0, 0, 0)


def ts(minutes):
    return (BASE + datetime.timedelta(minutes=minutes)).isoformat()


def samples(*pairs):
    return [(ts(m), s) for m, s in pairs]


def test_downtime_uses_timestamps_not_sample_counts(netmon):
    """Two failed samples 30 minutes apart are 30 minutes, not 2 x interval."""
    out = netmon.sensor_state_intervals(
        samples((0, "OK"), (30, "CRITICAL"), (60, "OK")),
        BASE, BASE + datetime.timedelta(minutes=90), interval_seconds=1800)
    assert netmon._interval_minutes(out["down"]) == 30
    assert netmon._interval_minutes(out["up"]) == 60


def test_gap_without_observations_is_unknown_not_downtime(netmon):
    out = netmon.sensor_state_intervals(
        samples((0, "OK"), (600, "OK")),
        BASE, BASE + datetime.timedelta(minutes=600), interval_seconds=60)
    # interval 60s, max hold 3 min -> the 597 minute gap is unknown.
    assert netmon._interval_minutes(out["unknown"]) > 590
    assert out["down"] == []


def test_one_healthy_sensor_does_not_recover_another(netmon):
    """The original bug: an OK row from sensor B ended sensor A's outage."""
    period_end = BASE + datetime.timedelta(minutes=60)
    sensors = {
        "ping:ICMP": netmon.sensor_state_intervals(
            samples((0, "CRITICAL"), (60, "CRITICAL")), BASE, period_end, 1800),
        "http:WEB": netmon.sensor_state_intervals(
            samples((0, "OK"), (30, "OK"), (60, "OK")), BASE, period_end, 1800),
    }
    rollup = netmon.device_availability(sensors, BASE, period_end)
    assert rollup["sensors"]["ping:ICMP"]["availability_pct"] == 0.0
    assert rollup["sensors"]["http:WEB"]["availability_pct"] == 100.0
    # Device is down while any sensor is down -> the whole hour is downtime.
    assert rollup["downtime_minutes"] == 60
    assert rollup["availability_pct"] == 0.0
    assert rollup["incident_count"] == 1


def test_multi_sensor_partial_outage(netmon):
    period_end = BASE + datetime.timedelta(minutes=60)
    sensors = {
        "ping:ICMP": netmon.sensor_state_intervals(
            samples((0, "OK"), (15, "CRITICAL"), (30, "OK"), (45, "OK"), (60, "OK")),
            BASE, period_end, 900),
        "port:443": netmon.sensor_state_intervals(
            samples((0, "OK"), (15, "OK"), (30, "OK"), (45, "OK"), (60, "OK")),
            BASE, period_end, 900),
    }
    rollup = netmon.device_availability(sensors, BASE, period_end)
    assert rollup["downtime_minutes"] == 15
    assert rollup["availability_pct"] == 75.0
    assert rollup["sensors"]["port:443"]["availability_pct"] == 100.0


def test_availability_modes(netmon):
    period_end = BASE + datetime.timedelta(minutes=60)
    sensors = {
        "a": netmon.sensor_state_intervals(
            samples((0, "CRITICAL"), (30, "OK"), (60, "OK")), BASE, period_end, 1800),
        "b": netmon.sensor_state_intervals(
            samples((0, "OK"), (30, "OK"), (60, "OK")), BASE, period_end, 1800),
    }
    worst = netmon.device_availability(sensors, BASE, period_end, mode="worst_sensor")
    mean = netmon.device_availability(sensors, BASE, period_end, mode="mean_sensor")
    strict = netmon.device_availability(sensors, BASE, period_end)
    assert worst["availability_pct"] == 50.0
    assert mean["availability_pct"] == 75.0
    assert strict["availability_pct"] == 50.0


def test_maintenance_is_excluded_from_availability(netmon):
    period_end = BASE + datetime.timedelta(minutes=60)
    sensors = {
        "a": netmon.sensor_state_intervals(
            samples((0, "CRITICAL"), (30, "OK"), (60, "OK")), BASE, period_end, 1800),
    }
    window = [(BASE, BASE + datetime.timedelta(minutes=30))]
    rollup = netmon.device_availability(sensors, BASE, period_end,
                                        maintenance=window)
    assert rollup["downtime_minutes"] == 0
    assert rollup["maintenance_minutes"] == 30
    assert rollup["availability_pct"] == 100.0


def test_mttr_is_the_mean_outage_length(netmon):
    period_end = BASE + datetime.timedelta(minutes=120)
    sensors = {
        "a": netmon.sensor_state_intervals(
            samples((0, "OK"), (10, "CRITICAL"), (20, "OK"), (60, "CRITICAL"),
                    (90, "OK"), (120, "OK")),
            BASE, period_end, 1800),
    }
    rollup = netmon.device_availability(sensors, BASE, period_end)
    assert rollup["incident_count"] == 2
    assert rollup["mttr_minutes"] == 20.0  # (10 + 30) / 2


def test_report_end_to_end_with_two_sensors(netmon):
    cfg = netmon.load_config()
    cfg["check_interval_seconds"] = 1800
    cfg["devices"] = [{"name": "dev1", "host": "10.0.0.1", "group": "Core",
                       "checks": [{"type": "ping", "label": "ICMP"},
                                  {"type": "http", "label": "WEB"}]}]
    netmon.save_config(cfg)
    netmon._reload_config()

    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    conn = sqlite3.connect(str(netmon.DB_PATH))
    rows = []
    for minutes_ago, icmp, web in ((60, "CRITICAL", "OK"), (30, "CRITICAL", "OK"),
                                   (0, "OK", "OK")):
        stamp = (now - datetime.timedelta(minutes=minutes_ago)).isoformat()
        rows.append((stamp, "dev1", "10.0.0.1", "ping", "ICMP", icmp, 1.0, ""))
        rows.append((stamp, "dev1", "10.0.0.1", "http", "WEB", web, 1.0, ""))
    conn.executemany(
        "INSERT INTO check_results (timestamp, device_name, host, check_type,"
        " check_label, status, response_ms, message)"
        " VALUES (?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()

    report = netmon.generate_sla_report(hours=2)[0]
    assert report["sensor_count"] == 2
    assert report["availability_mode"] == "any_sensor_down"
    # 60 minutes of ICMP downtime, not cancelled by the healthy WEB sensor.
    assert 55 <= report["downtime_minutes"] <= 65
    assert report["sensors"]["http:WEB"]["availability_pct"] == 100.0
    assert report["uptime_pct"] is not None and report["uptime_pct"] < 100
    csv_text = netmon.generate_sla_csv([report])
    assert "Availability Mode" in csv_text
