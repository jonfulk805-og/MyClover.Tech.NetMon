"""Free first-run /24 scan and CSV import: the limits live on the server.

The dashboard only *shows* the free scan; everything that makes it "one time,
one private /24, at most 10 devices" is enforced by the API and pinned here.
"""
import time

import pytest


def _fake_scan_factory(netmon, hosts):
    """Replace run_scan with one that 'finds' the given hosts instantly."""
    def fake_run_scan(target, *args, scan_id=None, auto_inventory=True, **kw):
        conn = netmon.sqlite3.connect(str(netmon.DB_PATH))
        for i, ip in enumerate(hosts):
            conn.execute(
                "INSERT INTO scan_results (scan_id,timestamp,ip,hostname,is_alive,"
                "open_ports,response_ms,added_to_devices) VALUES (?,?,?,?,?,?,?,0)",
                (scan_id, "2026-10-02T00:00:00", ip, "host%d.lan" % i if i % 2 else "",
                 1, "22,80", 1.5))
        conn.commit()
        conn.close()
    return fake_run_scan


def _wait_results(client, n, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        d = client.get("/api/first-scan").get_json()
        if len(d["results"]) >= n:
            return d
        time.sleep(0.05)
    raise AssertionError("scan results never appeared")


@pytest.fixture()
def scan_hosts():
    return ["192.168.50.%d" % i for i in range(1, 16)]  # 15 live hosts


@pytest.fixture()
def fake_scan(netmon, monkeypatch, scan_hosts):
    monkeypatch.setattr(netmon, "run_scan", _fake_scan_factory(netmon, scan_hosts))
    return scan_hosts


def test_first_scan_available_on_free_tier(client, netmon):
    assert netmon.get_tier() == netmon.TIER_FREE
    d = client.get("/api/first-scan").get_json()
    assert d["available"] is True
    assert d["import_cap"] == 10


def test_regular_discovery_still_pro_only(client):
    resp = client.post("/api/scan", json={"range": "192.168.50.0/24"})
    assert resp.status_code == 403


@pytest.mark.parametrize("rng,why", [
    ("192.168.0.0/23", "/24"),
    ("8.8.8.0/24", "private"),
    ("127.0.0.0/24", "private"),
    ("not-a-range", "CIDR"),
    ("fd00::/120", "IPv4"),
])
def test_first_scan_rejects_bad_ranges(client, fake_scan, rng, why):
    resp = client.post("/api/first-scan", json={"range": rng})
    assert resp.status_code == 400
    assert why in resp.get_json()["message"]
    # a rejected request must not burn the one free scan
    assert client.get("/api/first-scan").get_json()["available"] is True


def test_first_scan_is_one_time(client, netmon, fake_scan):
    resp = client.post("/api/first-scan", json={"range": "192.168.50.0/24"})
    assert resp.status_code == 202
    _wait_results(client, len(fake_scan))
    again = client.post("/api/first-scan", json={"range": "192.168.51.0/24"})
    assert again.status_code == 409
    # survives a reload of config (it is persisted, not just in memory)
    netmon._reload_config()
    assert client.get("/api/first-scan").get_json()["available"] is False


def test_bare_ip_becomes_its_slash24(client, fake_scan):
    resp = client.post("/api/first-scan", json={"range": "192.168.50.77"})
    assert resp.status_code == 202
    assert resp.get_json()["target"] == "192.168.50.0/24"


def test_first_scan_import_capped_at_ten(client, netmon, fake_scan):
    client.post("/api/first-scan", json={"range": "192.168.50.0/24"})
    _wait_results(client, len(fake_scan))
    resp = client.post("/api/first-scan/import", json={"ips": fake_scan})
    body = resp.get_json()
    assert len(body["added"]) == 10
    assert body["limit_reached"] is True
    assert len(netmon.load_config()["devices"]) == 10
    # nothing more can come in through the free scan
    more = client.post("/api/first-scan/import", json={"ips": fake_scan[10:]}).get_json()
    assert more["added"] == []


def test_first_scan_import_cap_survives_deleting_devices(client, netmon, fake_scan):
    """Delete-and-reimport must not turn the free scan into unlimited discovery."""
    client.post("/api/first-scan", json={"range": "192.168.50.0/24"})
    _wait_results(client, len(fake_scan))
    client.post("/api/first-scan/import", json={"ips": fake_scan[:10]})
    for d in list(netmon.load_config()["devices"]):
        client.delete("/api/devices/%s" % d["name"])
    again = client.post("/api/first-scan/import", json={"ips": fake_scan[10:]}).get_json()
    assert again["added"] == []


def test_first_scan_import_only_accepts_scanned_ips(client, netmon, fake_scan):
    client.post("/api/first-scan", json={"range": "192.168.50.0/24"})
    _wait_results(client, len(fake_scan))
    resp = client.post("/api/first-scan/import",
                       json={"ips": ["10.9.9.9", fake_scan[0]]}).get_json()
    assert len(resp["added"]) == 1
    hosts = [d["host"] for d in netmon.load_config()["devices"]]
    assert hosts == [fake_scan[0]]


def test_first_scan_import_respects_existing_device_limit(client, netmon, fake_scan):
    for i in range(7):
        client.post("/api/devices", json={"name": "d%d" % i, "host": "10.0.0.%d" % i})
    assert client.get("/api/first-scan").get_json()["import_cap"] == 3
    client.post("/api/first-scan", json={"range": "192.168.50.0/24"})
    _wait_results(client, len(fake_scan))
    resp = client.post("/api/first-scan/import", json={"ips": fake_scan}).get_json()
    assert len(resp["added"]) == 3
    assert len(netmon.load_config()["devices"]) == 10


CSV = """name,host,group,check,port,url
Core Router,192.168.1.1,Network,ping,,
NAS,192.168.1.20,Storage,tcp,445,
Web,192.168.1.30,,http,,http://192.168.1.30:8080/
,192.168.1.40,,,,
Bad,192.168.1.50,,smtp,,
"""


def test_csv_import_parses_columns(client, netmon):
    resp = client.post("/api/devices/import", json={"csv": CSV}).get_json()
    assert resp["added"] == ["Core Router", "NAS", "Web", "192.168.1.40"]
    assert any("unknown check" in e for e in resp["errors"])
    devs = {d["name"]: d for d in netmon.load_config()["devices"]}
    assert devs["NAS"]["checks"][0] == {"type": "tcp", "label": "TCP 445", "port": 445}
    assert devs["Web"]["checks"][0]["url"] == "http://192.168.1.30:8080/"
    assert devs["192.168.1.40"]["group"] == "Default"


def test_csv_import_enforces_free_device_limit(client, netmon):
    rows = "host\n" + "\n".join("10.1.0.%d" % i for i in range(1, 15))
    resp = client.post("/api/devices/import", json={"csv": rows}).get_json()
    assert len(resp["added"]) == 10
    assert resp["limit_reached"] is True
    assert len(netmon.load_config()["devices"]) == 10


def test_csv_import_skips_duplicates(client, netmon):
    client.post("/api/devices", json={"name": "Router", "host": "192.168.1.1"})
    resp = client.post("/api/devices/import", json={"csv": CSV}).get_json()
    assert "Core Router" not in resp["added"]
    assert {"name": "Core Router", "reason": "already monitored"} in resp["skipped"]


def test_csv_import_needs_host_column(client):
    resp = client.post("/api/devices/import", json={"csv": "name,ip\nA,1.2.3.4\n"})
    assert resp.status_code == 400


def test_static_logo_served_without_login(client, netmon):
    from tests.test_authz import enable_auth
    enable_auth(netmon, [("admin", "pw-123456789", "admin")])
    assert client.get("/static/img/myclover_logo.png").status_code == 200
    assert client.get("/api/first-scan").status_code == 401


def test_viewer_cannot_start_free_scan(client, netmon, fake_scan):
    from tests.test_authz import enable_auth, login, auth
    enable_auth(netmon, [("admin", "pw-123456789", "admin"),
                         ("view", "pw-123456789", "viewer")])
    tok = login(client, "view", "pw-123456789")
    resp = client.post("/api/first-scan", json={"range": "192.168.50.0/24"},
                       headers=auth(tok))
    assert resp.status_code == 403


def test_link_local_range_rejected(client, fake_scan):
    resp = client.post("/api/first-scan", json={"range": "169.254.0.0/24"})
    assert resp.status_code == 400
