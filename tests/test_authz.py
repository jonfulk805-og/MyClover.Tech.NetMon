"""Authorization, secret handling and password storage."""
import re

import pytest


def enable_auth(netmon, users):
    cfg = netmon.load_config()
    cfg["users"] = [
        {"username": u, "password_hash": netmon.hash_password(p), "role": r}
        for u, p, r in users
    ]
    cfg["auth_enabled"] = True
    netmon.save_config(cfg)
    netmon._reload_config()


def login(client, username, password):
    resp = client.post("/api/auth/login",
                       json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["token"]


def auth(token):
    return {"Authorization": "Bearer %s" % token}


# --- secrets ---------------------------------------------------------------

def test_secret_is_generated_per_installation(netmon, data_dir):
    assert (data_dir / "auth_secret.key").exists()
    assert len(netmon._AUTH_SECRET) >= 32
    assert b"netmon-auth-secret" not in netmon._AUTH_SECRET


def test_no_hardcoded_secret_left_in_source():
    src = open(netmon_path(), encoding="utf-8").read()
    assert 'b"netmon-auth-secret-2026"' not in src


def netmon_path():
    from pathlib import Path
    return Path(__file__).resolve().parent.parent / "netmon.py"


# --- password storage ------------------------------------------------------

def test_hash_and_verify(netmon):
    stored = netmon.hash_password("correct horse battery")
    assert stored.startswith("pbkdf2_sha256$")
    assert "correct horse battery" not in stored
    assert netmon.verify_password("correct horse battery", stored)
    assert not netmon.verify_password("wrong", stored)


def test_plaintext_is_never_accepted_as_a_hash(netmon):
    assert not netmon.verify_password("changeme", "changeme")


def test_plaintext_config_is_migrated(netmon, data_dir):
    cfg = netmon.load_config()
    cfg["users"] = [{"username": "admin", "password": "changeme", "role": "admin"}]
    netmon.save_config(cfg)
    netmon._reload_config()
    on_disk = (data_dir / "config.yaml").read_text(encoding="utf-8")
    assert "changeme" not in on_disk
    assert "pbkdf2_sha256" in on_disk
    user = netmon._find_user("admin")
    assert netmon.verify_password("changeme", user["password_hash"])


def test_created_users_are_stored_hashed(client, netmon, data_dir):
    resp = client.post("/api/users", json={"username": "op",
                                           "password": "hunter2hunter2",
                                           "role": "operator"})
    assert resp.status_code == 200
    assert "hunter2hunter2" not in (data_dir / "config.yaml").read_text(encoding="utf-8")


def test_weak_password_and_bad_username_rejected(client):
    assert client.post("/api/users", json={"username": "x", "password": "short",
                                           "role": "viewer"}).status_code == 400
    assert client.post("/api/users", json={"username": "bad name",
                                           "password": "longenough1",
                                           "role": "viewer"}).status_code == 400


# --- token binding ---------------------------------------------------------

def test_token_is_invalidated_when_user_is_removed(client, netmon):
    enable_auth(netmon, [("admin", "adminpassword", "admin"),
                         ("op", "operatorpass", "operator")])
    token = login(client, "op", "operatorpass")
    admin_token = login(client, "admin", "adminpassword")
    assert client.get("/api/devices", headers=auth(token)).status_code == 200
    assert client.delete("/api/users/op",
                         headers=auth(admin_token)).status_code == 200
    netmon._reload_config()
    assert client.get("/api/devices", headers=auth(token)).status_code == 401


def test_token_is_invalidated_when_role_changes(client, netmon):
    enable_auth(netmon, [("admin", "adminpassword", "admin"),
                         ("op", "operatorpass", "operator")])
    op_token = login(client, "op", "operatorpass")
    admin_token = login(client, "admin", "adminpassword")
    assert client.get("/api/devices", headers=auth(op_token)).status_code == 200
    client.put("/api/users/op", json={"role": "viewer"}, headers=auth(admin_token))
    netmon._reload_config()
    assert client.get("/api/devices", headers=auth(op_token)).status_code == 401


def test_token_is_invalidated_when_password_changes(client, netmon):
    enable_auth(netmon, [("admin", "adminpassword", "admin")])
    token = login(client, "admin", "adminpassword")
    client.put("/api/users/admin", json={"password": "brandnewpassword"},
               headers=auth(token))
    netmon._reload_config()
    assert client.get("/api/devices", headers=auth(token)).status_code == 401


def test_forged_token_with_the_old_public_secret_is_rejected(client, netmon):
    import base64
    import hashlib
    import hmac
    import time
    enable_auth(netmon, [("admin", "adminpassword", "admin")])
    payload = "admin:admin:%d:deadbeefcafe" % (int(time.time()) + 3600)
    sig = hmac.new(b"netmon-auth-secret-2026", payload.encode(),
                   hashlib.sha256).hexdigest()[:32]
    forged = base64.urlsafe_b64encode(("%s:%s" % (payload, sig)).encode()).decode()
    assert client.get("/api/devices", headers=auth(forged)).status_code == 401


# --- route coverage --------------------------------------------------------

PROTECTED_READS = ["/api/devices", "/api/status", "/api/settings", "/api/users",
                   "/api/license"]


@pytest.mark.parametrize("path", PROTECTED_READS)
def test_protected_routes_require_a_token(client, netmon, path):
    enable_auth(netmon, [("admin", "adminpassword", "admin")])
    assert client.get(path).status_code == 401


def test_every_api_route_is_gated_or_explicitly_exempt(netmon):
    """No route may be reachable unauthenticated unless it is on the allowlist."""
    app = netmon.create_app()
    ungated = []
    for rule in app.url_map.iter_rules():
        endpoint = rule.endpoint
        if endpoint in netmon._AUTH_EXEMPT_ENDPOINTS:
            continue
        perm = netmon._required_perm_for(endpoint, "GET")
        if perm not in ("read", "write", "config", "users"):
            ungated.append(endpoint)
    assert not ungated, "routes without a permission: %s" % ungated


def test_viewer_cannot_write_or_configure(client, netmon):
    enable_auth(netmon, [("v", "viewerpassword", "viewer")])
    token = login(client, "v", "viewerpassword")
    assert client.get("/api/status", headers=auth(token)).status_code == 200
    assert client.post("/api/devices", json={"name": "x", "host": "1.1.1.1"},
                       headers=auth(token)).status_code == 403
    assert client.get("/api/settings", headers=auth(token)).status_code == 403
    assert client.get("/api/users", headers=auth(token)).status_code == 403


def test_operator_cannot_change_settings_or_users(client, netmon):
    enable_auth(netmon, [("op", "operatorpass", "operator")])
    token = login(client, "op", "operatorpass")
    assert client.put("/api/settings", json={"auth_enabled": False},
                      headers=auth(token)).status_code == 403
    assert client.post("/api/users", json={"username": "z", "password": "zzzzzzzz",
                                           "role": "admin"},
                       headers=auth(token)).status_code == 403


def test_auth_cannot_be_disabled_without_admin_rights(client, netmon):
    enable_auth(netmon, [("v", "viewerpassword", "viewer")])
    token = login(client, "v", "viewerpassword")
    resp = client.put("/api/settings", json={"auth_enabled": False},
                      headers=auth(token))
    assert resp.status_code == 403
    netmon._reload_config()
    assert netmon._config["auth_enabled"] is True


def test_enabling_auth_without_an_admin_user_is_refused(client, netmon):
    resp = client.put("/api/settings", json={"auth_enabled": True})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "no_admin_user"


# --- SMTP password ---------------------------------------------------------

def test_settings_never_returns_the_smtp_password(client):
    body = client.get("/api/settings").get_json()
    assert body["smtp_password"] == ""
    assert body["smtp_password_set"] is True
    assert "supersecret" not in str(body)


def test_blank_smtp_password_keeps_the_existing_one(client, netmon):
    client.put("/api/settings", json={"smtp_password": "", "smtp_host": "new.host"})
    netmon._reload_config()
    assert netmon._config["smtp"]["password"] == "supersecret"
    assert netmon._config["smtp"]["smtp_host"] == "new.host"


def test_new_smtp_password_replaces_it(client, netmon):
    client.put("/api/settings", json={"smtp_password": "rotated"})
    netmon._reload_config()
    assert netmon._config["smtp"]["password"] == "rotated"


def test_login_sets_an_httponly_cookie(client, netmon):
    enable_auth(netmon, [("admin", "adminpassword", "admin")])
    resp = client.post("/api/auth/login",
                       json={"username": "admin", "password": "adminpassword"})
    cookie = resp.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert re.search(r"netmon_token=", cookie)


def test_last_admin_cannot_be_deleted_while_auth_is_on(client, netmon):
    enable_auth(netmon, [("admin", "adminpassword", "admin")])
    token = login(client, "admin", "adminpassword")
    resp = client.delete("/api/users/admin", headers=auth(token))
    assert resp.status_code == 409


def test_auth_on_with_no_users_fails_closed(client, netmon):
    cfg = netmon.load_config()
    cfg["auth_enabled"] = True
    cfg["users"] = []
    netmon.save_config(cfg)
    netmon._reload_config()
    assert client.get("/api/devices").status_code == 401
