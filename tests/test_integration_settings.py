"""The SentryLog read token can be managed from the Settings page."""


def test_generate_returns_token_once_and_enables_the_feed(netmon, client):
    assert client.get("/api/settings").get_json()["integration_read_token_set"] is False
    body = client.post("/api/settings/integration-token",
                       json={"action": "generate"}).get_json()
    token = body["read_token"]
    assert len(token) >= 32
    assert netmon._config["integration"]["read_token"] == token
    settings = client.get("/api/settings").get_json()
    assert settings["integration_read_token_set"] is True
    assert token not in str(settings)
    # SentryLog can now read the feed with the token.
    resp = client.get("/api/integration/events",
                      headers={"X-Netmon-Integration-Token": token})
    assert resp.status_code == 200


def test_regenerate_replaces_the_token(netmon, client):
    first = client.post("/api/settings/integration-token",
                        json={"action": "generate"}).get_json()["read_token"]
    second = client.post("/api/settings/integration-token",
                         json={"action": "generate"}).get_json()["read_token"]
    assert first != second
    assert netmon._config["integration"]["read_token"] == second


def test_clear_disables_the_token(netmon, client):
    client.post("/api/settings/integration-token", json={"action": "generate"})
    assert client.post("/api/settings/integration-token",
                       json={"action": "clear"}).get_json() == {"ok": True}
    assert netmon._config["integration"]["read_token"] == ""
    assert client.get("/api/settings").get_json()["integration_read_token_set"] is False


def test_token_survives_a_config_reload(netmon, client):
    token = client.post("/api/settings/integration-token",
                        json={"action": "generate"}).get_json()["read_token"]
    netmon.load_config()
    assert netmon._config["integration"]["read_token"] == token


def test_unknown_action_is_rejected(client):
    assert client.post("/api/settings/integration-token",
                       json={"action": "show"}).status_code == 400


def test_token_endpoint_requires_config_permission(netmon):
    assert netmon._required_perm_for("api_settings_integration_token", "POST") == "config"
