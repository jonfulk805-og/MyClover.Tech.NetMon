"""License keys: Ed25519, no signing secret in the public source.

Regression for the Repo Watch finding: the shared license secret was
hard-coded in netmon.py and stripe_handler.py, so anyone reading the public
repo could mint Pro/Enterprise keys.
"""
import hashlib
import importlib
import subprocess
import sys
from pathlib import Path

import pytest

import license_signing as ls

REPO_ROOT = Path(__file__).resolve().parent.parent
LEAKED_SECRET = b"clovertech-netmon-2026-salt"


def _old_scheme_key(tier, uid, secret=LEAKED_SECRET):
    payload = "%s-%s" % (tier, uid)
    sig = hashlib.sha256(secret + payload.encode("utf-8")).hexdigest()[:16]
    return "%s-%s" % (payload, sig.upper())


@pytest.fixture()
def keypair(tmp_path, monkeypatch):
    key_file = tmp_path / "signing.pem"
    priv = ls.create_key_pair(key_file)
    monkeypatch.setenv("NETMON_LICENSE_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.delenv("NETMON_LICENSE_SIGNING_KEY", raising=False)
    return priv, ls.public_key_b64(priv)


@pytest.fixture()
def licensed_netmon(netmon, keypair, monkeypatch):
    monkeypatch.setattr(netmon, "_LICENSE_PUBLIC_KEY_B64", keypair[1])
    return netmon


def _sign(priv, tier, uid="CAFE0001"):
    return ls.generate_license_key(tier, uid, private_key=priv, check_embedded=False)


def test_no_license_secret_in_any_tracked_python_file():
    files = subprocess.run(["git", "ls-files", "*.py"], cwd=str(REPO_ROOT),
                           capture_output=True, text=True, check=True).stdout.split()
    for name in files:
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        if name.startswith("tests/"):
            continue
        assert LEAKED_SECRET.decode() not in text, name
        assert "LICENSE_SECRET" not in text, name


def test_no_private_keys_tracked():
    files = subprocess.run(["git", "ls-files"], cwd=str(REPO_ROOT),
                           capture_output=True, text=True, check=True).stdout.split()
    bad = [f for f in files if f.endswith((".pem", ".key")) or "auth_secret" in f]
    assert bad == []


def test_round_trip_both_tiers(licensed_netmon, keypair):
    priv, _ = keypair
    assert licensed_netmon.validate_license_key(_sign(priv, "PRO")) == licensed_netmon.TIER_PRO
    assert licensed_netmon.validate_license_key(_sign(priv, "ENT")) == licensed_netmon.TIER_ENT


def test_lowercase_and_whitespace_still_validate(licensed_netmon, keypair):
    key = _sign(keypair[0], "PRO")
    assert licensed_netmon.validate_license_key("  %s \n" % key.lower()) == licensed_netmon.TIER_PRO


def test_keys_minted_with_the_leaked_secret_are_rejected(licensed_netmon):
    for tier in ("PRO", "ENT"):
        assert licensed_netmon.validate_license_key(_old_scheme_key(tier, "DEADBEEF")) is None


def test_tier_upgrade_by_editing_key_is_rejected(licensed_netmon, keypair):
    key = _sign(keypair[0], "PRO")
    assert licensed_netmon.validate_license_key("ENT" + key[3:]) is None


def test_id_tamper_is_rejected(licensed_netmon, keypair):
    tier, uid, sig = _sign(keypair[0], "ENT").split("-")
    assert licensed_netmon.validate_license_key("%s-%s-%s" % (tier, "CAFE0002", sig)) is None


def test_key_from_another_signing_key_is_rejected(licensed_netmon, tmp_path):
    other = ls.create_key_pair(tmp_path / "other.pem")
    assert licensed_netmon.validate_license_key(_sign(other, "ENT")) is None


@pytest.mark.parametrize("junk", ["", "PRO", "PRO-CAFE0001", "PRO-CAFE0001-!!!!",
                                  "PRO-ZZZZ-AAAA", "FREE-CAFE0001-AAAA", None, 42])
def test_garbage_is_rejected(licensed_netmon, junk):
    assert licensed_netmon.validate_license_key(junk) is None


def test_no_public_key_means_no_paid_tier(netmon, keypair, monkeypatch):
    monkeypatch.setattr(netmon, "_LICENSE_PUBLIC_KEY_B64", "")
    assert netmon.validate_license_key(_sign(keypair[0], "ENT")) is None


def test_shipped_public_key_is_well_formed(netmon):
    pub = netmon._LICENSE_PUBLIC_KEY_B64
    assert pub == "" or len(__import__("base64").b64decode(pub)) == 32


def test_activate_via_api(licensed_netmon, keypair, client):
    key = _sign(keypair[0], "ENT")
    assert client.post("/api/license", json={"license_key": "PRO-CAFE0001-AAAA"}).status_code == 400
    r = client.post("/api/license", json={"license_key": key})
    assert r.status_code == 200
    assert licensed_netmon.get_tier() == licensed_netmon.TIER_ENT


def test_signer_refuses_mismatched_embedded_key(keypair, tmp_path, monkeypatch):
    fake_netmon = tmp_path / "netmon.py"
    fake_netmon.write_text('_LICENSE_PUBLIC_KEY_B64 = "%s"\n'
                           % ls.public_key_b64(ls.create_key_pair(tmp_path / "x.pem")),
                           encoding="utf-8")
    monkeypatch.setattr(ls, "NETMON_PY", fake_netmon)
    with pytest.raises(ls.LicenseSigningError):
        ls.generate_license_key("PRO")


def test_signer_accepts_matching_embedded_key(keypair, tmp_path, monkeypatch):
    fake_netmon = tmp_path / "netmon.py"
    fake_netmon.write_text('_LICENSE_PUBLIC_KEY_B64 = ""\n', encoding="utf-8")
    ls.write_embedded_public_key(keypair[1], fake_netmon)
    monkeypatch.setattr(ls, "NETMON_PY", fake_netmon)
    assert ls.embedded_public_key_b64() == keypair[1]
    assert ls.verify_license_key(ls.generate_license_key("ENT"), keypair[1]) == "ENT"


def test_signing_key_from_env_pem_and_seed(keypair, monkeypatch):
    priv, pub = keypair
    monkeypatch.delenv("NETMON_LICENSE_SIGNING_KEY_FILE")
    monkeypatch.setenv("NETMON_LICENSE_SIGNING_KEY", ls.private_key_pem(priv).decode())
    assert ls.public_key_b64(ls.load_private_key()) == pub
    from cryptography.hazmat.primitives import serialization
    seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption())
    monkeypatch.setenv("NETMON_LICENSE_SIGNING_KEY", __import__("base64").b64encode(seed).decode())
    assert ls.public_key_b64(ls.load_private_key()) == pub


def test_missing_signing_key_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("NETMON_LICENSE_SIGNING_KEY", raising=False)
    monkeypatch.setenv("NETMON_LICENSE_SIGNING_KEY_FILE", str(tmp_path / "nope.pem"))
    with pytest.raises(ls.LicenseSigningError):
        ls.load_private_key()


def test_init_refuses_to_overwrite(tmp_path):
    f = tmp_path / "k.pem"
    ls.create_key_pair(f)
    with pytest.raises(ls.LicenseSigningError):
        ls.create_key_pair(f)
    ls.create_key_pair(f, force=True)


def _stripe_handler(monkeypatch, tmp_path):
    flask = pytest.importorskip("flask")  # noqa: F841
    monkeypatch.chdir(tmp_path)
    sys.modules.pop("stripe_handler", None)
    mod = importlib.import_module("stripe_handler")
    monkeypatch.setattr(mod, "STRIPE_DB", tmp_path / "orders.db")
    mod.init_stripe_db()
    return mod


def test_webhook_returns_500_without_signing_key(monkeypatch, tmp_path):
    monkeypatch.delenv("NETMON_LICENSE_SIGNING_KEY", raising=False)
    monkeypatch.setenv("NETMON_LICENSE_SIGNING_KEY_FILE", str(tmp_path / "missing.pem"))
    mod = _stripe_handler(monkeypatch, tmp_path)
    mod._config["stripe_webhook_secret"] = ""
    sent = []
    monkeypatch.setattr(mod, "send_license_email", lambda *a, **k: sent.append(a) or True)
    app = mod.create_stripe_app()
    event = {"type": "checkout.session.completed",
             "data": {"object": {"id": "cs_test_1", "customer_email": "a@b.c",
                                 "metadata": {"tier": "pro"}}}}
    r = app.test_client().post("/webhook/stripe", json=event)
    assert r.status_code == 500
    assert sent == []


def test_webhook_issues_verifiable_key(monkeypatch, tmp_path, keypair):
    mod = _stripe_handler(monkeypatch, tmp_path)
    monkeypatch.setattr(ls, "NETMON_PY", tmp_path / "absent_netmon.py")
    mod._config["stripe_webhook_secret"] = ""
    sent = []
    monkeypatch.setattr(mod, "send_license_email",
                        lambda email, tier, key, *a, **k: sent.append(key) or True)
    app = mod.create_stripe_app()
    event = {"type": "checkout.session.completed",
             "data": {"object": {"id": "cs_test_2", "customer_email": "a@b.c",
                                 "metadata": {"tier": "enterprise"}}}}
    r = app.test_client().post("/webhook/stripe", json=event)
    assert r.status_code == 200
    assert len(sent) == 1
    assert ls.verify_license_key(sent[0], keypair[1]) == "ENT"
