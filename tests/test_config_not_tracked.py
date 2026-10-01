"""Real config files must never be tracked in git (they hold passwords/keys)."""
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _git(*args):
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True,
                          text=True, encoding="utf-8")


@pytest.fixture(scope="module")
def tracked():
    r = _git("ls-files")
    if r.returncode != 0:
        pytest.skip("not a git checkout")
    return set(r.stdout.splitlines())


@pytest.mark.parametrize("name", ["config.yaml", "stripe_config.yaml"])
def test_real_config_untracked_and_ignored(tracked, name):
    assert name not in tracked
    assert _git("check-ignore", "-q", name).returncode == 0, name + " not gitignored"


@pytest.mark.parametrize("name", ["config.example.yaml", "stripe_config.example.yaml"])
def test_templates_tracked(tracked, name):
    assert name in tracked


def test_fresh_install_gets_template(tmp_path, monkeypatch):
    import importlib, sys
    monkeypatch.setenv("NETMON_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NETMON_CONFIG", str(tmp_path / "config.yaml"))
    monkeypatch.setenv("NETMON_DB_PATH", str(tmp_path / "netmon.db"))
    monkeypatch.setenv("NETMON_BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("NETMON_SECRET_FILE", str(tmp_path / "auth_secret.key"))
    sys.modules.pop("netmon", None)
    netmon = importlib.import_module("netmon")
    try:
        cfg = tmp_path / "config.yaml"
        assert cfg.exists()
        assert cfg.read_text(encoding="utf-8") == \
            (REPO / "config.example.yaml").read_text(encoding="utf-8")
    finally:
        sys.modules.pop("netmon", None)
