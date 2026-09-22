"""Test fixtures for NetMon.

netmon.py resolves its data paths at import time, so every test session gets a
fresh temporary data dir via environment variables *before* the import. That is
also exactly what the Docker image does, which makes these tests a real check of
the persistence contract.
"""
import importlib
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_netmon(data_dir):
    """Import (or re-import) netmon with NETMON_* pointing at data_dir."""
    os.environ["NETMON_DATA_DIR"] = str(data_dir)
    os.environ["NETMON_DB_PATH"] = str(Path(data_dir) / "netmon.db")
    os.environ["NETMON_CONFIG"] = str(Path(data_dir) / "config.yaml")
    os.environ["NETMON_BACKUP_DIR"] = str(Path(data_dir) / "backups")
    os.environ["NETMON_SECRET_FILE"] = str(Path(data_dir) / "auth_secret.key")
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    sys.modules.pop("netmon", None)
    return importlib.import_module("netmon")


DEFAULT_CONFIG = """\
check_interval_seconds: 60
auth_enabled: false
users: []
devices: []
smtp:
  smtp_host: smtp.example.com
  smtp_port: 587
  username: alerts@example.com
  password: supersecret
  from_addr: alerts@example.com
  recipients: []
dashboard:
  host: 127.0.0.1
  port: 8080
"""


@pytest.fixture()
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    (d / "config.yaml").write_text(DEFAULT_CONFIG, encoding="utf-8")
    return d


@pytest.fixture()
def netmon(data_dir):
    mod = load_netmon(data_dir)
    mod._reload_config()
    mod.init_db()
    return mod


@pytest.fixture()
def client(netmon):
    app = netmon.create_app()
    app.config["TESTING"] = True
    return app.test_client()
