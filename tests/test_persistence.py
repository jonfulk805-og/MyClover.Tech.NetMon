"""Docker persistence contract: state must live where the volume is mounted."""
import sqlite3
from pathlib import Path

from conftest import load_netmon, DEFAULT_CONFIG


def test_env_vars_decide_paths(netmon, data_dir):
    assert netmon.DB_PATH == data_dir / "netmon.db"
    assert netmon.DEFAULT_CFG == data_dir / "config.yaml"
    assert netmon.BACKUP_DIR == data_dir / "backups"
    assert netmon.SECRET_PATH == data_dir / "auth_secret.key"
    # And nothing is written next to the source file.
    assert netmon.DB_PATH.parent != netmon.BASE_DIR


def test_database_is_created_in_the_data_dir(netmon, data_dir):
    assert (data_dir / "netmon.db").exists()
    assert not (netmon.BASE_DIR / "netmon.db").exists()


def test_config_writes_land_in_the_data_dir(netmon, data_dir):
    cfg = netmon.load_config()
    cfg["check_interval_seconds"] = 123
    netmon.save_config(cfg)
    assert "123" in (data_dir / "config.yaml").read_text(encoding="utf-8")


def test_state_survives_container_replacement(tmp_path):
    """Simulate `docker rm` + `docker run` against the same volume."""
    volume = tmp_path / "volume"
    volume.mkdir()
    (volume / "config.yaml").write_text(DEFAULT_CONFIG, encoding="utf-8")

    first = load_netmon(volume)
    first._reload_config()
    first.init_db()
    conn = sqlite3.connect(str(first.DB_PATH))
    conn.execute(
        "INSERT INTO check_results (timestamp, device_name, host, check_type,"
        " status, response_ms, message) VALUES"
        " ('2026-01-01T00:00:00', 'dev1', '10.0.0.1', 'ping', 'OK', 5, 'ok')")
    conn.commit()
    conn.close()
    cfg = first.load_config()
    cfg["devices"] = [{"name": "dev1", "host": "10.0.0.1",
                       "checks": [{"type": "ping"}]}]
    first.save_config(cfg)

    # Container replaced: brand new process, same volume.
    second = load_netmon(volume)
    second._reload_config()
    second.init_db()
    rows = sqlite3.connect(str(second.DB_PATH)).execute(
        "SELECT COUNT(*) FROM check_results").fetchone()[0]
    assert rows == 1, "check results did not survive container replacement"
    assert second.load_config()["devices"][0]["name"] == "dev1"


def test_legacy_install_is_migrated_once(tmp_path, monkeypatch):
    """A pre-volume install keeps its data when the env vars appear."""
    legacy_db = tmp_path / "legacy.db"
    # Close explicitly: Windows cannot rename a file SQLite still holds open
    # (WinError 32), and CPython does not promise the handle is freed on GC.
    conn = sqlite3.connect(str(legacy_db))
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    volume = tmp_path / "vol"
    volume.mkdir()
    (volume / "config.yaml").write_text(DEFAULT_CONFIG, encoding="utf-8")

    mod = load_netmon(volume)
    monkeypatch.setattr(mod, "BASE_DIR", tmp_path)
    monkeypatch.setattr(mod, "DB_PATH", volume / "netmon.db")
    # Pretend the legacy db sat next to the source file.
    legacy_db.rename(tmp_path / "netmon.db")
    mod.ensure_data_dir()
    assert (volume / "netmon.db").exists()
    assert (tmp_path / "netmon.db").exists(), "legacy file must be copied, not moved"


def test_backup_dir_exists(netmon, data_dir):
    assert (data_dir / "backups").is_dir()


def test_dockerfile_matches_the_code_contract():
    text = Path(__file__).resolve().parent.parent.joinpath("Dockerfile").read_text()
    assert "ENV NETMON_DATA_DIR=/app/data" in text
    assert "ENV NETMON_CONFIG=/app/data/config.yaml" in text
    assert "ENV NETMON_DB_PATH=/app/data/netmon.db" in text
    assert 'VOLUME ["/app/data"]' in text
