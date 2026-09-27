"""Tests for scan_toolkit.config — defaults, env override, DB_URL derivation."""

from scan_toolkit.config import get_settings


def test_defaults_load():
    s = get_settings()
    assert s.data_dir is not None
    assert "sqlite+pysqlite" in s.db_url
    assert s.max_concurrent_dynamic_jobs == 2


def test_db_url_derived_when_empty(monkeypatch):
    monkeypatch.delenv("SCAN_TOOLKIT_DB_URL", raising=False)
    get_settings.cache_clear()
    s = get_settings()
    assert "toolkit.db" in s.db_url


def test_env_override(monkeypatch):
    monkeypatch.setenv("SCAN_TOOLKIT_DB_URL", "sqlite+pysqlite:///tmp/custom.db")
    get_settings.cache_clear()
    s = get_settings()
    assert s.db_url == "sqlite+pysqlite:///tmp/custom.db"
    get_settings.cache_clear()  # restore


def test_prefixed_var_wins(monkeypatch):
    """Unprefixed DATA_DIR (app namespace) should NOT populate the toolkit's data_dir."""
    monkeypatch.setenv("DATA_DIR", "/tmp/wrong-dir")
    monkeypatch.delenv("SCAN_TOOLKIT_DATA_DIR", raising=False)
    get_settings.cache_clear()
    s = get_settings()
    from scan_toolkit.config import ROOT
    assert s.data_dir == ROOT / "data"  # default, NOT /tmp/wrong-dir
    get_settings.cache_clear()