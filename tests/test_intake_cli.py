"""Tests for the intake CLI — create + validate, exercising the status gate."""

import re

from typer.testing import CliRunner

from scan_toolkit.config import get_settings
from scan_toolkit.main import app

runner = CliRunner()

_ID_RE = re.compile(r"[a-f0-9]{12}")


def _isolated_data(monkeypatch, tmp_path):
    """Point settings at a temp data dir (DB + artifacts) for the whole test."""
    monkeypatch.setenv("SCAN_TOOLKIT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("SCAN_TOOLKIT_DB_URL", raising=False)
    get_settings.cache_clear()
    return tmp_path


def _make_apk(tmp_path):
    p = tmp_path / "sample.apk"
    p.write_bytes(b"fake apk bytes")
    return str(p)


def _make_creds(tmp_path):
    p = tmp_path / "creds.json"
    p.write_text('{"user": "tester", "pass": "s3cr3t"}')
    return str(p)


def _extract_id(output: str) -> str:
    return _ID_RE.search(output).group(0)


def test_intake_create_stores_binary(monkeypatch, tmp_path):
    tmp = _isolated_data(monkeypatch, tmp_path)
    apk = _make_apk(tmp)
    result = runner.invoke(app, [
        "intake", "create",
        "--client", "Acme Mobile",
        "--platform", "android",
        "--confirm-scope",
        "--binary", apk,
    ])
    assert result.exit_code == 0, result.output
    assert "Created engagement" in result.output
    assert "Intake complete" in result.output

    eng_id = _extract_id(result.output)
    # binary copied into the per-engagement folder (not just referenced)
    stored = tmp / "data" / "engagements" / eng_id / "binary" / "sample.apk"
    assert stored.exists()
    assert stored.read_bytes() == b"fake apk bytes"
    # manifest snapshot written for reproducibility
    assert (tmp / "data" / "engagements" / eng_id / "intake.json").exists()


def test_intake_validate_blocked_without_credentials(monkeypatch, tmp_path):
    """User's example: API in scope but no test credentials -> validate blocks."""
    tmp = _isolated_data(monkeypatch, tmp_path)
    apk = _make_apk(tmp)
    result = runner.invoke(app, [
        "intake", "create",
        "--client", "Acme Mobile",
        "--platform", "android",
        "--confirm-scope",
        "--binary", apk,
        "--api-in-scope",
    ])
    assert result.exit_code == 0, result.output
    eng_id = _extract_id(result.output)

    result = runner.invoke(app, ["intake", "validate", eng_id])
    assert result.exit_code == 1, result.output  # blocked
    assert "blocked" in result.output.lower()
    assert "API/backend testing is in scope but no test credentials" in result.output
    # status unchanged
    assert "advanced to 'scanning'" not in result.output


def test_intake_validate_passes_and_advances(monkeypatch, tmp_path):
    tmp = _isolated_data(monkeypatch, tmp_path)
    apk = _make_apk(tmp)
    creds = _make_creds(tmp)
    docs = tmp / "openapi.yaml"
    docs.write_text("openapi: 3.0.0")
    result = runner.invoke(app, [
        "intake", "create",
        "--client", "Acme Mobile",
        "--platform", "android",
        "--confirm-scope",
        "--binary", apk,
        "--credentials", creds,
        "--api-in-scope",
        "--api-docs", str(docs),
        "--network-constraints", "sandboxed LAN only",
    ])
    assert result.exit_code == 0, result.output
    eng_id = _extract_id(result.output)

    result = runner.invoke(app, ["intake", "validate", eng_id])
    assert result.exit_code == 0, result.output
    assert f"advanced to 'scanning'" in result.output


def test_intake_create_bad_platform_rejected(monkeypatch, tmp_path):
    _isolated_data(monkeypatch, tmp_path)
    result = runner.invoke(app, [
        "intake", "create",
        "--client", "Acme",
        "--platform", "blackberry",
    ])
    assert result.exit_code != 0
    assert "android" in result.output.lower() or "ios" in result.output.lower()


def test_intake_create_missing_binary_path_blocked(monkeypatch, tmp_path):
    tmp = _isolated_data(monkeypatch, tmp_path)
    result = runner.invoke(app, [
        "intake", "create",
        "--client", "Acme",
        "--platform", "android",
        "--binary", str(tmp_path / "nope.apk"),
    ])
    assert result.exit_code == 1
    assert "does not exist" in result.output