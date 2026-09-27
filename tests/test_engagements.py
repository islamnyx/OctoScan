"""Service-level tests for engagements.py + artifacts.py."""

import pytest

from scan_toolkit import artifacts, engagements
from scan_toolkit.models import (
    EngagementStatus,
    IntakeChecklist,
    Platform,
)


@pytest.fixture()
def toolkit_tmp(monkeypatch, tmp_path):
    """Point settings.data_dir at a temp path so artifacts never touch real data/."""
    from scan_toolkit.config import get_settings
    s = get_settings()
    orig = s.data_dir
    s.data_dir = tmp_path / "data"
    yield tmp_path
    s.data_dir = orig  # restore, then drop the cached instance for good measure
    get_settings.cache_clear()


def _apk(tmp_path):
    p = tmp_path / "app.apk"
    p.write_bytes(b"apk")
    return p


def _cred(tmp_path):
    p = tmp_path / "creds.json"
    p.write_text("{}")
    return p


def test_create_complete_engagement_round_trip(db_session, toolkit_tmp):
    apk = _apk(toolkit_tmp)
    creds = _cred(toolkit_tmp)
    eng = engagements.create_engagement(
        db_session,
        client_name="Acme",
        app_platform=Platform.android,
        scope_agreement_confirmed=True,
        binary_source=apk,
        credentials_source=creds,
        api_scan_in_scope=True,
    )
    db_session.flush()

    assert eng.status is EngagementStatus.intake
    checklist = db_session.get(IntakeChecklist, eng.intake.id)
    assert checklist.has_test_credentials is True
    assert checklist.binary_path and checklist.binary_filename == "app.apk"
    # file actually copied into per-engagement folder
    assert (artifacts.engagement_dir(eng.id) / "binary" / "app.apk").exists()
    assert (artifacts.engagement_dir(eng.id) / "credentials.json").exists()
    assert (artifacts.engagement_dir(eng.id) / "intake.json").exists()


def test_intake_missing_items_api_without_credentials(db_session, toolkit_tmp):
    apk = _apk(toolkit_tmp)
    eng = engagements.create_engagement(
        db_session,
        client_name="Acme",
        app_platform=Platform.android,
        scope_agreement_confirmed=True,
        binary_source=apk,
        api_scan_in_scope=True,  # no credentials provided
    )
    db_session.flush()
    missing = engagements.intake_missing_items(eng)
    assert any("no test credentials" in m for m in missing)


def test_intake_missing_items_complete(db_session, toolkit_tmp):
    apk = _apk(toolkit_tmp)
    creds = _cred(toolkit_tmp)
    eng = engagements.create_engagement(
        db_session,
        client_name="Acme",
        app_platform=Platform.android,
        scope_agreement_confirmed=True,
        binary_source=apk,
        credentials_source=creds,
        api_scan_in_scope=True,
    )
    db_session.flush()
    assert engagements.intake_missing_items(eng) == []


def test_advance_scanning_blocked_when_incomplete(db_session, toolkit_tmp):
    apk = _apk(toolkit_tmp)
    eng = engagements.create_engagement(
        db_session,
        client_name="Acme",
        app_platform=Platform.android,
        scope_agreement_confirmed=True,
        binary_source=apk,
        api_scan_in_scope=True,  # no credentials
    )
    db_session.flush()
    with pytest.raises(ValueError, match="no test credentials"):
        engagements.advance_engagement_status(db_session, eng, EngagementStatus.scanning)
    assert eng.status is EngagementStatus.intake


def test_advance_scanning_passes_when_complete(db_session, toolkit_tmp):
    eng = engagements.create_engagement(
        db_session,
        client_name="Acme",
        app_platform=Platform.android,
        scope_agreement_confirmed=True,
        binary_source=_apk(toolkit_tmp),
        credentials_source=_cred(toolkit_tmp),
        api_scan_in_scope=True,
    )
    db_session.flush()
    engagements.advance_engagement_status(db_session, eng, EngagementStatus.scanning)
    assert eng.status is EngagementStatus.scanning


def test_backward_transition_rejected(db_session, toolkit_tmp):
    eng = engagements.create_engagement(
        db_session,
        client_name="Acme",
        app_platform=Platform.android,
        scope_agreement_confirmed=True,
        binary_source=_apk(toolkit_tmp),
        credentials_source=_cred(toolkit_tmp),
        api_scan_in_scope=True,
    )
    db_session.flush()
    engagements.advance_engagement_status(db_session, eng, EngagementStatus.scanning)
    assert eng.status is EngagementStatus.scanning
    with pytest.raises(ValueError, match="backward"):
        engagements.advance_engagement_status(db_session, eng, EngagementStatus.intake)


def test_create_rejects_missing_binary(db_session, toolkit_tmp):
    with pytest.raises(ValueError, match="does not exist"):
        engagements.create_engagement(
            db_session,
            client_name="Acme",
            app_platform=Platform.android,
            binary_source=toolkit_tmp / "missing.apk",
        )


def test_engagement_id_guard():
    with pytest.raises(ValueError):
        artifacts.validate_engagement_id("../../etc")

    import tempfile
    tmp = tempfile.mkdtemp()
    r = artifacts.validate_engagement_id("abcdef012345")
    assert r == "abcdef012345"