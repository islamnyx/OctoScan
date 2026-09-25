"""Tests for Phase 11 — audit trail, logging config, status command."""

from __future__ import annotations

import logging

import pytest
from typer.testing import CliRunner

from scan_toolkit.main import app
from scan_toolkit.models import (
    AuditEvent,
    Confidence,
    Engagement,
    EngagementStatus,
    Finding,
    FindingStatus,
    Platform,
    Severity,
    SourceAgent,
)

runner = CliRunner()


@pytest.fixture()
def status_env(tmp_path, monkeypatch):
    """Isolated DATA_DIR via env (covers in-process CLI paths)."""
    from scan_toolkit.config import get_settings
    monkeypatch.setenv("SCAN_TOOLKIT_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def _seed(status_env):
    """Engagement + findings + chain + audit in the isolated DB."""
    from scan_toolkit import audit as audit_mod
    from scan_toolkit.db import init_db, session_scope
    from scan_toolkit.models import AttackChain

    engine = init_db()
    with session_scope(engine) as s:
        eng = Engagement(client_name="Acme", app_platform=Platform.android,
                         status=EngagementStatus.scanning)
        s.add(eng)
        s.flush()
        eid = eng.id
        for title, sev, src, st in [
            ("S-one", "high", SourceAgent.static, FindingStatus.new),
            ("A-one", "medium", SourceAgent.api, FindingStatus.confirmed),
        ]:
            s.add(Finding(engagement_id=eid, source_agent=src, title=title,
                          severity=Severity(sev), confidence=Confidence.high,
                          status=st, related_finding_ids=[]))
        s.flush()
        s.add(AttackChain(engagement_id=eid, finding_ids=["x", "y"],
                          narrative="Chain.", combined_severity=Severity.high))
        audit_mod.audit(s, "intake.create", engagement_id=eid,
                        details="client=Acme")
    return eid


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------

class TestAudit:
    def test_row_written(self, db_session):
        from scan_toolkit import audit as audit_mod
        event = audit_mod.audit(db_session, "run.stage",
                                engagement_id="abc123",
                                details="stage=static")
        assert event.actor  # OS login, never empty in test env
        assert event.action == "run.stage"
        rows = db_session.query(AuditEvent).all()
        assert len(rows) == 1 and rows[0].to_dict()["action"] == "run.stage"

    def test_details_truncated(self, db_session):
        from scan_toolkit import audit as audit_mod
        event = audit_mod.audit(db_session, "x", details="d" * 900)
        assert len(event.details) == 500

    def test_recent_scoped(self, db_session):
        from scan_toolkit import audit as audit_mod
        audit_mod.audit(db_session, "a", engagement_id="e1")
        audit_mod.audit(db_session, "b", engagement_id="e2")
        assert len(audit_mod.recent(db_session)) == 2
        scoped = audit_mod.recent(db_session, engagement_id="e1")
        assert len(scoped) == 1 and scoped[0].action == "a"


# ---------------------------------------------------------------------------
# Logging config
# ---------------------------------------------------------------------------

class TestLoggingConfig:
    def test_idempotent_and_file(self, tmp_path):
        from scan_toolkit import logging_config
        logging_config.reset_for_tests()
        data = tmp_path / "data"
        logging_config.configure_logging(data)
        logging_config.configure_logging(data)  # second call no-ops
        logging.getLogger("scan_toolkit.test").info("hello-log")
        assert (data / "toolkit.log").exists()
        assert "hello-log" in (data / "toolkit.log").read_text()
        logging_config.reset_for_tests()


# ---------------------------------------------------------------------------
# Status command
# ---------------------------------------------------------------------------

class TestStatusCLI:
    def test_overview_empty(self, status_env):
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "No engagements" in result.output
        assert "pending=0" in result.output

    def test_overview_with_data(self, status_env):
        eid = _seed(status_env)
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert eid in result.output
        assert "findings=2" in result.output

    def test_detail(self, status_env):
        eid = _seed(status_env)
        result = runner.invoke(app, ["status", "--engagement", eid])
        assert result.exit_code == 0
        out = result.output
        assert "Acme" in out
        assert "by severity: high=1, medium=1" in out
        assert "by agent: api=1, static=1" in out
        assert "Attack chains: 1" in out
        assert "no stages run yet" in out
        assert "intake.create" in out  # audit trail visible

    def test_unknown_engagement(self, status_env):
        result = runner.invoke(
            app, ["status", "--engagement", "deadbeef1234"])
        assert result.exit_code == 1
        assert "not found" in result.output


# ---------------------------------------------------------------------------
# Audit wiring (through real CLI paths)
# ---------------------------------------------------------------------------

class TestAuditWiring:
    def test_review_writes_audit(self, status_env):
        from scan_toolkit.db import init_db, session_scope
        eid = _seed(status_env)
        fids = []
        engine = init_db()
        with session_scope(engine) as s:
            fids = [f.id for f in s.query(Finding).all()]
        result = runner.invoke(
            app, ["review", "--engagement", eid,
                  "--confirm", fids[0], "--confirm", fids[1]])
        assert result.exit_code == 0
        with session_scope(engine) as s:
            actions = [e.action for e in
                       s.query(AuditEvent).order_by(AuditEvent.created_at).all()]
        assert "review" in actions

    def test_worker_completion_audited(self, status_env):
        from scan_toolkit.db import init_db, session_scope
        from scan_toolkit.queue import JobQueue
        eid = _seed(status_env)
        engine = init_db()
        with session_scope(engine) as s:
            queue = JobQueue(engine)
            job = queue.submit(s, engagement_id=eid, stage="dynamic")
            job_id = job.id
        result = runner.invoke(app, ["worker", "--once"])
        assert result.exit_code == 0
        with session_scope(engine) as s:
            actions = [e.action for e in s.query(AuditEvent).all()]
        assert "worker.job" in actions
