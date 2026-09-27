"""Tests for the Phase 9 Correlation Agent — validation, dedup + chains,
readiness gate, CLI. The LLM is always mocked; no network is touched.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from scan_toolkit.agents.correlation import (
    CorrelationAgent,
    make_validator,
    stages_done,
)
from scan_toolkit.main import app
from scan_toolkit.models import (
    AttackChain,
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(db_session, eng_id, source, title, severity="medium",
             status=FindingStatus.new):
    f = Finding(
        engagement_id=eng_id,
        source_agent=source,
        category="test",
        title=title,
        description=f"{title} description",
        evidence=f"{title} evidence",
        severity=Severity(severity),
        confidence=Confidence.high,
        status=status,
        related_finding_ids=[],
    )
    db_session.add(f)
    db_session.flush()
    return f


@pytest.fixture()
def engagement(db_session):
    eng = Engagement(client_name="Test", app_platform=Platform.android,
                     status=EngagementStatus.scanning)
    db_session.add(eng)
    db_session.flush()
    return eng


VALID_OUTPUT = {
    "duplicates": [],
    "attack_chains": [
        {
            "finding_ids": ["a1", "b2"],
            "narrative": "Exported activity leads to unauthenticated data access.",
            "combined_severity": "high",
        }
    ],
    "related_updates": [
        {"finding_id": "a1", "related_finding_ids": ["b2"]},
    ],
    "notes": None,
}


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

_KNOWN = frozenset({"a1", "b2"})


class TestValidator:
    def test_valid(self):
        make_validator(_KNOWN)(VALID_OUTPUT)

    def test_empty_dict_defaults(self):
        make_validator(_KNOWN)({})  # missing keys -> all empty

    def test_unknown_dup_id(self):
        bad = {"duplicates": [{"keep_id": "a1", "remove_id": "zz"}]}
        with pytest.raises(ValueError, match="unknown finding id"):
            make_validator(_KNOWN)(bad)

    def test_dup_same_id(self):
        bad = {"duplicates": [{"keep_id": "a1", "remove_id": "a1"}]}
        with pytest.raises(ValueError, match="must differ"):
            make_validator(_KNOWN)(bad)

    def test_chain_single_member(self):
        bad = {"attack_chains": [{"finding_ids": ["a1"],
                                  "narrative": "x",
                                  "combined_severity": "low"}]}
        with pytest.raises(ValueError, match=">= 2"):
            make_validator(_KNOWN)(bad)

    def test_chain_bad_severity(self):
        bad = {"attack_chains": [{"finding_ids": ["a1", "b2"],
                                  "narrative": "x",
                                  "combined_severity": "extreme"}]}
        with pytest.raises(ValueError, match="combined_severity"):
            make_validator(_KNOWN)(bad)

    def test_chain_unknown_id(self):
        bad = {"attack_chains": [{"finding_ids": ["a1", "zz"],
                                  "narrative": "x",
                                  "combined_severity": "low"}]}
        with pytest.raises(ValueError, match="unknown finding id"):
            make_validator(_KNOWN)(bad)

    def test_related_unknown_id(self):
        bad = {"related_updates": [{"finding_id": "zz",
                                    "related_finding_ids": []}]}
        with pytest.raises(ValueError, match="unknown finding id"):
            make_validator(_KNOWN)(bad)


# ---------------------------------------------------------------------------
# Readiness gate
# ---------------------------------------------------------------------------

class TestStagesDone:
    def test_no_findings_not_ready(self, db_session, engagement):
        ok, reason = stages_done(db_session, engagement.id)
        assert ok is False
        assert "no findings" in reason

    def test_findings_ready(self, db_session, engagement):
        _finding(db_session, engagement.id, SourceAgent.static, "S1")
        _finding(db_session, engagement.id, SourceAgent.api, "A1")
        ok, reason = stages_done(db_session, engagement.id)
        assert ok is True
        assert "static=1" in reason and "api=1" in reason

    def test_pending_job_blocks(self, db_session, engagement):
        from scan_toolkit.queue import JobQueue
        _finding(db_session, engagement.id, SourceAgent.static, "S1")
        queue = JobQueue.__new__(JobQueue)  # submit needs no engine state
        job = queue.submit(db_session, engagement_id=engagement.id,
                           stage="dynamic")
        assert job.status.value == "pending"
        ok, reason = stages_done(db_session, engagement.id)
        assert ok is False
        assert "worker" in reason

    def test_failed_job_does_not_block(self, db_session, engagement):
        from scan_toolkit.queue import JobQueue, JobStatus
        _finding(db_session, engagement.id, SourceAgent.static, "S1")
        queue = JobQueue.__new__(JobQueue)
        job = queue.submit(db_session, engagement_id=engagement.id,
                           stage="dynamic")
        job.status = JobStatus.failed
        ok, _ = stages_done(db_session, engagement.id)
        assert ok is True


# ---------------------------------------------------------------------------
# Agent run
# ---------------------------------------------------------------------------

class TestCorrelationAgent:
    def test_full_flow(self, db_session, engagement):
        static_f = _finding(db_session, engagement.id, SourceAgent.static,
                            "Plaintext prefs", severity="medium")
        dynamic_f = _finding(db_session, engagement.id, SourceAgent.dynamic,
                             "Prefs write observed", severity="high")
        api_f = _finding(db_session, engagement.id, SourceAgent.api,
                         "Cleartext login", severity="high")

        mock_llm = MagicMock()
        mock_llm.call.return_value = {
            "duplicates": [{"keep_id": dynamic_f.id,
                            "remove_id": static_f.id,
                            "reason": "same storage issue, dynamic observed"}],
            "attack_chains": [{
                "finding_ids": [dynamic_f.id, api_f.id],
                "narrative": "Creds in prefs + cleartext login = theft.",
                "combined_severity": "critical",
            }],
            "related_updates": [
                {"finding_id": api_f.id,
                 "related_finding_ids": [dynamic_f.id]}],
            "notes": None,
        }

        summary = CorrelationAgent(llm=mock_llm).run(
            db_session, engagement.id)

        assert len(summary["chains"]) == 1
        assert summary["duplicates_marked"] == 1
        assert summary["related_updated"] == 1

        db_session.refresh(static_f)
        db_session.refresh(dynamic_f)
        db_session.refresh(api_f)
        assert static_f.status == FindingStatus.duplicate
        assert static_f.id in dynamic_f.related_finding_ids
        assert dynamic_f.id in api_f.related_finding_ids

        chains = db_session.query(AttackChain).all()
        assert len(chains) == 1
        assert set(chains[0].finding_ids) == {dynamic_f.id, api_f.id}
        assert chains[0].combined_severity == Severity.critical

        # Engagement advanced to reviewing (forward-only, idempotent-safe).
        db_session.refresh(engagement)
        assert engagement.status == EngagementStatus.reviewing

    def test_dispositioned_findings_excluded(self, db_session, engagement):
        dup = _finding(db_session, engagement.id, SourceAgent.static, "Old",
                       status=FindingStatus.duplicate)
        live = _finding(db_session, engagement.id, SourceAgent.api, "Live")

        mock_llm = MagicMock()
        mock_llm.call.return_value = {"duplicates": [], "attack_chains": [],
                                      "related_updates": [], "notes": None}
        CorrelationAgent(llm=mock_llm).run(db_session, engagement.id)

        user_message = mock_llm.call.call_args.kwargs["user_message"]
        assert live.id in user_message
        assert dup.id not in user_message

    def test_no_correlatable_skips_llm(self, db_session, engagement):
        _finding(db_session, engagement.id, SourceAgent.static, "Old",
                 status=FindingStatus.false_positive)
        mock_llm = MagicMock()
        summary = CorrelationAgent(llm=mock_llm).run(
            db_session, engagement.id)
        assert summary == {"chains": [], "duplicates_marked": 0,
                           "related_updated": 0}
        mock_llm.call.assert_not_called()

    def test_gate_blocks(self, db_session, engagement):
        with pytest.raises(ValueError, match="not ready"):
            CorrelationAgent(llm=MagicMock()).run(db_session, engagement.id)

    def test_prompt_redacted(self, db_session, engagement):
        f = _finding(db_session, engagement.id, SourceAgent.dynamic, "Leak")
        f.evidence = "logcat: password=s3cr3t"
        db_session.add(f)

        mock_llm = MagicMock()
        mock_llm.call.return_value = {"duplicates": [], "attack_chains": [],
                                      "related_updates": [], "notes": None}
        CorrelationAgent(llm=mock_llm).run(db_session, engagement.id)

        user_message = mock_llm.call.call_args.kwargs["user_message"]
        assert "s3cr3t" not in user_message


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCorrelateCLI:
    def test_help(self):
        result = runner.invoke(app, ["correlate", "--help"])
        assert result.exit_code == 0
        assert "--engagement" in result.output

    def test_unknown_engagement(self, tmp_path):
        result = runner.invoke(
            app, ["correlate", "--engagement", "deadbeef1234"],
            env={"SCAN_TOOLKIT_DATA_DIR": str(tmp_path / "data")},
        )
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_malformed_id(self, tmp_path):
        result = runner.invoke(
            app, ["correlate", "--engagement", "../../etc"],
            env={"SCAN_TOOLKIT_DATA_DIR": str(tmp_path / "data")},
        )
        assert result.exit_code == 1
