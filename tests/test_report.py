"""Tests for Phase 10 — report gate, metadata validation, redaction,
md/docx/pdf rendering, review CLI. The LLM is always mocked.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from scan_toolkit.agents.report import ReportAgent, make_report_validator
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
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def rpt_env(tmp_path, monkeypatch):
    """Isolated DATA_DIR via env (covers in-process CLI + agent paths)."""
    from scan_toolkit.config import get_settings
    monkeypatch.setenv("SCAN_TOOLKIT_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def _engagement(db_session, status=EngagementStatus.reviewing):
    eng = Engagement(client_name="Acme", app_platform=Platform.android,
                     app_version="1.0", status=status)
    db_session.add(eng)
    db_session.flush()
    return eng


def _finding(db_session, eng_id, title, severity="high",
             status=FindingStatus.new, source=SourceAgent.static):
    f = Finding(
        engagement_id=eng_id, source_agent=source, category="test",
        title=title, description=f"{title} desc",
        evidence=f"{title} evidence", severity=Severity(severity),
        confidence=Confidence.high, status=status, related_finding_ids=[],
    )
    db_session.add(f)
    db_session.flush()
    return f


def _seed_cli_db():
    """Create engagement + findings in the env-isolated DB; return ids."""
    from scan_toolkit.db import init_db, session_scope
    engine = init_db()
    with session_scope(engine) as s:
        eng = Engagement(client_name="Acme", app_platform=Platform.android,
                         status=EngagementStatus.scanning)
        s.add(eng)
        s.flush()
        eid = eng.id
        fids = []
        for title in ("F-one", "F-two"):
            f = Finding(engagement_id=eid, source_agent=SourceAgent.static,
                        title=title, severity=Severity.high,
                        confidence=Confidence.high, status=FindingStatus.new,
                        related_finding_ids=[])
            s.add(f)
            s.flush()
            fids.append(f.id)
    return eid, fids


# ---------------------------------------------------------------------------
# Metadata validator
# ---------------------------------------------------------------------------

class TestReportValidator:
    def test_valid(self):
        make_report_validator(2, {"critical": 1, "high": 1, "medium": 0,
                                  "low": 0, "info": 0}, 1)({
            "report_markdown": "# R",
            "metadata": {"total_findings": 2,
                         "by_severity": {"critical": 1, "high": 1,
                                         "medium": 0, "low": 0, "info": 0},
                         "attack_chains": 1},
        })

    def test_total_mismatch(self):
        with pytest.raises(ValueError, match="total_findings"):
            make_report_validator(2, {"critical": 0, "high": 2, "medium": 0,
                                      "low": 0, "info": 0}, 0)({
                "report_markdown": "# R",
                "metadata": {"total_findings": 1,
                             "by_severity": {"critical": 0, "high": 2,
                                             "medium": 0, "low": 0, "info": 0},
                             "attack_chains": 0},
            })

    def test_bucket_mismatch(self):
        with pytest.raises(ValueError, match="by_severity"):
            make_report_validator(1, {"critical": 0, "high": 1, "medium": 0,
                                      "low": 0, "info": 0}, 0)({
                "report_markdown": "# R",
                "metadata": {"total_findings": 1,
                             "by_severity": {"critical": 1, "high": 0,
                                             "medium": 0, "low": 0, "info": 0},
                             "attack_chains": 0},
            })

    def test_chains_mismatch(self):
        with pytest.raises(ValueError, match="attack_chains"):
            make_report_validator(1, {"critical": 0, "high": 1, "medium": 0,
                                      "low": 0, "info": 0}, 2)({
                "report_markdown": "# R",
                "metadata": {"total_findings": 1,
                             "by_severity": {"critical": 0, "high": 1,
                                             "medium": 0, "low": 0, "info": 0},
                             "attack_chains": 1},
            })

    def test_missing_markdown(self):
        with pytest.raises(ValueError, match="report_markdown"):
            make_report_validator(0, {"critical": 0, "high": 0, "medium": 0,
                                      "low": 0, "info": 0}, 0)({
                "metadata": {"total_findings": 0,
                             "by_severity": {"critical": 0, "high": 0,
                                             "medium": 0, "low": 0, "info": 0},
                             "attack_chains": 0},
            })


# ---------------------------------------------------------------------------
# Agent gate + run
# ---------------------------------------------------------------------------

class TestReportAgent:
    def test_unconfirmed_blocked(self, db_session):
        eng = _engagement(db_session)
        _finding(db_session, eng.id, "Draft finding", status=FindingStatus.new)
        with pytest.raises(ValueError, match="none is confirmed"):
            ReportAgent(llm=MagicMock()).run(db_session, eng.id)

    def test_empty_engagement_no_llm(self, db_session, rpt_env):
        eng = _engagement(db_session)
        mock_llm = MagicMock()
        path, metadata = ReportAgent(llm=mock_llm).run(db_session, eng.id)
        mock_llm.call.assert_not_called()
        assert path.exists() and metadata["total_findings"] == 0
        assert "No findings were recorded" in path.read_text()

    def test_confirmed_only_and_redacted(self, db_session, rpt_env):
        eng = _engagement(db_session)
        keep = _finding(db_session, eng.id, "Confirmed issue",
                        status=FindingStatus.confirmed)
        _finding(db_session, eng.id, "Draft issue", status=FindingStatus.new)
        db_session.add(AttackChain(
            engagement_id=eng.id, finding_ids=[keep.id],
            narrative="Single chain.", combined_severity=Severity.high))

        mock_llm = MagicMock()
        mock_llm.call.return_value = {
            "report_markdown": (
                "# Acme Mobile Security Assessment\n\n"
                "## Executive Summary\n\nPassword password=hunter2 seen.\n\n"
                "## Methodology\n\nTools.\n\n"
                "## Findings\n\nContact admin@example.com.\n\n"
                "## Attack Chains\n\nNone.\n\n"
                "## Remediation Roadmap\n\nFix.\n\n"
                "## Appendix\n\nDone.\n"),
            "metadata": {"total_findings": 1,
                         "by_severity": {"critical": 0, "high": 1,
                                         "medium": 0, "low": 0, "info": 0},
                         "attack_chains": 1},
        }
        path, metadata = ReportAgent(llm=mock_llm).run(db_session, eng.id)

        user_message = mock_llm.call.call_args.kwargs["user_message"]
        assert "Confirmed issue" in user_message
        assert "Draft issue" not in user_message  # gate: confirmed only
        assert metadata["total_findings"] == 1

        text = path.read_text()
        assert "hunter2" not in text and "admin@example.com" not in text
        assert "[REDACTED]" in text
        assert path.parent.name == "reports"


# ---------------------------------------------------------------------------
# Markdown rendering (docx / pdf)
# ---------------------------------------------------------------------------

SAMPLE_MD = """# Acme Mobile Security Assessment

## Executive Summary

Posture is **acceptable** with 1 high finding.

## Findings

### Weak crypto

- Item one with **bold**
- Item two

1. First step
2. Second step

| Severity | Count |
|----------|-------|
| high | 1 |
| medium | 0 |

```
Cipher.getInstance("DES/ECB/PKCS5Padding")
```
"""


class TestRendering:
    def test_parse_blocks(self):
        from scan_toolkit.reports import parse_markdown
        kinds = [k for k, _ in parse_markdown(SAMPLE_MD)]
        assert kinds == ["h1", "h2", "para", "h2", "h3", "ulist", "olist",
                         "table", "code"]

    def test_bold_segments(self):
        from scan_toolkit.reports import inline_segments
        assert inline_segments("a **b** c") == [("a ", False), ("b", True),
                                                (" c", False)]

    def test_docx(self, tmp_path):
        from scan_toolkit.reports import convert_report
        md = tmp_path / "report.md"
        md.write_text(SAMPLE_MD)
        out = convert_report(md, "docx")
        assert out.suffix == ".docx" and out.stat().st_size > 2000
        assert out.read_bytes()[:2] == b"PK"  # zip container

    def test_pdf(self, tmp_path):
        from scan_toolkit.reports import convert_report
        md = tmp_path / "report.md"
        md.write_text(SAMPLE_MD)
        out = convert_report(md, "pdf")
        assert out.suffix == ".pdf" and out.stat().st_size > 2000
        assert out.read_bytes()[:4] == b"%PDF"

    def test_md_noop_and_bad_format(self, tmp_path):
        from scan_toolkit.reports import convert_report
        md = tmp_path / "report.md"
        md.write_text("# hi")
        assert convert_report(md, "md") == md
        with pytest.raises(ValueError, match="unsupported format"):
            convert_report(md, "odt")


# ---------------------------------------------------------------------------
# Review CLI
# ---------------------------------------------------------------------------

class TestReviewCLI:
    def test_list(self, rpt_env):
        eid, fids = _seed_cli_db()
        result = runner.invoke(app, ["review", "--engagement", eid])
        assert result.exit_code == 0
        assert fids[0] in result.output and "new" in result.output

    def test_confirm(self, rpt_env):
        eid, fids = _seed_cli_db()
        result = runner.invoke(
            app, ["review", "--engagement", eid,
                  "--confirm", fids[0], "--confirm", fids[1]])
        assert result.exit_code == 0
        assert "Updated 2" in result.output
        assert "confirmed" in result.output

    def test_unknown_id_fails_clean(self, rpt_env):
        eid, _ = _seed_cli_db()
        result = runner.invoke(
            app, ["review", "--engagement", eid, "--confirm", "deadbeef1234"])
        assert result.exit_code == 1
        assert "unknown finding" in result.output

    def test_conflicting_statuses_fail(self, rpt_env):
        eid, fids = _seed_cli_db()
        result = runner.invoke(
            app, ["review", "--engagement", eid,
                  "--confirm", fids[0], "--false-positive", fids[0]])
        assert result.exit_code == 1
        assert "conflicting" in result.output

    def test_report_gate_end_to_end(self, rpt_env):
        eid, fids = _seed_cli_db()
        # Unconfirmed -> report refuses.
        result = runner.invoke(app, ["report", "--engagement", eid])
        assert result.exit_code == 1
        assert "none is confirmed" in result.output
        # Confirm -> report refuses only on missing LLM key (fail loudly).
        runner.invoke(app, ["review", "--engagement", eid,
                            "--confirm", fids[0], "--confirm", fids[1]])
        result = runner.invoke(app, ["report", "--engagement", eid])
        assert result.exit_code == 1
        assert "ANTHROPIC_API_KEY" in result.output
