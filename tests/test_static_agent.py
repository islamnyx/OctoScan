"""Tests for the Static Analysis Agent — LLM is mocked, never called.

Tests cover:
  - Schema validation (valid, missing fields, bad enum values)
  - Agent end-to-end with a mock LLM (IR → Finding rows in DB)
  - Zero-findings shortcut (no LLM call)
  - Retry on validation failure
  - LLMClient code-fence stripping and JSON parsing
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scan_toolkit.agents.llm_client import LLMClient, LLMError, _strip_code_fences
from scan_toolkit.agents.static import StaticAnalysisAgent, validate_agent_output
from scan_toolkit.intermediate import IRFinding, IRToolOutput, StageIR
from scan_toolkit.models import Finding, Severity, Confidence, SourceAgent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_FINDING = {
    "source_agent": "static",
    "category": "insecure_crypto",
    "cwe_id": "CWE-327",
    "title": "Weak MD5 hash used for security",
    "description": "MD5 is used in CryptoUtil.java for password hashing.",
    "evidence": "MessageDigest.getInstance(\"MD5\") at CryptoUtil.java:42",
    "severity": "high",
    "confidence": "high",
    "affected_component": "com.acme.app.CryptoUtil",
    "remediation_suggestion": "Use SHA-256 or bcrypt instead of MD5.",
    "status": "new",
    "related_finding_ids": [],
}

VALID_OUTPUT = {"findings": [VALID_FINDING], "notes": "One finding from Semgrep."}

SAMPLE_IR = StageIR(
    engagement_id="abc123def456",
    stage="static",
    input={"binary": "app.apk", "platform": "android"},
    tools=[
        IRToolOutput(
            tool="semgrep",
            version="1.90.0",
            findings=[
                IRFinding(
                    tool="semgrep",
                    rule_id="message-digest-weak",
                    severity="error",
                    cwe_id="CWE-327",
                    file="CryptoUtil.java",
                    line=42,
                    evidence='MessageDigest.getInstance("MD5")',
                    title="Weak message digest MD5 used",
                ),
            ],
        ),
        IRToolOutput(tool="mobsf", findings=[]),
    ],
)


@pytest.fixture()
def ir_file(tmp_path) -> Path:
    """Write SAMPLE_IR to a temp file."""
    p = tmp_path / "static_ir.json"
    p.write_text(SAMPLE_IR.model_dump_json(indent=2))
    return p


# ---------------------------------------------------------------------------
# validate_agent_output
# ---------------------------------------------------------------------------


class TestValidation:
    def test_valid_output_passes(self):
        validate_agent_output(VALID_OUTPUT)  # should not raise

    def test_missing_findings_key(self):
        with pytest.raises(ValueError, match="Missing.*findings"):
            validate_agent_output({"notes": "oops"})

    def test_findings_not_list(self):
        with pytest.raises(ValueError, match="must be a list"):
            validate_agent_output({"findings": "oops"})

    def test_finding_missing_title(self):
        bad = {**VALID_FINDING, "title": ""}
        with pytest.raises(ValueError, match="title"):
            validate_agent_output({"findings": [bad]})

    def test_finding_bad_severity(self):
        bad = {**VALID_FINDING, "severity": "super_critical"}
        with pytest.raises(ValueError, match="severity"):
            validate_agent_output({"findings": [bad]})

    def test_finding_bad_confidence(self):
        bad = {**VALID_FINDING, "confidence": "very_high"}
        with pytest.raises(ValueError, match="confidence"):
            validate_agent_output({"findings": [bad]})

    def test_finding_wrong_source_agent(self):
        bad = {**VALID_FINDING, "source_agent": "dynamic"}
        with pytest.raises(ValueError, match="source_agent"):
            validate_agent_output({"findings": [bad]})

    def test_empty_findings_valid(self):
        validate_agent_output({"findings": [], "notes": "none"})

    def test_not_a_dict(self):
        with pytest.raises(ValueError, match="Expected JSON object"):
            validate_agent_output([1, 2, 3])


# ---------------------------------------------------------------------------
# _strip_code_fences
# ---------------------------------------------------------------------------


class TestStripCodeFences:
    def test_no_fences(self):
        assert _strip_code_fences('{"a": 1}') == '{"a": 1}'

    def test_json_fence(self):
        assert _strip_code_fences('```json\n{"a": 1}\n```') == '{"a": 1}'

    def test_plain_fence(self):
        assert _strip_code_fences('```\n{"a": 1}\n```') == '{"a": 1}'


# ---------------------------------------------------------------------------
# LLMClient (mocked Anthropic SDK)
# ---------------------------------------------------------------------------


class TestLLMClient:
    def _make_mock_response(self, text: str):
        block = MagicMock()
        block.type = "text"
        block.text = text
        resp = MagicMock()
        resp.content = [block]
        return resp

    @patch("scan_toolkit.agents.llm_client.anthropic")
    def test_call_returns_parsed_json(self, mock_anthropic):
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client
        mock_client.messages.create.return_value = self._make_mock_response(
            json.dumps(VALID_OUTPUT)
        )

        client = LLMClient(provider="anthropic", api_key="test-key")
        result = client.call(system="sys", user_message="user")
        assert result == VALID_OUTPUT

    @patch("scan_toolkit.agents.llm_client.anthropic")
    def test_call_strips_code_fences(self, mock_anthropic):
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client
        mock_client.messages.create.return_value = self._make_mock_response(
            '```json\n{"findings": []}\n```'
        )

        client = LLMClient(provider="anthropic", api_key="test-key")
        result = client.call(system="sys", user_message="user")
        assert result == {"findings": []}

    @patch("scan_toolkit.agents.llm_client.anthropic")
    def test_call_raises_on_invalid_json(self, mock_anthropic):
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client
        mock_client.messages.create.return_value = self._make_mock_response(
            "this is not json"
        )

        client = LLMClient(provider="anthropic", api_key="test-key")
        with pytest.raises(LLMError, match="invalid JSON"):
            client.call(system="sys", user_message="user")

    @patch("scan_toolkit.agents.llm_client.anthropic")
    def test_call_retries_on_validation_failure(self, mock_anthropic):
        """First response fails validation, second succeeds."""
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        bad_output = {"findings": [{"title": "X", "severity": "INVALID",
                                     "confidence": "high", "source_agent": "static"}]}
        good_output = VALID_OUTPUT

        mock_client.messages.create.side_effect = [
            self._make_mock_response(json.dumps(bad_output)),
            self._make_mock_response(json.dumps(good_output)),
        ]

        client = LLMClient(provider="anthropic", api_key="test-key")
        result = client.call(
            system="sys",
            user_message="user",
            validate_fn=validate_agent_output,
        )
        assert result == VALID_OUTPUT
        assert mock_client.messages.create.call_count == 2

    @patch("scan_toolkit.agents.llm_client.anthropic")
    def test_call_fails_after_retry(self, mock_anthropic):
        """Both attempts fail validation → LLMError."""
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        bad_output = {"findings": [{"title": "X", "severity": "INVALID",
                                     "confidence": "high", "source_agent": "static"}]}
        mock_client.messages.create.side_effect = [
            self._make_mock_response(json.dumps(bad_output)),
            self._make_mock_response(json.dumps(bad_output)),
        ]

        client = LLMClient(provider="anthropic", api_key="test-key")
        with pytest.raises(LLMError, match="failed validation after retry"):
            client.call(
                system="sys",
                user_message="user",
                validate_fn=validate_agent_output,
            )

    def test_missing_api_key_raises(self, monkeypatch):
        monkeypatch.setenv("SCAN_TOOLKIT_ANTHROPIC_API_KEY", "")
        from scan_toolkit.config import get_settings
        get_settings.cache_clear()
        with pytest.raises(RuntimeError, match="SCAN_TOOLKIT_ANTHROPIC_API_KEY"):
            LLMClient(provider="anthropic")
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# StaticAnalysisAgent (mocked LLM)
# ---------------------------------------------------------------------------


class TestStaticAnalysisAgent:
    def test_run_produces_finding_rows(self, db_session, ir_file):
        """Full pipeline: IR file → mock LLM → Finding rows in DB."""
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()

        mock_llm = MagicMock(spec=LLMClient)
        mock_llm.call.return_value = VALID_OUTPUT

        agent = StaticAnalysisAgent(llm=mock_llm)
        findings = agent.run(db_session, eng.id, ir_file)

        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, Finding)
        assert f.engagement_id == eng.id
        assert f.source_agent == SourceAgent.static
        assert f.severity == Severity.high
        assert f.confidence == Confidence.high
        assert f.cwe_id == "CWE-327"
        assert f.title == "Weak MD5 hash used for security"

        # Verify it's actually in the DB.
        loaded = db_session.get(Finding, f.id)
        assert loaded is not None
        assert loaded.title == f.title

    def test_zero_findings_skips_llm(self, db_session, tmp_path):
        """When IR has no findings, agent returns [] without calling the LLM."""
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()

        empty_ir = StageIR(
            engagement_id=eng.id,
            stage="static",
            tools=[IRToolOutput(tool="semgrep"), IRToolOutput(tool="mobsf")],
        )
        ir_path = tmp_path / "empty_ir.json"
        ir_path.write_text(empty_ir.model_dump_json())

        mock_llm = MagicMock(spec=LLMClient)
        agent = StaticAnalysisAgent(llm=mock_llm)
        findings = agent.run(db_session, eng.id, ir_path)

        assert findings == []
        mock_llm.call.assert_not_called()

    def test_missing_ir_file_raises(self, db_session):
        mock_llm = MagicMock(spec=LLMClient)
        agent = StaticAnalysisAgent(llm=mock_llm)
        with pytest.raises(FileNotFoundError):
            agent.run(db_session, "abc123def456", Path("/nonexistent/ir.json"))

    def test_multiple_findings_persisted(self, db_session, ir_file):
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Multi", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()

        output = {
            "findings": [
                VALID_FINDING,
                {
                    **VALID_FINDING,
                    "title": "Hardcoded API key",
                    "cwe_id": "CWE-798",
                    "severity": "critical",
                    "confidence": "high",
                },
            ],
            "notes": None,
        }

        mock_llm = MagicMock(spec=LLMClient)
        mock_llm.call.return_value = output

        agent = StaticAnalysisAgent(llm=mock_llm)
        findings = agent.run(db_session, eng.id, ir_file)

        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert Severity.critical in severities
        assert Severity.high in severities

    def test_build_prompt_includes_findings(self):
        """Verify the prompt builder serialises IR findings."""
        prompt = StaticAnalysisAgent._build_prompt(SAMPLE_IR)
        assert "CryptoUtil.java" in prompt
        assert "CWE-327" in prompt
        assert "semgrep" in prompt
        assert "abc123def456" in prompt
