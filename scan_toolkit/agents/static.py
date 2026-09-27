"""Static Analysis Agent — first LLM integration.

Takes normalised IR output from the static analysis pipeline (Semgrep + MobSF)
and returns Finding objects matching the DB schema.  The LLM deduplicates across
tools, assigns severity/confidence/CWE, and writes actionable descriptions.

Flow:
  1. Load the StageIR JSON produced by ``stages.run_static``.
  2. Serialise the IR findings into the LLM prompt.
  3. Call the LLM with the Static Analysis Agent system prompt.
  4. Validate the structured JSON response against the Finding schema.
  5. Persist validated Findings to the database.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from scan_toolkit.agents.llm_client import LLMClient, LLMError
from scan_toolkit.intermediate import StageIR
from scan_toolkit.models import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    SourceAgent,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt (loaded from agent_prompts.md Section 2 at module level)
# ---------------------------------------------------------------------------

_PROMPTS_PATH = Path(__file__).resolve().parent.parent / "agent_prompts.md"

_SYSTEM_PROMPT = """\
You are the Static Analysis Agent for a mobile application security assessment \
toolkit.  You process normalized output from static analysis tools (Semgrep and \
MobSF) that have scanned a decompiled Android APK.

RULES:
1. Every Finding you produce MUST correspond to at least one IR finding in the \
input.  You MUST NOT invent findings.
2. Output ONLY a JSON object matching the schema below. No markdown, no prose.
3. Deduplicate: if Semgrep and MobSF flag the same underlying issue (same file + \
same CWE), merge into one Finding with combined evidence.
4. Be conservative with severity.  When uncertain, prefer lower severity.
5. Map CWE IDs accurately.  If the tool provides one, validate it. If not, \
assign the most specific applicable one.
6. Preserve file paths and line numbers from the original tool output.
7. If the input has zero findings, return {"findings": [], "notes": "No findings."}.

SEVERITY GUIDELINES:
- critical: Hardcoded secrets/credentials, disabled cert validation, SQLi
- high: Weak crypto (MD5/SHA1), insecure storage (plaintext SharedPrefs for \
sensitive data), exported components without guards, WebView JS+file access
- medium: Missing root detection, debug flags, overly broad permissions, \
sensitive data logging
- low: Deprecated APIs, minor best-practice misses
- info: Non-security observations

CONFIDENCE:
- high: Concrete code evidence (matched pattern, specific code line)
- medium: Heuristic match or category-level detection
- low: Informational or pattern-based guess

OUTPUT SCHEMA:
{
  "findings": [
    {
      "source_agent": "static",
      "category": "<string>",
      "cwe_id": "<CWE-NNN or null>",
      "title": "<concise, max 200 chars>",
      "description": "<detailed description>",
      "evidence": "<code snippet, file:line, concrete proof>",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "affected_component": "<package/class/file>",
      "remediation_suggestion": "<specific fix>",
      "status": "new",
      "related_finding_ids": []
    }
  ],
  "notes": "<optional string or null>"
}
"""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = {s.value for s in Severity}
_VALID_CONFIDENCES = {c.value for c in Confidence}


def validate_agent_output(data: dict) -> None:
    """Raise ValueError if *data* doesn't match the expected schema."""
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object, got {type(data).__name__}")
    if "findings" not in data:
        raise ValueError("Missing top-level 'findings' key")
    findings = data["findings"]
    if not isinstance(findings, list):
        raise ValueError(f"'findings' must be a list, got {type(findings).__name__}")
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            raise ValueError(f"findings[{i}] must be a dict")
        # Required keys.
        for key in ("title", "severity", "confidence", "source_agent"):
            if key not in f or not f[key]:
                raise ValueError(f"findings[{i}] missing required field '{key}'")
        if f["severity"] not in _VALID_SEVERITIES:
            raise ValueError(
                f"findings[{i}].severity={f['severity']!r} not in {_VALID_SEVERITIES}"
            )
        if f["confidence"] not in _VALID_CONFIDENCES:
            raise ValueError(
                f"findings[{i}].confidence={f['confidence']!r} not in {_VALID_CONFIDENCES}"
            )
        if f.get("source_agent") != "static":
            raise ValueError(
                f"findings[{i}].source_agent must be 'static', got {f.get('source_agent')!r}"
            )


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class StaticAnalysisAgent:
    """Process static IR → validated Finding rows in the DB."""

    def __init__(self, *, llm: LLMClient | None = None):
        self._llm = llm or LLMClient()

    def run(
        self,
        session: Session,
        engagement_id: str,
        ir_path: Path,
    ) -> list[Finding]:
        """Run the agent: load IR, call LLM, persist Findings.

        Parameters
        ----------
        session : Session
            Active SQLAlchemy session (caller manages commit/rollback).
        engagement_id : str
            Engagement to attach findings to.
        ir_path : Path
            Path to the ``static_ir.json`` written by ``stages.run_static``.

        Returns
        -------
        list[Finding]
            Persisted Finding ORM objects.

        Raises
        ------
        LLMError
            If the LLM fails after retry.
        FileNotFoundError
            If ir_path doesn't exist.
        """
        ir = self._load_ir(ir_path)

        # Build the user message with the IR data.
        user_message = self._build_prompt(ir)

        # If there are zero findings across all tools, skip the LLM call.
        total_findings = sum(len(t.findings) for t in ir.tools)
        if total_findings == 0:
            log.info("No IR findings for engagement %s — skipping LLM call", engagement_id)
            return []

        log.info(
            "Sending %d IR findings to Static Analysis Agent for engagement %s",
            total_findings,
            engagement_id,
        )

        result = self._llm.call(
            system=_SYSTEM_PROMPT,
            user_message=user_message,
            validate_fn=validate_agent_output,
        )

        findings = self._persist(session, engagement_id, result)
        log.info(
            "Static Analysis Agent produced %d findings for engagement %s",
            len(findings),
            engagement_id,
        )
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_ir(ir_path: Path) -> StageIR:
        if not ir_path.exists():
            raise FileNotFoundError(f"IR file not found: {ir_path}")
        raw = json.loads(ir_path.read_text())
        return StageIR.model_validate(raw)

    @staticmethod
    def _build_prompt(ir: StageIR) -> str:
        """Serialise the IR into a compact prompt for the LLM."""
        sections = [
            f"## Engagement: {ir.engagement_id}",
            f"## Stage: {ir.stage}",
            f"## App info: {json.dumps(ir.input)}",
        ]
        if ir.notes:
            sections.append(f"## Notes: {json.dumps(ir.notes)}")

        for tool_output in ir.tools:
            if not tool_output.findings:
                continue
            sections.append(f"\n### Tool: {tool_output.tool} (v{tool_output.version or 'unknown'})")
            sections.append(f"Finding count: {len(tool_output.findings)}")
            for j, f in enumerate(tool_output.findings):
                sections.append(f"\n#### Finding {j+1}")
                sections.append(json.dumps(f.model_dump(exclude_none=True), indent=2))

        return "\n".join(sections)

    @staticmethod
    def _persist(
        session: Session,
        engagement_id: str,
        result: dict,
    ) -> list[Finding]:
        """Convert validated LLM output to ORM Finding rows."""
        findings: list[Finding] = []
        for item in result.get("findings", []):
            finding = Finding(
                engagement_id=engagement_id,
                source_agent=SourceAgent.static,
                category=item.get("category"),
                cwe_id=item.get("cwe_id"),
                title=item["title"][:200],
                description=item.get("description"),
                evidence=item.get("evidence"),
                severity=Severity(item["severity"]),
                confidence=Confidence(item["confidence"]),
                affected_component=item.get("affected_component"),
                remediation_suggestion=item.get("remediation_suggestion"),
                status=FindingStatus.new,
                related_finding_ids=item.get("related_finding_ids", []),
            )
            session.add(finding)
            findings.append(finding)
        session.flush()
        return findings
