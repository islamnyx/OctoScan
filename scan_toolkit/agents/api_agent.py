"""API/Backend Agent — LLM layer for mitmproxy + ZAP + role-diff output.

Takes the ``api_ir.json`` produced by ``stages.run_api`` and returns Finding
objects with ``source_agent="api"``.  Two redaction layers protect secrets:

  1. Deterministic: ``redact_dict()`` scrubs the whole IR payload BEFORE
     the prompt is built (rule-based, does not depend on model behaviour).
  2. Instructional: the system prompt orders the model to emit ``[REDACTED]``
     for any secret/PII it still sees.

Persisted finding evidence is redacted a second time before DB write, so
even a model that echoes a raw token cannot leak it into stored findings.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from sqlalchemy.orm import Session

from scan_toolkit.agents.llm_client import LLMClient, LLMError  # noqa: F401
from scan_toolkit.agents.redact import redact_dict, redact_text
from scan_toolkit.intermediate import StageIR
from scan_toolkit.models import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    SourceAgent,
)

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are the API/Backend Security Agent for a mobile application security \
assessment toolkit.  You process output from API security testing: mitmproxy \
traffic captures (passive transport/secret-hygiene checks), a multi-role \
access comparison, and OWASP ZAP active-scan alerts.

RULES:
1. Every Finding you produce MUST correspond to an IR finding in the input. \
You MUST NOT invent vulnerabilities.
2. Output ONLY a JSON object matching the schema below.
3. CRITICAL — REDACTION: the input was mechanically scrubbed, but if you see \
any remaining authentication token, session ID, API key, password, or PII \
(email, phone, real name) in evidence, replace it with [REDACTED] in your \
output.  Never copy a live secret into a Finding.
4. Role-diff findings (tool=role_diff) are TRIAGE CANDIDATES, not confirmed \
vulns.  Keep their candidate wording, keep confidence low, and do NOT raise \
their severity above medium without concrete ZAP/traffic evidence.
5. Deduplicate: a ZAP alert and a mitmproxy passive check describing the same \
issue on the same endpoint = one Finding with combined evidence.
6. Be conservative with severity.  When uncertain, prefer lower severity.
7. If the input has zero findings, return {"findings": [], "notes": "No API findings."}.

SEVERITY GUIDELINES:
- critical: Auth bypass or IDOR with concrete evidence (e.g. ZAP high-risk \
alert confirmed by traffic showing cross-user data access)
- high: Injection (SQLi/XSS) from ZAP with alert evidence, secrets in URLs, \
sensitive data over cleartext HTTP
- medium: Missing auth on an endpoint (anonymous 2xx) that serves \
non-public data, missing security headers with exploit context, ZAP mediums
- low: Role-diff candidates needing manual verification, ZAP lows
- info: Informational observations, scan coverage notes

OUTPUT SCHEMA:
{
  "findings": [
    {
      "source_agent": "api",
      "category": "<string>",
      "cwe_id": "<CWE-NNN or null>",
      "title": "<concise, max 200 chars>",
      "description": "<detailed description>",
      "evidence": "<endpoint, status codes, roles — concrete proof, redacted>",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "affected_component": "<endpoint or host>",
      "remediation_suggestion": "<specific fix>",
      "status": "new",
      "related_finding_ids": []
    }
  ],
  "notes": "<optional string or null>"
}
"""

_VALID_SEVERITIES = {s.value for s in Severity}
_VALID_CONFIDENCES = {c.value for c in Confidence}


def validate_api_output(data: dict) -> None:
    """Raise ValueError if data doesn't match the API agent output schema."""
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
        if f.get("source_agent") != "api":
            raise ValueError(
                f"findings[{i}].source_agent must be 'api', got {f.get('source_agent')!r}"
            )


class APIBackendAgent:
    """Process API IR -> validated Finding rows in the DB (redacted)."""

    def __init__(self, *, llm: LLMClient | None = None):
        self._llm = llm or LLMClient()

    def run(
        self,
        session: Session,
        engagement_id: str,
        ir_path: Path,
    ) -> list[Finding]:
        ir = self._load_ir(ir_path)

        total_findings = sum(len(t.findings) for t in ir.tools)
        if total_findings == 0:
            log.info("No API IR findings for engagement %s — skipping LLM call", engagement_id)
            return []

        log.info(
            "Sending %d API IR findings to API/Backend Agent for engagement %s",
            total_findings,
            engagement_id,
        )

        user_message = self._build_prompt(ir)
        result = self._llm.call(
            system=_SYSTEM_PROMPT,
            user_message=user_message,
            validate_fn=validate_api_output,
        )

        findings = self._persist(session, engagement_id, result)
        log.info("API/Backend Agent produced %d findings for engagement %s", len(findings), engagement_id)
        return findings

    @staticmethod
    def _load_ir(ir_path: Path) -> StageIR:
        if not ir_path.exists():
            raise FileNotFoundError(f"IR file not found: {ir_path}")
        raw = json.loads(ir_path.read_text())
        return StageIR.model_validate(raw)

    @staticmethod
    def _build_prompt(ir: StageIR) -> str:
        """Serialise the IR with deterministic redaction applied FIRST."""
        scrubbed_input = redact_dict(ir.input)
        scrubbed_notes = [redact_text(n) for n in ir.notes]
        sections = [
            f"## Engagement: {ir.engagement_id}",
            f"## Stage: {ir.stage}",
            f"## App info: {json.dumps(scrubbed_input)}",
        ]
        if scrubbed_notes:
            sections.append(f"## Notes: {json.dumps(scrubbed_notes)}")

        for tool_output in ir.tools:
            if not tool_output.findings:
                continue
            sections.append(f"\n### Tool: {tool_output.tool} (v{tool_output.version or 'unknown'})")
            sections.append(f"Finding count: {len(tool_output.findings)}")
            for j, f in enumerate(tool_output.findings):
                sections.append(f"\n#### Finding {j+1}")
                scrubbed = redact_dict(f.model_dump(exclude_none=True))
                sections.append(json.dumps(scrubbed, indent=2))

        return "\n".join(sections)

    @staticmethod
    def _persist(session: Session, engagement_id: str, result: dict) -> list[Finding]:
        findings: list[Finding] = []
        for item in result.get("findings", []):
            finding = Finding(
                engagement_id=engagement_id,
                source_agent=SourceAgent.api,
                category=item.get("category"),
                cwe_id=item.get("cwe_id"),
                title=item["title"][:200],
                description=redact_text(item.get("description")),
                evidence=redact_text(item.get("evidence")),
                severity=Severity(item["severity"]),
                confidence=Confidence(item["confidence"]),
                affected_component=item.get("affected_component"),
                remediation_suggestion=redact_text(item.get("remediation_suggestion")),
                status=FindingStatus.new,
                related_finding_ids=item.get("related_finding_ids", []),
            )
            session.add(finding)
            findings.append(finding)
        session.flush()
        return findings
