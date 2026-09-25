"""Dynamic Analysis Agent — LLM layer for Frida + emulator observations.

Takes the ``dynamic_ir.json`` produced by ``stages.run_dynamic`` and returns
Finding objects with ``source_agent="dynamic"``.  Per agent_prompts.md
Section 4, dynamic findings carry HIGHER confidence than static — the
behaviour was observed at runtime, not pattern-matched — and the agent is
instructed to preserve that distinction rather than downgrade it.

Redaction: runtime evidence routinely contains storage values and logcat
lines, so the deterministic ``redact_dict()`` pass runs BEFORE the prompt
is built, and persisted evidence is redacted again before DB write
(same two layers as the API agent).
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
You are the Dynamic Analysis Agent for a mobile application security \
assessment toolkit.  You process runtime observations: Frida instrumentation \
events (crypto calls, storage writes, TLS validation, debugger/root signals), \
emulator observations (logcat, dumpsys, exported-component surface).

RULES:
1. Every Finding you produce MUST correspond to an IR finding in the input. \
You MUST NOT invent findings.
2. Output ONLY a JSON object matching the schema below.
3. Dynamic evidence was OBSERVED at runtime — keep confidence high where the \
tool observed concrete behaviour.  Do NOT downgrade dynamic confidence to \
match static-style caution.
4. CRITICAL — REDACTION: storage values and logcat lines may contain secrets \
or PII.  If you see any token, password, key, email, or phone number in \
evidence, replace it with [REDACTED].
5. Exported-component findings describe ATTACK SURFACE, not confirmed \
exploits.  Keep their wording as surface-to-exercise, keep severity at or \
below medium unless Frida/logcat evidence shows actual exploitation.
6. Deduplicate: a Frida cleartext observation and a logcat cleartext line \
for the same host = one Finding with combined evidence.
7. Be conservative with severity.  When uncertain, prefer lower severity.
8. If the input has zero findings, return {"findings": [], "notes": "No dynamic findings."}.

SEVERITY GUIDELINES:
- critical: Trust-all TLS (empty checkServerTrusted CONFIRMED by traffic), \
WebView tapping through cert errors on sensitive flows
- high: Weak cipher (DES/ECB) observed, world-accessible files, credentials \
in logcat, sensitive values in plaintext storage
- medium: MD5/SHA-1 in security context, cleartext HTTP observed, exported \
component without guard on a sensitive action
- low: Custom TrustManager (unverified), test-keys environment caveats, \
single-role storage writes of unclear sensitivity
- info: Debugger-attached notes, coverage/observation inventory

OUTPUT SCHEMA:
{
  "findings": [
    {
      "source_agent": "dynamic",
      "category": "<string>",
      "cwe_id": "<CWE-NNN or null>",
      "title": "<concise, max 200 chars>",
      "description": "<detailed description>",
      "evidence": "<observed behaviour — concrete proof, redacted>",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "affected_component": "<class/endpoint/component>",
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


def validate_dynamic_output(data: dict) -> None:
    """Raise ValueError if data doesn't match the dynamic output schema."""
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
        if f.get("source_agent") != "dynamic":
            raise ValueError(
                f"findings[{i}].source_agent must be 'dynamic', got {f.get('source_agent')!r}"
            )


class DynamicAnalysisAgent:
    """Process dynamic IR -> validated Finding rows in the DB (redacted)."""

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
            log.info("No dynamic IR findings for engagement %s — skipping LLM call", engagement_id)
            return []

        log.info(
            "Sending %d dynamic IR findings to Dynamic Analysis Agent for engagement %s",
            total_findings,
            engagement_id,
        )

        user_message = self._build_prompt(ir)
        result = self._llm.call(
            system=_SYSTEM_PROMPT,
            user_message=user_message,
            validate_fn=validate_dynamic_output,
        )

        findings = self._persist(session, engagement_id, result)
        log.info(
            "Dynamic Analysis Agent produced %d findings for engagement %s",
            len(findings), engagement_id,
        )
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
                source_agent=SourceAgent.dynamic,
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
