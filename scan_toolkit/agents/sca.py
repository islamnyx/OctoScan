"""SCA (Software Composition Analysis) Agent — LLM layer for dependency vulns.

Takes normalized IR output from the SCA pipeline (OSV.dev and/or Grype)
and returns Finding objects.  The LLM assesses mobile-context relevance,
reachability, and priority — a critical CVE in an unused transitive dep
is less urgent than a high CVE in a core networking lib.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

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

_SYSTEM_PROMPT = """\
You are the SCA (Software Composition Analysis) Agent for a mobile application \
security assessment toolkit.  You process vulnerability data from dependency \
scanners (OSV.dev and Grype) that have analyzed third-party libraries extracted \
from an Android APK.

RULES:
1. Every Finding you produce MUST correspond to a vulnerability in the input. \
You MUST NOT invent vulnerabilities.
2. Output ONLY a JSON object matching the schema below.
3. Assess mobile-context relevance: a critical CVE in an unused transitive \
dependency is LOWER priority than a high CVE in a directly-used library.
4. Deduplicate: if OSV and Grype both report the same CVE for the same package, \
produce one Finding with combined evidence.
5. Be conservative with severity adjustments. Keep the original CVSS-based \
severity unless you have strong reason to change it.
6. Include upgrade guidance in remediation_suggestion.
7. If the input has zero findings, return {"findings": [], "notes": "No SCA findings."}.

SEVERITY GUIDELINES:
- critical: RCE, authentication bypass, data exfiltration in a directly-used lib
- high: Major vulns in libs the app likely uses (networking, crypto, serialization)
- medium: Vulns in common libs with unclear reachability
- low: Vulns in transitive deps or test-only deps, or low-impact issues
- info: Informational advisories, EOL notices

OUTPUT SCHEMA:
{
  "findings": [
    {
      "source_agent": "sca",
      "category": "<string>",
      "cwe_id": "<CWE-NNN or null>",
      "title": "<concise, max 200 chars>",
      "description": "<detailed description incl. reachability assessment>",
      "evidence": "<vuln ID, CVE, package, version, fix version>",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "affected_component": "<package:version>",
      "remediation_suggestion": "<specific upgrade path>",
      "status": "new",
      "related_finding_ids": []
    }
  ],
  "notes": "<optional string or null>"
}
"""

_VALID_SEVERITIES = {s.value for s in Severity}
_VALID_CONFIDENCES = {c.value for c in Confidence}


def validate_sca_output(data: dict) -> None:
    """Raise ValueError if data doesn't match the SCA output schema."""
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
        if f.get("source_agent") != "sca":
            raise ValueError(
                f"findings[{i}].source_agent must be 'sca', got {f.get('source_agent')!r}"
            )


class SCAAgent:
    """Process SCA IR -> validated Finding rows in the DB."""

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
            log.info("No SCA IR findings for engagement %s — skipping LLM call", engagement_id)
            return []

        log.info(
            "Sending %d SCA IR findings to SCA Agent for engagement %s",
            total_findings,
            engagement_id,
        )

        user_message = self._build_prompt(ir)
        result = self._llm.call(
            system=_SYSTEM_PROMPT,
            user_message=user_message,
            validate_fn=validate_sca_output,
        )

        findings = self._persist(session, engagement_id, result)
        log.info("SCA Agent produced %d findings for engagement %s", len(findings), engagement_id)
        return findings

    @staticmethod
    def _load_ir(ir_path: Path) -> StageIR:
        if not ir_path.exists():
            raise FileNotFoundError(f"IR file not found: {ir_path}")
        raw = json.loads(ir_path.read_text())
        return StageIR.model_validate(raw)

    @staticmethod
    def _build_prompt(ir: StageIR) -> str:
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
    def _persist(session: Session, engagement_id: str, result: dict) -> list[Finding]:
        findings: list[Finding] = []
        for item in result.get("findings", []):
            finding = Finding(
                engagement_id=engagement_id,
                source_agent=SourceAgent.sca,
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
