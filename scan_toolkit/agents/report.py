"""Report Agent — client-ready Markdown from human-reviewed findings.

Hard gate (enforced in code, not process):
  * Only findings with status ``confirmed`` are fed to the LLM and included.
  * Findings exist but none confirmed -> ValueError ("review findings first").
  * Zero findings at all -> a deterministic "no findings recorded" report
    without calling the LLM (a clean scan is a legitimate outcome).

The LLM's ``metadata`` block is cross-checked against the confirmed set
(total == fed count, severity buckets sum to total, chains == chains fed) —
a model that silently drops a finding fails validation (retry, then loud).

Reports go to CLIENTS, so ``redact_text()`` scrubs the final Markdown
before it is written to disk — even a model that echoes a token cannot
leak it into the deliverable.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from scan_toolkit import artifacts
from scan_toolkit.agents.llm_client import LLMClient, LLMError  # noqa: F401
from scan_toolkit.agents.redact import redact_dict, redact_text
from scan_toolkit.models import (
    AttackChain,
    Engagement,
    Finding,
    FindingStatus,
    Severity,
)

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are the Report Agent for a mobile application security assessment \
toolkit.  You produce a client-ready security assessment report in Markdown \
from finalized (human-reviewed, CONFIRMED) findings.

RULES:
1. Every finding section MUST correspond to a CONFIRMED finding in the \
input.  NEVER include, mention, or hint at unconfirmed/draft findings.
2. Structure (exact headings, in order): # <client> Mobile Security \
Assessment, ## Executive Summary, ## Methodology, ## Findings (with ### \
subsections grouped Critical, then High, Medium, Low, Info — skip empty \
groups), ## Attack Chains, ## Remediation Roadmap, ## Appendix.
3. Executive Summary: 1 short paragraph for management (risk posture + \
counts), no jargon dumps.
4. Each finding: title, severity, confidence, CWE, affected component, \
description, evidence (code/endpoint proof), and specific remediation.
5. Attack Chains: one subsection per chain with its narrative; name the \
member finding titles.
6. Remediation Roadmap: prioritized ordered list (critical first), each item \
naming the finding it fixes.
7. Appendix: tool/methodology coverage notes from the input.
8. FORMATTING (machine-converted to PDF/DOCX — obey strictly): headings with \
# / ## / ### only; body paragraphs; unordered lists with "- "; ordered lists \
with "1. " numbering; fenced code blocks (```); **bold** sparingly; GitHub \
tables when comparing items.  NOTHING else: no HTML, no footnotes, no \
embedded images, no horizontal rules.
9. REDACTION: replace any token, password, key, email, or phone number with \
[REDACTED].
10. Output ONLY the JSON object below — the report goes in \
"report_markdown" as ONE string (escape newlines as \\n).

OUTPUT SCHEMA:
{
  "report_markdown": "<full markdown report>",
  "metadata": {
    "total_findings": <int>,
    "by_severity": {"critical": <n>, "high": <n>, "medium": <n>, "low": <n>, "info": <n>},
    "attack_chains": <int>
  }
}
"""

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def make_report_validator(n_findings: int, by_severity: dict[str, int],
                          n_chains: int):
    """Validate the report JSON against the confirmed set actually fed in."""

    def validate(data: dict) -> None:
        if not isinstance(data, dict):
            raise ValueError(f"Expected JSON object, got {type(data).__name__}")
        if not data.get("report_markdown") or not isinstance(
                data["report_markdown"], str):
            raise ValueError("missing or empty 'report_markdown'")
        meta = data.get("metadata")
        if not isinstance(meta, dict):
            raise ValueError("missing 'metadata' object")
        if meta.get("total_findings") != n_findings:
            raise ValueError(
                f"metadata.total_findings={meta.get('total_findings')!r} "
                f"!= {n_findings} confirmed findings fed in"
            )
        buckets = meta.get("by_severity")
        if not isinstance(buckets, dict):
            raise ValueError("metadata.by_severity must be an object")
        for sev in _SEVERITY_ORDER:
            if buckets.get(sev) != by_severity.get(sev, 0):
                raise ValueError(
                    f"metadata.by_severity[{sev}]={buckets.get(sev)!r} "
                    f"!= {by_severity.get(sev, 0)} confirmed"
                )
        if sum(buckets.get(s, 0) for s in _SEVERITY_ORDER) != n_findings:
            raise ValueError("metadata.by_severity does not sum to total_findings")
        if meta.get("attack_chains") != n_chains:
            raise ValueError(
                f"metadata.attack_chains={meta.get('attack_chains')!r} "
                f"!= {n_chains} chains fed in"
            )

    return validate


class ReportAgent:
    """Generate the client report Markdown for an engagement.

    Returns the written Markdown path.  Metadata is returned alongside so
    the CLI can print accurate counts without re-parsing the report.
    """

    def __init__(self, *, llm: LLMClient | None = None):
        # Stored, not defaulted: the LLM client is constructed lazily in
        # run() AFTER the confirmed-findings gate, so a missing API key
        # never masks the "review findings first" error.
        self._llm = llm

    def run(self, session: Session, engagement_id: str) -> tuple[Path, dict]:
        engagement = session.get(Engagement, engagement_id)
        if engagement is None:
            raise ValueError(f"engagement {engagement_id!r} not found")

        confirmed = (
            session.query(Finding)
            .filter(Finding.engagement_id == engagement_id)
            .filter(Finding.status == FindingStatus.confirmed)
            .order_by(Finding.created_at)
            .all()
        )
        total = (
            session.query(Finding)
            .filter(Finding.engagement_id == engagement_id)
            .count()
        )
        if not confirmed:
            if total > 0:
                raise ValueError(
                    f"engagement {engagement_id} has {total} finding(s) but "
                    "none is confirmed — review them first "
                    "('scan-toolkit review --engagement <id>')"
                )
            return self._write_empty(engagement)

        chains = (
            session.query(AttackChain)
            .filter(AttackChain.engagement_id == engagement_id)
            .order_by(AttackChain.created_at)
            .all()
        )
        by_severity = {s: 0 for s in _SEVERITY_ORDER}
        for f in confirmed:
            by_severity[f.severity.value] += 1

        log.info("Generating report for %s (%d confirmed, %d chains)",
                 engagement_id, len(confirmed), len(chains))
        user_message = self._build_prompt(engagement, confirmed, chains)
        llm = self._llm or LLMClient()
        result = llm.call(
            system=_SYSTEM_PROMPT,
            user_message=user_message,
            validate_fn=make_report_validator(
                len(confirmed), by_severity, len(chains)),
        )

        markdown = redact_text(result["report_markdown"])
        out_path = self._report_path(engagement_id, "md")
        out_path.write_text(markdown)
        log.info("Report written to %s", out_path)
        return out_path, result["metadata"]

    # ------------------------------------------------------------------

    @staticmethod
    def _report_path(engagement_id: str, ext: str) -> Path:
        reports_dir = artifacts.engagement_dir(engagement_id) / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        return reports_dir / f"report-{stamp}.{ext}"

    @staticmethod
    def _build_prompt(engagement: Engagement, confirmed: list[Finding],
                      chains: list[AttackChain]) -> str:
        sections = [
            f"## Client: {engagement.client_name}",
            f"## Platform: {engagement.app_platform.value if engagement.app_platform else 'unknown'}",
            f"## App version: {engagement.app_version or 'unknown'}",
            f"## Confirmed findings: {len(confirmed)}",
        ]
        for f in confirmed:
            d = f.to_dict()
            if d.get("evidence") and len(d["evidence"]) > 800:
                d["evidence"] = d["evidence"][:800] + "[…truncated]"
            sections.append(f"\n### Finding {f.id} [{f.severity.value}]")
            sections.append(json.dumps(redact_dict(d), indent=2))
        if chains:
            sections.append(f"\n## Attack chains: {len(chains)}")
            for c in chains:
                d = c.to_dict()
                sections.append(f"\n### Chain {c.id}")
                sections.append(json.dumps(redact_dict(d), indent=2))
                member_titles = [
                    f.title for f in confirmed if f.id in (d["finding_ids"] or [])]
                unconfirmed = [fid for fid in (d["finding_ids"] or [])
                               if fid not in {f.id for f in confirmed}]
                sections.append("Member titles (confirmed): "
                                + json.dumps(member_titles))
                if unconfirmed:
                    sections.append(
                        "WARNING: chain references unconfirmed findings "
                        f"{unconfirmed} — present this chain as PENDING "
                        "CONFIRMATION, not as a confirmed result.")
        else:
            sections.append("\n## Attack chains: none")
        return "\n".join(sections)

    def _write_empty(self, engagement: Engagement) -> tuple[Path, dict]:
        """Deterministic no-findings report — no LLM call needed."""
        markdown = (
            f"# {engagement.client_name or 'Client'} Mobile Security Assessment\n\n"
            "## Executive Summary\n\n"
            "No findings were recorded for this engagement. Either the "
            "assessment scope produced no findings, or no scan stages have "
            "been run yet.\n\n"
            "## Methodology\n\n"
            "No scan data available.\n\n"
            "## Findings\n\nNone.\n\n"
            "## Attack Chains\n\nNone.\n\n"
            "## Remediation Roadmap\n\nNone required.\n\n"
            "## Appendix\n\nNo tool output recorded.\n"
        )
        out_path = self._report_path(engagement.id, "md")
        out_path.write_text(markdown)
        metadata = {"total_findings": 0,
                    "by_severity": {s: 0 for s in _SEVERITY_ORDER},
                    "attack_chains": 0}
        log.info("Empty report written to %s", out_path)
        return out_path, metadata
