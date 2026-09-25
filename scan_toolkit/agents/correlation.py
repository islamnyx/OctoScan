"""Correlation Agent — cross-agent dedup + attack-chain construction.

Runs ONCE all stages for an engagement report done (see ``stages_done()``).
Unlike the per-stage agents it reads Finding rows from the DB (not stage IR),
sends the full set to the LLM per agent_prompts.md Section 6, and writes back:

  * duplicates -> ``status=duplicate`` on the loser (rows are NEVER deleted;
    the audit trail stays intact), loser id appended to the winner's
    ``related_finding_ids``.
  * attack_chains -> new ``AttackChain`` rows.
  * related_updates -> union into ``Finding.related_finding_ids``.

Only findings with status new/confirmed/needs_review are fed in — already
dispositioned rows (duplicate/false_positive) stay out of the LLM's view.
"""

from __future__ import annotations

import json
import logging

from sqlalchemy.orm import Session

from scan_toolkit.agents.llm_client import LLMClient, LLMError  # noqa: F401
from scan_toolkit.agents.redact import redact_dict
from scan_toolkit.engagements import advance_engagement_status
from scan_toolkit.models import (
    AttackChain,
    Engagement,
    EngagementStatus,
    Finding,
    FindingStatus,
    Severity,
)

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are the Correlation Agent for a mobile application security assessment \
toolkit.  You run after all scan stages for an engagement are complete.  You \
receive ALL findings from ALL agents (static, sca, api, dynamic).

RULES:
1. Output ONLY a JSON object matching the schema below.
2. DEDUPLICATE ACROSS AGENTS: if two findings describe the same underlying \
issue (e.g. static flagged insecure storage AND dynamic observed the write), \
emit one duplicates entry.  keep_id = the finding with BETTER evidence \
(dynamic observation beats static pattern-match); remove_id = the other.
3. BUILD ATTACK CHAINS: identify findings that combine into a more severe \
vulnerability than any one alone (e.g. exported activity + missing auth + \
sensitive data exposure = data exfiltration).  Each chain needs >= 2 finding \
ids and a narrative a reviewer can follow step by step.
4. COMBINED SEVERITY must be >= the highest severity of the chain's members \
(chains escalate, never downgrade).
5. related_updates link findings that are related but not duplicates \
(same component, same CWE family, chain-adjacent).
6. Every id you reference MUST come from the input.  NEVER invent finding ids.
7. If nothing correlates, return {"duplicates": [], "attack_chains": [], \
"related_updates": [], "notes": "..."}.
8. REDACTION: replace any token, password, key, email, or phone number you \
see with [REDACTED].

OUTPUT SCHEMA:
{
  "duplicates": [
    {"keep_id": "<finding_id>", "remove_id": "<finding_id>", "reason": "..."}
  ],
  "attack_chains": [
    {
      "finding_ids": ["<id1>", "<id2>", ...],
      "narrative": "<how these findings chain together>",
      "combined_severity": "critical|high|medium|low"
    }
  ],
  "related_updates": [
    {"finding_id": "<id>", "related_finding_ids": ["<id1>", "<id2>"]}
  ],
  "notes": "<optional string or null>"
}
"""

_VALID_SEVERITIES = {s.value for s in Severity}
_SEVERITY_RANK = {s.value: i for i, s in enumerate(
    [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical])}

# Findings worth correlating — dispositioned rows stay out of the LLM's view.
_CORRELATABLE = [
    FindingStatus.new, FindingStatus.confirmed, FindingStatus.needs_review,
]


def make_validator(known_ids: frozenset[str]):
    """Build a validate_fn closing over the engagement's real finding ids.

    Missing top-level keys default to [] (lenient); entry shape, id
    existence, chain length, and severity values are strict — violations
    trigger the LLM retry, then fail loudly.
    """

    def validate(data: dict) -> None:
        if not isinstance(data, dict):
            raise ValueError(f"Expected JSON object, got {type(data).__name__}")

        for dup in data.get("duplicates", []):
            if not isinstance(dup, dict):
                raise ValueError("duplicates entries must be objects")
            for key in ("keep_id", "remove_id"):
                if not dup.get(key):
                    raise ValueError(f"duplicates entry missing '{key}'")
                if dup[key] not in known_ids:
                    raise ValueError(f"unknown finding id {dup[key]!r} in duplicates")
            if dup["keep_id"] == dup["remove_id"]:
                raise ValueError("duplicates keep_id and remove_id must differ")

        for i, chain in enumerate(data.get("attack_chains", [])):
            if not isinstance(chain, dict):
                raise ValueError(f"attack_chains[{i}] must be an object")
            ids = chain.get("finding_ids")
            if not isinstance(ids, list) or len(ids) < 2:
                raise ValueError(f"attack_chains[{i}] needs >= 2 finding_ids")
            for fid in ids:
                if fid not in known_ids:
                    raise ValueError(f"unknown finding id {fid!r} in attack_chains[{i}]")
            if chain.get("combined_severity") not in _VALID_SEVERITIES:
                raise ValueError(
                    f"attack_chains[{i}].combined_severity invalid: "
                    f"{chain.get('combined_severity')!r}"
                )
            if not chain.get("narrative"):
                raise ValueError(f"attack_chains[{i}] missing narrative")

        for rel in data.get("related_updates", []):
            if not isinstance(rel, dict):
                raise ValueError("related_updates entries must be objects")
            if rel.get("finding_id") not in known_ids:
                raise ValueError(
                    f"unknown finding id {rel.get('finding_id')!r} in related_updates"
                )
            rids = rel.get("related_finding_ids", [])
            if not isinstance(rids, list) or any(r not in known_ids for r in rids):
                raise ValueError(
                    f"related_updates for {rel.get('finding_id')!r} "
                    "references unknown finding ids"
                )

    return validate


def stages_done(session: Session, engagement_id: str) -> tuple[bool, str]:
    """Readiness gate: all queued jobs settled + at least one finding.

    Returns (True, summary) when correlation may run, else (False, reason).
    A FAILED job does not block (its stage IR is still stored); PENDING or
    RUNNING jobs do.  This is what "all stages report done" means — stages
    that never ran (e.g. dynamic on an iOS engagement) don't block either.
    """
    from scan_toolkit.queue import JobStatus, ScanJob

    jobs = session.query(ScanJob).filter(
        ScanJob.engagement_id == engagement_id).all()
    unsettled = [j for j in jobs
                 if j.status in (JobStatus.pending, JobStatus.running)]
    if unsettled:
        return False, (
            f"{len(unsettled)} job(s) still "
            f"{'/'.join(sorted({j.status.value for j in unsettled}))} — "
            "run 'scan-toolkit worker' first"
        )
    count = session.query(Finding).filter(
        Finding.engagement_id == engagement_id).count()
    if count == 0:
        return False, "no findings yet — run a stage with --analyze first"
    by_agent = _coverage(session, engagement_id)
    return True, f"{count} findings ({by_agent})"


def _coverage(session: Session, engagement_id: str) -> str:
    rows = session.query(Finding).filter(
        Finding.engagement_id == engagement_id).all()
    counts: dict[str, int] = {}
    for f in rows:
        key = f.source_agent.value
        counts[key] = counts.get(key, 0) + 1
    return ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))


class CorrelationAgent:
    """Correlate an engagement's findings -> dedup + AttackChain rows."""

    def __init__(self, *, llm: LLMClient | None = None):
        self._llm = llm or LLMClient()

    def run(self, session: Session, engagement_id: str) -> dict:
        """Run correlation. Returns a summary dict (chains/duplicates/related).

        Findings with zero correlatable rows skip the LLM call and return an
        empty summary.  Raises ValueError if the readiness gate fails.
        """
        ok, reason = stages_done(session, engagement_id)
        if not ok:
            raise ValueError(f"engagement {engagement_id} not ready: {reason}")
        log.info("Correlating engagement %s (%s)", engagement_id, reason)

        findings = (
            session.query(Finding)
            .filter(Finding.engagement_id == engagement_id)
            .filter(Finding.status.in_(_CORRELATABLE))
            .order_by(Finding.created_at)
            .all()
        )
        if not findings:
            log.info("No correlatable findings for %s — skipping LLM call", engagement_id)
            return {"chains": [], "duplicates_marked": 0, "related_updated": 0}

        known_ids = frozenset(f.id for f in findings)
        user_message = self._build_prompt(engagement_id, findings)
        result = self._llm.call(
            system=_SYSTEM_PROMPT,
            user_message=user_message,
            validate_fn=make_validator(known_ids),
        )
        return self._persist(session, engagement_id, findings, result)

    # ------------------------------------------------------------------

    @staticmethod
    def _build_prompt(engagement_id: str, findings: list[Finding]) -> str:
        """Serialise findings with deterministic redaction applied FIRST."""
        sections = [f"## Engagement: {engagement_id}",
                    f"## Finding count: {len(findings)}"]
        for f in findings:
            d = f.to_dict()
            # Bound prompt size — full evidence lives in the DB for review.
            if d.get("evidence") and len(d["evidence"]) > 500:
                d["evidence"] = d["evidence"][:500] + "[…truncated]"
            if d.get("description") and len(d["description"]) > 800:
                d["description"] = d["description"][:800] + "[…truncated]"
            scrubbed = redact_dict(d)
            sections.append(f"\n### Finding {f.id}")
            sections.append(json.dumps(scrubbed, indent=2))
        return "\n".join(sections)

    @staticmethod
    def _persist(
        session: Session,
        engagement_id: str,
        findings: list[Finding],
        result: dict,
    ) -> dict:
        by_id = {f.id: f for f in findings}
        # Validator guarantees membership; assert defensively anyway.
        chains: list[AttackChain] = []
        duplicates_marked = 0

        for dup in result.get("duplicates", []):
            keep, remove = by_id[dup["keep_id"]], by_id[dup["remove_id"]]
            remove.status = FindingStatus.duplicate
            keep.related_finding_ids = sorted(
                set(keep.related_finding_ids or []) | {remove.id})
            session.add(remove)
            session.add(keep)
            duplicates_marked += 1
            log.info("Marked %s as duplicate of %s (%s)",
                     remove.id, keep.id, dup.get("reason", "")[:100])

        for chain in result.get("attack_chains", []):
            members = [by_id[fid] for fid in chain["finding_ids"]]
            combined = Severity(chain["combined_severity"])
            peak = max(_SEVERITY_RANK[m.severity.value] for m in members)
            if _SEVERITY_RANK[combined.value] < peak:
                log.warning(
                    "Chain severity %s below member peak — persisting as "
                    "returned (reviewer decides)", combined.value)
            record = AttackChain(
                engagement_id=engagement_id,
                finding_ids=list(chain["finding_ids"]),
                narrative=chain["narrative"],
                combined_severity=combined,
            )
            session.add(record)
            chains.append(record)

        related_updated = 0
        for rel in result.get("related_updates", []):
            target = by_id[rel["finding_id"]]
            merged = sorted(set(target.related_finding_ids or [])
                            | set(rel.get("related_finding_ids", []))
                            - {target.id})
            if merged != (target.related_finding_ids or []):
                target.related_finding_ids = merged
                session.add(target)
                related_updated += 1

        session.flush()
        engagement = session.get(Engagement, engagement_id)
        if engagement is not None:
            try:
                advance_engagement_status(
                    session, engagement, EngagementStatus.reviewing)
            except ValueError:
                pass  # already past reviewing — correlation is idempotent-safe
        return {
            "chains": [c.to_dict() for c in chains],
            "duplicates_marked": duplicates_marked,
            "related_updated": related_updated,
        }
