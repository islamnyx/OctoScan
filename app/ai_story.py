"""Attack story + launch verdict (docs/NEXT.md "Friend B").

attack_story(): ONE ai_core.call_json call chains the real findings into
how an attacker would break in, in plain words for a startup founder, plus
a ready / not_ready verdict and blockers. The verdict is kept honest by a
rule: any critical/high real finding means not_ready, whatever the model
says (patches are suggestions until a human applies them).
AIError -> rule-based verdict, story = "AI unavailable: ...".
"""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, Field

from app import ai_core

MAX_FINDINGS = 15
SEVERE = ("critical", "high")
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class StoryReply(BaseModel):
    verdict: Literal["ready", "not_ready"]
    blockers: list[str] = Field(default_factory=list, description="max 6 short 'what + where' items")
    attack_story: str = Field(max_length=4000)


SYSTEM = (
    "You are a penetration tester explaining results to a startup founder who is about to "
    "launch. Chain the confirmed findings into ONE realistic attack path: how an attacker gets "
    "in, what they reach next, what they finally steal or break. Plain words, short sentences, "
    "explain any jargon, 120-220 words, no markdown. Only use the findings given; never invent "
    "vulnerabilities. Findings marked fixed_and_verified have a re-scanned patch that is NOT "
    "applied yet, so they still block launch until merged. verdict = not_ready if any "
    "critical or high finding is present, else ready. blockers = up to 6 short items "
    "'what + where' ordered by risk."
)


def _severe(real: list[dict]) -> list[dict]:
    return [r for r in real if str(r.get("severity") or "").lower() in SEVERE]


def _title(r: dict) -> str:
    where = f" ({r['file']}:{r['line']})" if r.get("file") and r.get("line") else ""
    return f"{str(r.get('title') or 'finding')[:160]}{where}"


def rule_based(real: list[dict], note: str = "") -> dict:
    severe = _severe(real)
    return {
        "verdict": "not_ready" if severe else "ready",
        "blockers": [_title(r) for r in severe[:6]],
        "attack_story": note or (
            f"{len(real)} confirmed finding(s), {len(severe)} critical/high." if real
            else "No confirmed vulnerabilities in the scanned code."),
    }


def attack_story(real: list[dict], target: str) -> dict:
    """real: triage rows with verdict "real" (+ title, severity, file, line).
    Returns {"verdict": "ready|not_ready", "blockers": [str], "attack_story": str}."""
    real = [r for r in (real or []) if isinstance(r, dict)]
    if not real:
        return rule_based([])
    top = sorted(real, key=lambda r: SEV_RANK.get(str(r.get("severity") or "").lower(), 5))[:MAX_FINDINGS]
    items = [{
        "title": str(r.get("title") or "")[:200],
        "severity": r.get("severity"),
        "where": f"{r.get('file') or '?'}:{r.get('line') or '?'}",
        "why_real": str(r.get("reason") or "")[:300],
        "fixed_and_verified": bool(r.get("fixed_and_verified")),
    } for r in top]
    user = json.dumps({"target": target, "confirmed_findings": items,
                       "not_shown": max(0, len(real) - len(top))})
    try:
        reply, _meta = ai_core.call_json(
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
            StoryReply, max_tokens=1200, purpose="story")
    except ai_core.AIError as exc:
        return rule_based(real, f"AI unavailable: {str(exc)[:200]}")
    blockers = [str(b).strip()[:300] for b in reply.blockers if str(b).strip()][:6]
    verdict = reply.verdict
    severe = _severe(real)
    if severe and verdict == "ready":  # the rule wins over the model
        verdict = "not_ready"
        blockers = blockers or [_title(r) for r in severe[:6]]
    if verdict == "not_ready" and not blockers:
        blockers = [_title(r) for r in (severe or real)[:6]]
    return {"verdict": verdict, "blockers": blockers, "attack_story": reply.attack_story.strip()}
