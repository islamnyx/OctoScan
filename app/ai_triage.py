"""Friend A: pre-filter + AI triage (FP filter).

Cost control (AI-PLAN): filter WITHOUT AI first (drop dev-only OSV deps,
test fixtures, info noise, ai-code-review meta rows), keep prioritize()
order, then send only top ~30 to the model, 5 per structured call.

Model is called ONLY through the core JSON helper (never directly).
On AIError every item -> review.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from app.models import Finding, Severity
from app.normalize import prioritize


# ---------------------------------------------------------------- locate


def _as_finding_parts(f: Finding | dict) -> tuple[dict, str]:
    if isinstance(f, dict):
        raw = f.get("raw") or {}
        loc = f.get("location") or ""
    else:
        raw = f.raw or {}
        loc = f.location or ""
    if not isinstance(raw, dict):
        raw = {}
    return raw, str(loc or "")


def locate(f: Finding | dict) -> tuple[str | None, int | None]:
    """File + line from f.raw["file"] or the "...#path:line" suffix of location.

    Returns (rel_path | None, line | None). Line is 1-based int when the
    suffix ends with :<digits>, else None.
    """
    raw, loc = _as_finding_parts(f)
    raw_file = raw.get("file")
    file: str | None = str(raw_file).strip() if raw_file else None
    if file == "":
        file = None

    # Line: prefer raw["line"] when it looks like an int, else location suffix.
    line: int | None = None
    raw_line = raw.get("line")
    if raw_line is not None:
        try:
            n = int(str(raw_line).strip())
            if n > 0:
                line = n
        except (ValueError, TypeError):
            line = None

    # Location suffix after the last "#": "…#app/routes/x.js:42" or "…#pkg-lock".
    frag = loc.split("#")[-1] if "#" in loc else ""
    if frag:
        rel, sep, tail = frag.rpartition(":")
        if sep and tail.strip().isdigit():
            if file is None:
                file = rel.strip() or None
            if line is None:
                try:
                    line = int(tail.strip())
                except ValueError:
                    line = None
        elif file is None:
            file = frag.strip() or None

    if file:
        file = file.replace("\\", "/").lstrip("./").strip() or None
    return file, line


# -------------------------------------------------------------- prefilter


def prefilter(findings: list[Finding], limit: int = 30) -> list[Finding]:
    """NO AI: drop dev-only deps, test fixtures, info noise, review meta rows.

    Keeps prioritize() order (dedupe + severity/cvss sort) and returns the
    top `limit` findings.
    """
    kept: list[Finding] = []
    for f in findings:
        raw = f.raw or {} if not isinstance(f, dict) else (f.get("raw") or {})
        if isinstance(raw, dict):
            if raw.get("scope") == "dev":
                continue
            if raw.get("likely_test_fixture"):
                continue
        sev = f.severity if not isinstance(f, dict) else f.get("severity")
        # Finding.severity is a Severity enum; dicts may carry the raw string.
        sev_val = sev.value if isinstance(sev, Severity) else str(sev or "")
        if sev_val == Severity.info.value:
            continue
        scanner = f.scanner if not isinstance(f, dict) else f.get("scanner")
        if str(scanner or "") == "ai-code-review":
            continue
        kept.append(f)  # type: ignore[arg-type]
    return prioritize(kept)[: max(0, limit)]


# ------------------------------------------------------------ code window


def code_window(workdir: Path | str, rel: str | None, line: int | None, radius: int = 20) -> str:
    """~40 numbered lines "N: code" around `line`. "" if file missing.

    Out-of-range lines clamp; path traversal outside workdir -> "".
    """
    if not rel:
        return ""
    try:
        base = Path(workdir).resolve()
        target = (base / str(rel)).resolve()
        if target != base and base not in target.parents:
            return ""
        if not target.is_file():
            return ""
        text = target.read_text(errors="ignore")
    except Exception:
        return ""
    lines = text.splitlines()
    if not lines:
        return ""
    n = len(lines)
    try:
        ln = int(line or 0)
    except (ValueError, TypeError):
        ln = 0
    if ln < 1 or ln > n:
        # No usable line: head of file (still useful for lockfiles/manifests).
        ln = min(max(1, n // 2), n) if False else 0
        if ln == 0:
            start, end = 1, min(n, 2 * radius + 1)
            return "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
    start = max(1, ln - radius)
    end = min(n, ln + radius)
    # Extend short edges toward a full ~40-line window when possible.
    want = 2 * radius + 1
    if end - start + 1 < want:
        if start == 1:
            end = min(n, start + want - 1)
        elif end == n:
            start = max(1, end - want + 1)
    return "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))


# ----------------------------------------------------------------- triage

TRIAGE_SYSTEM = (
    "You are a senior application-security triager. For each finding decide "
    "whether the scanner hit is a REAL vulnerability, a FALSE_POSITIVE "
    "(test fixture, dev-only code, unreachable sample, scanner misfire), or "
    "REVIEW when the code is inconclusive. Use the code window as ground "
    "truth, not the scanner title alone. Reply with JSON only."
)


class TriageItem(BaseModel):
    finding_id: str
    verdict: Literal["real", "false_positive", "review"]
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(max_length=500)


class TriageBatch(BaseModel):
    items: list[TriageItem]


def _finding_text(f: Finding, workdir: Path) -> str:
    file, line = locate(f)
    code = code_window(workdir, file, line, radius=20) if file else ""
    desc = (f.description or "")[:600]
    ev = (f.evidence or "")[:400]
    loc = f.location or ""
    header = (
        f"ID: {f.id}\nTitle: {f.title}\nSeverity: {f.severity.value} | "
        f"Scanner: {f.scanner}\nFile: {file or '?'} | Line: {line or '?'} | "
        f"Location: {loc}\nDescription: {desc}\nEvidence: {ev}"
    )
    if code:
        return header + f"\nCode ({file}:{line}):\n{code}"
    return header + "\nCode: (unavailable)"


def triage(findings: list[Finding], workdir: Path | str) -> list[dict]:
    """Triage findings in batches of 5 via app.ai_core.call_json.

    Returns [{"finding_id", "verdict", "confidence", "reason"}] in input
    order. AIError -> every item is review/0.0/"AI unavailable: ...".
    """
    if not findings:
        return []
    from app import ai_core  # deferred so tests can monkeypatch app.ai_core

    base = Path(workdir)
    out: list[dict] = []
    for start in range(0, len(findings), 5):
        batch = findings[start : start + 5]
        blocks = [_finding_text(f, base) for f in batch]
        user = (
            "Triage these findings (5 max). For each return finding_id "
            "(exact ID above), verdict real|false_positive|review, "
            "confidence 0..1, reason (one sentence, cite the code):\n\n"
            + "\n\n---\n\n".join(blocks)
        )
        try:
            obj, _meta = ai_core.call_json(
                [
                    {"role": "system", "content": TRIAGE_SYSTEM},
                    {"role": "user", "content": user},
                ],
                TriageBatch,
                max_tokens=1500,
                purpose="triage",
            )
            by_id = {it.finding_id: it for it in obj.items}
            for f in batch:
                it = by_id.get(f.id)
                if it is None:
                    out.append({
                        "finding_id": f.id,
                        "verdict": "review",
                        "confidence": 0.0,
                        "reason": "No verdict returned for this finding.",
                    })
                    continue
                try:
                    conf = float(it.confidence)
                except (ValueError, TypeError):
                    conf = 0.0
                conf = max(0.0, min(1.0, conf))
                out.append({
                    "finding_id": it.finding_id,
                    "verdict": it.verdict,
                    "confidence": conf,
                    "reason": str(it.reason or "")[:500],
                })
        except ai_core.AIError as exc:
            msg = f"AI unavailable: {exc}"[:500]
            for f in batch:
                out.append({
                    "finding_id": f.id,
                    "verdict": "review",
                    "confidence": 0.0,
                    "reason": msg,
                })
    return out
