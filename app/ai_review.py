"""AI code review (Phase 2): the model reads selected source files,
finds vulnerabilities itself, then triage summarizes everything.

Bounded by design: a scorer picks the most security-relevant files,
per-file/total byte caps keep prompts inside context windows and
costs predictable. Static scanners still run first — AI complements
them (logic flaws, auth gaps, insecure patterns they miss).

Cloud providers receive code excerpts. Local providers
(Ollama/LM Studio) keep everything on the user's machine —
the dashboard says so next to the AI config.
"""
from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from pathlib import Path

from app import ai as ai_layer
from app.config import settings
from app.models import Finding, Severity
from app.repo import iter_repo_files

REVIEW_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
    ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c", ".h",
    ".rs", ".kt", ".swift",
}

HOT_PATH_RE = re.compile(
    r"(auth|login|session|secur|config|setting|valid|sanit|guard|verify|"
    r"passwd|password|crypt|token|secret|api|route|"
    r"control|middle|admin|upload|db|sql|pay|checkout|user|account|"
    r"permission|role|oauth|jwt|key|credential|private)",
    re.I,
)
COLD_RE = re.compile(r"(test|spec|mock|fixture|seed|migrat|/i18n/|/locale/)", re.I)
SKIP_FILE_RE = re.compile(
    r"(\.min\.js$|\.bundle\.js$|package-lock\.json$|yarn\.lock$|"
    r"poetry\.lock$|\.map$|\.d\.ts$|_test\.go$|\.snap$)",
    re.I,
)

SEV_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
}

REVIEW_SYSTEM = (
    "You are a senior application-security code reviewer. Read the code, "
    "find real vulnerabilities (injection, auth bypass, broken access "
    "control, secrets, crypto flaws, SSRF, path traversal, XSS, insecure "
    "deserialization, race conditions, missing validation). Ignore style. "
    "Do not invent issues that the code does not show. "
    "Reply with a JSON array only: "
    '[{"title": "...", "severity": "critical|high|medium|low|info", '
    '"line": 12, "description": "...", "fix": "..."}]. '
    "Empty array [] when nothing is wrong."
)


def _score(path: Path, root: Path, size: int) -> int | None:
    rel = str(path.relative_to(root))
    if SKIP_FILE_RE.search(path.name):
        return None
    if path.suffix.lower() not in REVIEW_EXTS:
        return None
    score = 0
    if HOT_PATH_RE.search(rel):
        score += 3
    if COLD_RE.search(rel):
        score -= 2
    if 500 <= size <= 30_000:
        score += 1
    if size > 100_000:
        score -= 3
    return score


def pick_review_files(root: Path) -> list[tuple[Path, int]]:
    max_files = max(1, settings.ai_review_max_files)
    max_bytes = max(10_000, settings.ai_review_max_bytes)
    scored: list[tuple[int, int, Path]] = []
    for p in iter_repo_files(root):
        try:
            size = p.stat().st_size
        except Exception:
            continue
        s = _score(p, root, size)
        if s is None:
            continue
        scored.append((s, -size, p))
    scored.sort(reverse=True)
    picked: list[tuple[Path, int]] = []
    total = 0
    for _, _, p in scored[: max_files * 3]:
        if len(picked) >= max_files:
            break
        try:
            size = p.stat().st_size
        except Exception:
            continue
        if total + min(size, 15_000) > max_bytes and picked:
            break
        picked.append((p, size))
        total += min(size, 15_000)
    return picked


def _excerpt(path: Path, per_file_cap: int = 15_000) -> str:
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return ""
    if len(text) <= per_file_cap:
        return text
    head = per_file_cap * 2 // 3
    tail = per_file_cap - head
    return text[:head] + f"\n… [truncated {len(text) - per_file_cap} chars] …\n" + text[-tail:]


def _parse_review_reply(reply: str) -> list[dict]:
    start = reply.find("[")
    end = reply.rfind("]")
    if start == -1 or end <= start:
        return []
    try:
        items = json.loads(reply[start : end + 1])
    except Exception:
        return []
    return [i for i in items if isinstance(i, dict)]


def _chat_once(messages: list[dict[str, str]], cfg: dict[str, str]) -> str:
    return ai_layer.chat_complete(
        messages,
        cfg=cfg,
        max_tokens=settings.ai_review_max_tokens,
        temperature=0.1,
    )


def _chat_with_retry(messages: list[dict[str, str]], cfg: dict[str, str]) -> tuple[str, float, int]:
    """One retry on rate-limit (429), honoring the server's 'try again in Xs'.

    Free tiers (e.g. Groq 1000 output-tokens/min) 429 constantly on
    back-to-back calls — without this, half the files silently fail.
    Returns (reply, seconds_waited, attempts). Raises on final failure.
    """
    try:
        return _chat_once(messages, cfg), 0.0, 1
    except RuntimeError as exc:
        if "429" not in str(exc):
            raise
        m = re.search(r"try again in ([\d.]+)s", str(exc))
        wait = min(float(m.group(1)) + 1.0 if m else 12.0, 30.0)
        time.sleep(wait)
        return _chat_once(messages, cfg), wait, 2


def review_codebase(
    root: Path,
    repo_url: str = "",
    check: Callable[[], str | None] | None = None,
) -> list[Finding]:
    """Ask the configured model to read files and report vulns as Findings.

    `check` (optional) is called between files and returns "pause",
    "finish" or None — lets long reviews stop promptly on user request.
    """
    cfg = ai_layer.load_config()
    if not (cfg.get("base_url") and cfg.get("model")):
        raise RuntimeError("AI base_url/model not configured")
    picked = pick_review_files(root)
    if not picked:
        return [
            Finding(
                scanner="ai-code-review",
                title="AI review skipped: no reviewable code files",
                severity=Severity.info,
                description="No source files with reviewable extensions found.",
                location=repo_url or str(root),
            )
        ]
    findings: list[Finding] = []
    # Manifest: proof of what the model actually read. Shown in the
    # dashboard so "AI reviewed" is auditable, not a black box.
    manifest: list[str] = []
    total_chars = 0
    for path, _size in picked:
        if check is not None:
            try:
                stop = check()
            except Exception:
                stop = None
            if stop in ("pause", "finish"):
                manifest.append(f"stopped early by user ({stop}) — remaining files skipped")
                break
        rel = str(path.relative_to(root))
        code = _excerpt(path)
        if not code.strip():
            manifest.append(f"{rel}: skipped (empty)")
            continue
        user = (
            f"File: {rel}\n```\n{code}\n```\n"
            "List vulnerabilities in this file as a JSON array only."
        )
        t0 = time.time()
        try:
            reply, waited, attempts = _chat_with_retry(
                [
                    {"role": "system", "content": REVIEW_SYSTEM},
                    {"role": "user", "content": user},
                ],
                cfg,
            )
            dt = time.time() - t0
            total_chars += len(code)
        except Exception as exc:
            manifest.append(f"{rel}: FAILED ({len(code)} chars sent, {str(exc)[:120]})")
            findings.append(
                Finding(
                    scanner="ai-code-review",
                    title=f"AI review failed for {rel}",
                    severity=Severity.info,
                    description=f"Model call failed: {exc}"[:400],
                    location=f"{repo_url}#{rel}" if repo_url else rel,
                )
            )
            continue
        items = _parse_review_reply(reply)
        manifest.append(
            f"{rel}: read {len(code)} chars in {dt:.1f}s "
            f"(attempts={attempts}, waited={waited:.0f}s) -> {len(items)} vuln(s)"
        )
        for item in items[:10]:
            title = str(item.get("title") or "AI finding").strip()[:160] or "AI finding"
            sev = SEV_MAP.get(str(item.get("severity") or "").strip().lower(), Severity.medium)
            try:
                line = int(item.get("line") or 0)
            except Exception:
                line = 0
            loc = f"{repo_url}#{rel}:{line}" if repo_url else (f"{rel}:{line}" if line else rel)
            findings.append(
                Finding(
                    scanner="ai-code-review",
                    title=f"{title} ({rel})",
                    severity=sev,
                    description=str(item.get("description") or title)[:800],
                    evidence=f"{rel}:{line}" if line else rel,
                    location=loc,
                    recommendation=str(item.get("fix") or "Review and remediate.")[:600],
                    raw={"file": rel, "line": line or None, "ai": True},
                )
            )
        if len(findings) >= 50:
            break
    vuln_count = len([f for f in findings if f.scanner == "ai-code-review" and not f.title.startswith("AI review failed")])
    if vuln_count == 0 and not [f for f in findings if f.title.startswith("AI review failed")]:
        findings.append(
            Finding(
                scanner="ai-code-review",
                title="AI review: no issues found in sampled files",
                severity=Severity.info,
                description=(
                    "Model read %d file(s) and reported nothing. "
                    "Sampling is bounded — not a clean bill of health."
                    % len(picked)
                ),
                location=repo_url or str(root),
            )
        )
    # Always attach the manifest + model id: what was actually read.
    failed = [m for m in manifest if "FAILED" in m]
    findings.append(
        Finding(
            scanner="ai-code-review",
            title=(
                f"AI review manifest: {len(picked)} file(s) sampled, "
                f"{total_chars} chars read via {cfg.get('provider', '')}/{cfg.get('model', '')} "
                f"({vuln_count} vuln(s), {len(failed)} failed)"
            ),
            severity=Severity.info,
            description="Per-file audit trail:\n" + "\n".join(manifest)[:2500],
            location=repo_url or str(root),
            raw={"manifest": manifest, "model": cfg.get("model", ""),
                  "provider": cfg.get("provider", ""), "chars_read": total_chars},
        )
    )
    return findings
