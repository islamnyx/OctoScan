"""AI code review (Phase 2): the model reads selected source files,
finds vulnerabilities itself, then triage summarizes everything.

Two-phase design (2026-09-14): Phase 1 shows the model the full file
listing and it nominates the files most likely to hold vulns; Phase 2
reviews those files TOGETHER with the heuristic scorer's picks in small
batches — related files in one prompt (views+urls+models) give the model
the context it needs to connect a sink to a route.

Bounded by design: file/byte caps keep prompts inside context windows
and costs predictable. Static scanners still run first — AI complements
them (logic flaws, auth gaps, insecure patterns they miss).

Cloud providers receive code excerpts. Local providers
(Ollama/LM Studio) keep everything on the user's machine —
the dashboard says so next to the AI config.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from collections.abc import Callable
from pathlib import Path

from app import ai as ai_layer
from app import ai_core as ai_layer_core
from app.config import settings
from app.models import Finding, Severity
from app.repo import is_vendored, iter_repo_files

REVIEW_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
    ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c", ".h",
    ".rs", ".kt", ".swift",
}

HOT_PATH_RE = re.compile(
    r"(auth|login|session|secur|config|setting|valid|sanit|guard|verify|"
    r"passwd|password|crypt|token|secret|api|route|"
    r"view|controller|handler|endpoint|servlet|resource|form|serial|"
    r"exec|eval|query|search|upload|shell|cmd|command|"
    r"control|middle|admin|db|sql|pay|checkout|user|account|"
    r"permission|role|oauth|jwt|key|credential|private)",
    re.I,
)
COLD_RE = re.compile(r"(test|spec|mock|fixture|seed|migrat|/i18n/|/locale/)", re.I)
SKIP_FILE_RE = re.compile(
    r"(\.min\.js$|\.bundle\.js$|package-lock\.json$|yarn\.lock$|"
    r"poetry\.lock$|\.map$|\.d\.ts$|_test\.go$|\.snap$)",
    re.I,
)

# Sink scan (deterministic pre-pass): files containing dangerous call
# patterns get a nomination boost regardless of name/size. This is what
# pulls "source/low.php"-style files (600B, anonymous name) into review —
# on DVWA every classic vuln (exec/fi/sqli/upload) lives in exactly such
# files and both the scorer and the model's nomination skipped them.
SINK_CALL_RE = re.compile(
    r"(shell_exec|exec\s*\(|system\s*\(|passthru|popen|proc_open|"
    r"\binclude\b|\brequire\b|move_uploaded_file|"
    r"header\s*\(\s*['\"]Location|eval\s*\(|assert\s*\(|unserialize\s*\(|"
    r"pickle\.loads|yaml\.load\b|"
    r"cursor\.execute|executemany|os\.system|subprocess\.(call|run|Popen)|"
    r"mysqli_query|mysql_query|pg_query|->query\s*\(|sqlite_query)",
    re.I,
)
USER_INPUT_RE = re.compile(
    r"(\$_(GET|POST|REQUEST|COOKIE|SERVER)|request\.(GET|POST|args|form|data|json|values)|"
    r"params\[|query_params|os\.environ)",
    re.I,
)
XSS_SINK_RE = re.compile(
    r"(echo\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)|print\s+[^;]*\$_(GET|POST|REQUEST)|"
    r"innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)",
    re.I,
)

# Extra window anchors for _excerpt: Express/Flask/Spring route handlers
# and Node request input (USER_INPUT_RE is PHP/Python-centric).
WINDOW_HINT_RE = re.compile(
    r"(\b(app|router)\.(get|post|put|patch|delete|all|use)\s*\(|@app\.route|"
    r"@(Get|Post|Put|Delete|Request)Mapping|req\.(body|query|params|cookies|headers)|"
    r"\$_(GET|POST|REQUEST|COOKIE)|request\.(GET|POST|args|form|json))",
    re.I,
)
EXCERPT_CAP = 8_000  # chars per file sent to the model
WINDOW_RADIUS = 15  # lines around each anchor (~30-line windows)

SEV_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
}

TRIAGE_SYSTEM = (
    "You are a senior application-security auditor triaging a repository. "
    "You get a listing of source files (path + size). Nominate the files "
    "most likely to contain REAL vulnerabilities: injection (SQL/cmd), "
    "broken auth or access control, crypto flaws, SSRF, path traversal, "
    "XSS sinks, insecure deserialization, hardcoded secrets. "
    "Skip tests, migrations, docs, configs without logic, vendored code. "
    "Reply with a JSON array of paths ONLY, most suspicious first, "
    'max {limit} entries: ["src/app/views.py", "src/auth.py"]. '
    "Empty array [] if nothing looks reviewable."
)

REVIEW_SYSTEM = (
    "You are a senior application-security code reviewer. You are given "
    "one or more related source files. Read the code, find real "
    "vulnerabilities (injection, auth bypass, broken access control, "
    "secrets, crypto flaws, SSRF, path traversal, XSS, insecure "
    "deserialization, race conditions, missing validation). Cross-reference "
    "files (routes -> handlers -> models) before deciding. Ignore style. "
    "Do not invent issues that the code does not show. "
    'Each code line starts with its line number ("12: code"); use that '
    'number for "line". "…" marks lines not sent. [REDACTED] marks a secret '
    "literal removed before review: still report it as a hardcoded secret. "
    "Reply with a JSON array only, each item: "
    '{"file": "<path as given>", "title": "...", "severity": '
    '"critical|high|medium|low|info", "line": 12, "description": "...", '
    '"fix": "..."}. '
    "Empty array [] when nothing is wrong."
)


def _excerpt(path: Path, per_file_cap: int = EXCERPT_CAP) -> str:
    """Line-numbered code for the prompt ("12: code").

    Small files go whole. Bigger ones send only ~30-line windows around
    sinks, user input and route handlers (AGENTS.md: small windows, not
    whole files), then the file head if nothing matched. Secrets are
    redacted later by app.ai_core on every outgoing message.
    """
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return ""
    numbered = [f"{i + 1}: {line}" for i, line in enumerate(lines)]
    whole = "\n".join(numbered)
    if len(whole) <= per_file_cap:
        return whole
    hits = [
        i for i, line in enumerate(lines)
        if SINK_CALL_RE.search(line) or XSS_SINK_RE.search(line) or WINDOW_HINT_RE.search(line)
    ]
    spans: list[list[int]] = []
    for i in hits:
        lo, hi = max(0, i - WINDOW_RADIUS), min(len(lines), i + WINDOW_RADIUS + 1)
        if spans and lo <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], hi)
        else:
            spans.append([lo, hi])
    if not spans:
        spans = [[0, len(lines)]]
    out: list[str] = []
    size = 0
    for lo, hi in spans:
        if lo > 0 and (not out or out[-1] != "…"):
            out.append("…")
        for i in range(lo, hi):
            if size + len(numbered[i]) > per_file_cap:
                out.append(f"… [{len(lines) - i} more lines not sent]")
                return "\n".join(out)
            out.append(numbered[i])
            size += len(numbered[i]) + 1
    if spans[-1][1] < len(lines):
        out.append("…")
    return "\n".join(out)


def _parse_json_array(reply: str) -> list:
    """Any JSON array in a model reply (<think>/fences handled), else []."""
    try:
        return ai_layer_core.parse_json_loose(reply, want=list)
    except ValueError:
        return []


def _parse_review_reply(reply: str) -> list[dict]:
    return [i for i in _parse_json_array(reply) if isinstance(i, dict)]


def _chat_once(messages: list[dict[str, str]], cfg: dict[str, str], max_tokens: int) -> str:
    return ai_layer.chat_complete(
        messages,
        cfg=cfg,
        max_tokens=max_tokens,
        temperature=0.1,
        purpose="review",
    )


def _chat_with_retry(
    messages: list[dict[str, str]], cfg: dict[str, str], max_tokens: int
) -> tuple[str, float, int]:
    """Retries on rate-limit (429), honoring the server's 'try again in Xs'.

    Free tiers (e.g. Groq token/min budget) 429 on back-to-back calls;
    token-budget windows can demand 60s+ waits, so allow two retries and
    honor wait times up to 60s. Returns (reply, seconds_waited, attempts).
    Raises on final failure.
    """
    waited_total = 0.0
    for attempt in (1, 2, 3):
        try:
            return _chat_once(messages, cfg, max_tokens), waited_total, attempt
        except RuntimeError as exc:
            if "429" not in str(exc) or attempt == 3:
                raise
            m = re.search(r"try again in ([\d.]+)s", str(exc))
            wait = min(float(m.group(1)) + 1.0 if m else 15.0, 60.0)
            time.sleep(wait)
            waited_total += wait


def _reviewable_entries(root: Path) -> list[tuple[Path, int, str]]:
    entries: list[tuple[Path, int, str]] = []
    for p in iter_repo_files(root):
        if SKIP_FILE_RE.search(p.name):
            continue
        if is_vendored(p, root):
            continue
        if p.suffix.lower() not in REVIEW_EXTS:
            continue
        try:
            size = p.stat().st_size
        except Exception:
            continue
        entries.append((p, size, str(p.relative_to(root))))
    return entries


def _sink_count(path: Path) -> int:
    """Dangerous-sink occurrences in a file (bounded read)."""
    try:
        if path.stat().st_size > 200_000:
            return 0
        text = path.read_text(errors="ignore")
    except Exception:
        return 0
    n = 0
    for line in text.splitlines():
        if SINK_CALL_RE.search(line):
            n += 1
        elif XSS_SINK_RE.search(line):
            n += 1
        if n >= 10:
            break
    return n


def _score(path: Path, root: Path, size: int) -> int | None:
    rel = str(path.relative_to(root))
    if SKIP_FILE_RE.search(path.name):
        return None
    if is_vendored(path, root):
        # migrations/fixtures/static: never vuln sinks, never spend slots
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
    sinks = _sink_count(path)
    if sinks:
        # Sink evidence beats naming heuristics: DVWA's exec/sqli/upload
        # vulns live in 600B files named low.php that nothing else ranks.
        score += 3 + min(sinks, 5)
        if size < 800:
            score += 2  # waive the tiny-file penalty when sinks exist
    elif size < 800:
        score -= 2
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
    # score desc, then LARGEST first on ties: t[1] is -size, so ascending
    # t[1] = descending size ((-3,-28000) < (-3,-570) -> big file first).
    scored.sort(key=lambda t: (-t[0], t[1]))
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


def _norm_rel(rel: str) -> str:
    return rel.replace("\\", "/").lstrip("./").lower()


def nominate_files(
    root: Path, entries: list[tuple[Path, int, str]], cfg: dict[str, str], limit: int
) -> list[str]:
    """Phase 1: the model sees the full file listing and nominates
    suspicious files. Returns validated rel paths, best-first. Falls
    back to [] on any failure (scorer picks still cover review)."""
    if not entries:
        return []
    # Rank the listing hot-first: an alphabetical listing truncated at
    # the cap hid DVWA's vulnerabilities/* tree entirely (it sorts last).
    ranked = sorted(
        entries,
        key=lambda e: -(_score(e[0], root, e[1]) or 0),
    )
    lines = [f"{rel} ({size}b)" for _p, size, rel in ranked[:600]]
    user = (
        f"Repository file listing ({len(lines)} source files):\n"
        + "\n".join(lines)
        + f"\n\nNominate up to {limit} files most likely to contain vulnerabilities."
    )
    try:
        reply, _waited, _attempts = _chat_with_retry(
            [
                {"role": "system", "content": TRIAGE_SYSTEM.replace("{limit}", str(limit))},
                {"role": "user", "content": user},
            ],
            cfg,
            max_tokens=1000,
        )
    except Exception:
        return []
    known = {_norm_rel(rel): rel for _p, _s, rel in entries}
    picked: list[str] = []
    for item in _parse_json_array(reply):
        if isinstance(item, dict):
            item = item.get("path") or item.get("file") or ""
        if not isinstance(item, str) or not item.strip():
            continue
        key = _norm_rel(item)
        # exact match first, then unique suffix match (model may prefix repo name)
        rel = known.get(key)
        if rel is None:
            matches = [orig for k, orig in known.items() if k.endswith(key) or key.endswith(k)]
            rel = matches[0] if len(matches) == 1 else None
        if rel and rel not in picked:
            picked.append(rel)
        if len(picked) >= limit:
            break
    return picked


def review_codebase(
    root: Path,
    repo_url: str = "",
    check: Callable[[], str | None] | None = None,
    report: Callable[[str], None] | None = None,
    model: str | None = None,
) -> list[Finding]:
    """Phase 1 (nominate) + Phase 2 (batched review) as Findings.

    The model first shortlists suspicious files from the listing, then
    reviews them together with the scorer's picks in small batches so
    related files share one prompt. `check` (optional) is called between
    batches and returns "pause", "finish" or None. `report` (optional)
    receives live progress lines for the status page. `model` (optional)
    overrides the saved config's model for this call.
    """

    def _report(msg: str) -> None:
        if report is not None:
            try:
                report(msg)
            except Exception:
                pass

    cfg = ai_layer.load_config()
    # Calls recorded from here on belong to this review (manifest honesty:
    # name the models that actually answered, incl. fallbacks).
    since = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if model:
        cfg["model"] = model
    if not (cfg.get("base_url") and cfg.get("model")):
        raise RuntimeError("AI base_url/model not configured")
    entries = _reviewable_entries(root)
    if not entries:
        return [
            Finding(
                scanner="ai-code-review",
                title="AI review skipped: no reviewable code files",
                severity=Severity.info,
                description="No source files with reviewable extensions found.",
                location=repo_url or str(root),
            )
        ]
    max_files = max(1, settings.ai_review_max_files)
    max_bytes = max(10_000, settings.ai_review_max_bytes)
    batch_files = max(1, settings.ai_review_batch_files)
    batch_chars = max(20_000, settings.ai_review_batch_chars)

    # Phase 1: AI nomination. Nominated files lead the queue; scorer
    # picks fill the rest (deduped, same budget).
    _report("AI: ranking the file listing to pick review targets…")
    nominated = nominate_files(root, entries, cfg, limit=max_files)
    by_rel = {rel: (p, size) for p, size, rel in entries}
    queued: list[str] = list(nominated)
    for p, size in pick_review_files(root):
        rel = str(p.relative_to(root))
        if rel not in queued:
            queued.append(rel)
        if len(queued) >= max_files:
            break
    # byte budget
    final_rels: list[str] = []
    total = 0
    for rel in queued:
        p, size = by_rel[rel]
        cost = min(size, EXCERPT_CAP)
        if total + cost > max_bytes and final_rels:
            break
        final_rels.append(rel)
        total += cost
    manifest: list[str] = []
    if nominated:
        manifest.append(
            f"pre-triage: model nominated {len(nominated)} file(s) from listing: "
            + ", ".join(nominated[:8])
        )
    findings: list[Finding] = []
    total_chars = 0
    seen_vulns: set[tuple[str, str, int]] = set()

    # Phase 2: batched review — related files share one prompt.
    batches: list[list[str]] = []
    cur: list[str] = []
    cur_chars = 0
    for rel in final_rels:
        cost = min(by_rel[rel][1], EXCERPT_CAP)
        if cur and (len(cur) >= batch_files or cur_chars + cost > batch_chars):
            batches.append(cur)
            cur, cur_chars = [], 0
        cur.append(rel)
        cur_chars += cost
    if cur:
        batches.append(cur)

    def process_batch(batch: list[str], depth: int = 0) -> None:
        nonlocal total_chars
        if check is not None:
            try:
                stop = check()
            except Exception:
                stop = None
            if stop in ("pause", "finish"):
                manifest.append(f"stopped early by user ({stop}) — remaining batches skipped")
                return
        _report(
            f"AI: reading {batch[0]}"
            + (f" (+{len(batch) - 1} more file(s))" if len(batch) > 1 else "")
        )
        user_parts: list[str] = []
        batch_chars_actual = 0
        for rel in batch:
            code = _excerpt(by_rel[rel][0])
            if not code.strip():
                manifest.append(f"{rel}: skipped (empty)")
                continue
            batch_chars_actual += len(code)
            user_parts.append(f"File: {rel}\n```\n{code}\n```")
        if not user_parts:
            return
        user = (
            "\n\n".join(user_parts)
            + "\n\nList all vulnerabilities found across these files as a JSON array. "
            'Include the exact "file" path for each item.'
        )
        t0 = time.time()
        try:
            reply, waited, attempts = _chat_with_retry(
                [
                    {"role": "system", "content": REVIEW_SYSTEM},
                    {"role": "user", "content": user},
                ],
                cfg,
                max_tokens=min(2000, settings.ai_review_max_tokens * len(batch)),
            )
            dt = time.time() - t0
            total_chars += batch_chars_actual
        except RuntimeError as exc:
            # Provider request-size cap (413): split the batch and retry
            # each half so one fat file never voids its batchmates.
            if ("413" in str(exc) or "too large" in str(exc).lower()) and len(batch) > 1 and depth < 4:
                mid = len(batch) // 2
                process_batch(batch[:mid], depth + 1)
                process_batch(batch[mid:], depth + 1)
                return
            for rel in batch:
                manifest.append(f"{rel}: FAILED ({str(exc)[:120]})")
                findings.append(
                    Finding(
                        scanner="ai-code-review",
                        title=f"AI review failed for {rel}",
                        severity=Severity.info,
                        description=f"Model call failed: {exc}"[:400],
                        location=f"{repo_url}#{rel}" if repo_url else rel,
                    )
                )
            return
        items = _parse_review_reply(reply)
        batch_rels = {_norm_rel(rel): rel for rel in batch}
        per_file_counts = {rel: 0 for rel in batch}
        _report(f"AI: batch done — {len(items)} candidate finding(s)")
        for item in items[:30]:
            item_file = str(item.get("file") or "")
            rel = batch_rels.get(_norm_rel(item_file)) or batch[0]
            title = str(item.get("title") or "AI finding").strip()[:160] or "AI finding"
            # Models repeat the same vuln in slightly different words;
            # dedupe on (file, lowercase title, line) across all batches.
            try:
                _line = int(item.get("line") or 0)
            except Exception:
                _line = 0
            dedup_key = (rel, title.lower(), _line)
            if dedup_key in seen_vulns:
                continue
            seen_vulns.add(dedup_key)
            sev = SEV_MAP.get(str(item.get("severity") or "").strip().lower(), Severity.medium)
            line = _line
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
            per_file_counts[rel] = per_file_counts.get(rel, 0) + 1
        for rel in batch:
            manifest.append(
                f"{rel}: read {min(by_rel[rel][1], EXCERPT_CAP)} chars in {dt:.1f}s "
                f"(attempts={attempts}, waited={waited:.0f}s) -> {per_file_counts.get(rel, 0)} vuln(s)"
            )
        # Pace batches: back-to-back big calls blow free-tier token/min
        # windows and the next batch eats 429s.
        time.sleep(3)

    for batch in batches:
        process_batch(batch)
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
                    "Model reviewed %d file(s) and reported nothing. "
                    "Sampling is bounded — not a clean bill of health."
                    % len(final_rels)
                ),
                location=repo_url or str(root),
            )
        )
    # Always attach the manifest + model id: what was actually read.
    failed = [m for m in manifest if "FAILED" in m]
    used = ai_layer_core.stats(since)
    via = ", ".join(used["models"]) or f"{cfg.get('provider', '')}/{cfg.get('model', '')}"
    if used["fallback_used"]:
        via += " (fallback)"
    findings.append(
        Finding(
            scanner="ai-code-review",
            title=(
                f"AI review manifest: {len(final_rels)} file(s) sampled, "
                f"{total_chars} chars read via {via} "
                f"({vuln_count} vuln(s), {len(failed)} failed)"
            ),
            severity=Severity.info,
            description="Per-file audit trail:\n" + "\n".join(manifest)[:2500],
            location=repo_url or str(root),
            raw={"manifest": manifest, "model": ", ".join(used["models"]) or cfg.get("model", ""),
                  "configured_model": cfg.get("model", ""),
                  "provider": cfg.get("provider", ""), "chars_read": total_chars,
                  "fallback_used": used["fallback_used"], "nominated": nominated},
        )
    )
    return findings
