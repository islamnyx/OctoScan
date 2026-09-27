"""AI fix + verify (docs/NEXT.md, Islam).

fix_finding(): for a real semgrep/gitleaks finding, ONE ai_core.call_json
call returns a minimal patch for a ~40-line window around the flagged
line. The model replaces a line range; we build the unified diff
ourselves (models are bad at diff syntax). The patch is applied to a
COPY of the file (data/agent/<run>/<fix>/after/...), never to the kept
clone, then ONLY the rule that fired is re-run on the original copy and
the patched copy:

  verified = True   rule fired on the original and fires less after the patch
  verified = False  re-scan ran and the rule still fires as often, or the
                    patch breaks parsing
  verified = None   no re-scan possible (OSV/ZAP, heuristic finding, rule
                    unavailable, rule does not fire on the original, no patch)

The scanner grades the patch, not the model.
"""
from __future__ import annotations

import difflib
import json
import re
import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from app import ai_core
from app.config import ROOT, settings
from app.models import AgentFix, Finding

RADIUS = 20
MAX_FILE_BYTES = 1_000_000
VERIFY_TIMEOUT_S = 120
CUSTOM_RULES_DIR = ROOT / "semgrep-rules"
GITLEAKS_CFG = ROOT / ".gitleaks.toml"
CODE_SCANNERS = {"semgrep", "gitleaks"}
# Key material / lockfiles: the fix is "delete + rotate" or a dependency
# bump, not a code patch.
NOT_PATCHABLE_EXT = {".key", ".pem", ".crt", ".cer", ".p12", ".pfx", ".der", ".jks", ".lock"}
PLACEHOLDER = "[REDACTED"


class PatchError(ValueError):
    """The model's patch cannot be applied safely."""


class PatchReply(BaseModel):
    start_line: int = Field(description="first line to replace (window numbering)")
    end_line: int = Field(description="last line to replace, inclusive")
    replacement: str = Field(max_length=6000, description="new code for exactly those lines, no line numbers")
    explanation: str = Field(max_length=1500, description="why this removes the vulnerability, 1-3 sentences")


# ------------------------------------------------------------------ helpers

def locate(f: Finding) -> tuple[str | None, int | None]:
    """(repo-relative file, line) from raw.file or the '#path:line' location suffix."""
    raw = f.raw or {}
    loc = (f.location or "").split("#", 1)[1] if "#" in (f.location or "") else ""
    m = re.match(r"^(.*?):(\d+)$", loc)
    rel = raw.get("file") or (m.group(1) if m else loc) or None
    line = int(m.group(2)) if m else None
    return (str(rel) if rel else None), line


def _safe_path(workdir: Path, rel: str) -> Path | None:
    try:
        p = (workdir / rel).resolve()
        p.relative_to(workdir.resolve())
    except Exception:
        return None
    return p if p.is_file() else None


def is_patchable(f: Finding, workdir: Path) -> bool:
    """semgrep/gitleaks finding on a readable text file inside the clone."""
    if f.scanner not in CODE_SCANNERS:
        return False
    rel, line = locate(f)
    if not rel or not line:
        return False
    p = _safe_path(workdir, rel)
    if p is None or p.suffix.lower() in NOT_PATCHABLE_EXT:
        return False
    try:
        return p.stat().st_size <= MAX_FILE_BYTES and b"\0" not in p.read_bytes()[:4096]
    except Exception:
        return False


def rule_of(f: Finding) -> str:
    raw = f.raw or {}
    return str(raw.get("check") or raw.get("rule") or "")


def window(lines: list[str], line: int, radius: int = RADIUS) -> tuple[int, int, str]:
    """(lo, hi, numbered text) for lines lo..hi (1-based, inclusive)."""
    lo = max(1, line - radius)
    hi = min(len(lines), line + radius)
    text = "\n".join(f"{i}: {lines[i - 1].rstrip(chr(13) + chr(10))}" for i in range(lo, hi + 1))
    return lo, hi, text


_NUMBERED = re.compile(r"^\s*\d+: ?")


def apply_patch(lines: list[str], reply: PatchReply, lo: int, hi: int) -> list[str]:
    """Replace lines start..end (inside lo..hi) with the reply. end = start-1
    is a pure insertion. Raises PatchError when unsafe."""
    s, e = reply.start_line, reply.end_line
    if not (lo <= s <= hi and s - 1 <= e <= hi):
        raise PatchError(f"patch range {s}-{e} outside the shown window {lo}-{hi}")
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    new = reply.replacement.replace("\r\n", "\n").split("\n")
    if new and new[-1] == "":
        new = new[:-1]
    # Model echoed the window numbering ("32: code") on every line: strip it.
    if new and all(_NUMBERED.match(x) for x in new if x.strip()):
        new = [_NUMBERED.sub("", x, count=1) for x in new]
    # Lines the model copied verbatim from the (redacted) prompt get their
    # original text back; any placeholder left would corrupt the file.
    restore: dict[str, str] = {}
    for orig in lines[lo - 1:hi]:
        o = orig.rstrip("\r\n")
        red, n = ai_core.redact(o)
        if n:
            restore[red.strip()] = o
    new = [restore.get(x.strip(), x) for x in new]
    if any(PLACEHOLDER in x for x in new):
        raise PatchError("patch would write a redaction placeholder into the file")
    out = lines[: s - 1] + [x + newline for x in new] + lines[e:]
    # Keep the file's trailing-newline state.
    if lines and not lines[-1].endswith(("\n", "\r")) and out and e >= len(lines):
        out[-1] = out[-1].rstrip("\r\n")
    if out == lines:
        raise PatchError("patch changes nothing")
    return out


def unified_diff(before: list[str], after: list[str], rel: str) -> str:
    return "".join(difflib.unified_diff(before, after, fromfile=f"a/{rel}", tofile=f"b/{rel}", n=3))


# ------------------------------------------------------------ verification

def _custom_rule_ids() -> set[str]:
    ids: set[str] = set()
    try:
        for yml in CUSTOM_RULES_DIR.glob("*.yml"):
            ids.update(re.findall(r"^\s*-\s*id:\s*([\w.-]+)", yml.read_text(), re.M))
    except Exception:
        pass
    return ids


def _semgrep_config(check: str) -> tuple[str, str]:
    """(--config value, rule id to match). Custom rules come from the
    in-repo semgrep-rules/ dir, registry rules as one `r/<id>` rule."""
    leaf = check.rsplit(".", 1)[-1]
    if leaf in _custom_rule_ids() and (check == leaf or "semgrep-rules" in check):
        return str(CUSTOM_RULES_DIR), leaf
    return f"r/{check}", check


def _side(path: str) -> str:
    p = path.replace("\\", "/")
    for side in ("before", "after"):
        if p.startswith(f"{side}/") or f"/{side}/" in p:
            return side
    return ""


def run_semgrep_rule(check: str, fix_dir: Path) -> dict:
    """Re-run ONE semgrep rule on fix_dir/before + fix_dir/after.
    Returns {before, after, broken, error}."""
    config, rule = _semgrep_config(check)
    fix_dir = fix_dir.resolve()  # cwd=fix_dir below: relative paths would double up
    out = fix_dir / "semgrep.json"
    cmd = [settings.semgrep_bin, "--config", config, "--json", "--quiet", "--metrics=off",
           "--output", str(out), "before", "after"]
    try:
        proc = subprocess.run(cmd, cwd=fix_dir, capture_output=True, text=True, timeout=VERIFY_TIMEOUT_S)
    except FileNotFoundError:
        return {"error": "semgrep not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "semgrep re-scan timed out"}
    try:
        data = json.loads(out.read_text())
    except Exception:
        return {"error": f"semgrep re-scan failed: {(proc.stderr or proc.stdout or '')[-200:].strip()}"}
    counts = {"before": 0, "after": 0}
    for r in data.get("results") or []:
        cid = str(r.get("check_id") or "")
        if cid == rule or cid.endswith("." + rule):
            side = _side(str(r.get("path") or ""))
            if side:
                counts[side] += 1
    errs = {"before": 0, "after": 0}
    for e in data.get("errors") or []:
        side = _side(str(e.get("path") or ""))
        if side:
            errs[side] += 1
    return {**counts, "broken": errs["after"] > errs["before"], "error": ""}


def _gitleaks_rules(f: Finding) -> set[str]:
    raw = f.raw or {}
    rules = {str(raw.get("rule") or "")}
    for m in raw.get("merged_from") or []:
        if isinstance(m, dict):
            r = (m.get("raw") or {}).get("rule")
            if not r:
                mt = re.match(r"Gitleaks (\S+) in ", str(m.get("title") or ""))
                r = mt.group(1) if mt else ""
            rules.add(str(r or ""))
    return {r for r in rules if r}


def run_gitleaks_rules(rules: set[str], fix_dir: Path) -> dict:
    fix_dir = fix_dir.resolve()
    out = fix_dir / "gitleaks.json"
    cmd = [settings.gitleaks_bin, "detect", "--no-git", "--source", str(fix_dir),
           "--report-format", "json", "--report-path", str(out)]
    if GITLEAKS_CFG.exists():
        cmd += ["--config", str(GITLEAKS_CFG)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=VERIFY_TIMEOUT_S)
    except FileNotFoundError:
        return {"error": "gitleaks not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "gitleaks re-scan timed out"}
    try:
        items = json.loads(out.read_text() or "[]")
    except Exception:
        return {"error": "gitleaks re-scan produced no report"}
    counts = {"before": 0, "after": 0}
    for it in items if isinstance(items, list) else []:
        if str(it.get("RuleID") or "") in rules:
            try:
                rel = str(Path(str(it.get("File") or "")).resolve().relative_to(fix_dir.resolve()))
            except Exception:
                rel = str(it.get("File") or "")
            side = _side(rel)
            if side:
                counts[side] += 1
    return {**counts, "broken": False, "error": ""}


def verify(f: Finding, fix_dir: Path) -> tuple[bool | None, str]:
    """Re-run only the rule that fired on before/ vs after/ copies."""
    if f.scanner == "semgrep":
        check = str((f.raw or {}).get("check") or "")
        if not check:
            return None, "heuristic finding: no semgrep rule to re-run"
        res, label = run_semgrep_rule(check, fix_dir), f"semgrep {check}"
    elif f.scanner == "gitleaks":
        rules = _gitleaks_rules(f)
        if not rules:
            return None, "no gitleaks rule id to re-run"
        res, label = run_gitleaks_rules(rules, fix_dir), f"gitleaks {', '.join(sorted(rules))}"
    else:
        return None, f"{f.scanner} finding: not verifiable by a code re-scan"
    if res.get("error"):
        return None, f"{label}: {res['error']}"
    b, a = res["before"], res["after"]
    if res.get("broken"):
        return False, f"{label}: patched file no longer parses ({b} -> {a} matches)"
    if b == 0:
        return None, f"{label}: rule does not fire on the original file copy, cannot verify"
    if a < b:
        return True, f"{label}: {b} -> {a} matches after the patch"
    return False, f"{label}: still {a} match(es) after the patch (was {b})"


# --------------------------------------------------------------------- fix

SYSTEM = (
    "You are a senior application-security engineer. Write the MINIMAL patch that removes "
    "the flagged vulnerability and keeps the code's behaviour otherwise. Rules: replace ONE "
    "contiguous line range inside the numbered window (start_line..end_line, inclusive, window "
    "numbering); replacement = the new code for exactly those lines, correct indentation, no "
    "line numbers; keep the language and style; no new dependencies unless unavoidable; for a "
    "hardcoded secret read it from an environment variable instead; values shown as [REDACTED] "
    "are hidden secrets: never write [REDACTED] in the replacement."
)


def _prompt(f: Finding, rel: str, line: int, win: str, hint: str) -> list[dict[str, str]]:
    body = (
        f"Finding: {f.title}\nScanner: {f.scanner}\nRule: {rule_of(f)}\n"
        f"Severity: {f.severity.value}\nMessage: {(f.description or '')[:600]}\n"
        f"File: {rel}, flagged line {line}\n"
    )
    if hint:
        body += f"Previous attempt feedback: {hint[:600]}\n"
    body += f"\nCode window:\n{win}\n"
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": body}]


def fix_finding(f: Finding, workdir: Path, run_dir: Path, *, hint: str = "", attempt: int = 1) -> AgentFix:
    """Patch + verify one finding. Never raises; never writes into workdir."""
    rel, line = locate(f)
    base = AgentFix(finding_id=f.id, file=rel, rule=rule_of(f))
    if f.scanner not in CODE_SCANNERS:
        return base.model_copy(update={
            "explanation": f.recommendation or "Upgrade or reconfigure the affected component.",
            "note": f"{f.scanner} finding: not verifiable by a code re-scan",
        })
    if not is_patchable(f, workdir):
        return base.model_copy(update={
            "explanation": f.recommendation or "",
            "note": "not a patchable source file (key material, lockfile, missing or binary file)",
        })
    src = _safe_path(workdir, rel)
    text = src.read_text(errors="replace")
    lines = text.splitlines(keepends=True)
    line = min(max(1, line), max(1, len(lines)))
    lo, hi, win = window(lines, line)
    try:
        reply, _meta = ai_core.call_json(_prompt(f, rel, line, win, hint), PatchReply,
                                         max_tokens=1500, purpose="fix")
    except ai_core.AIError as exc:
        return base.model_copy(update={"note": f"AI unavailable: {str(exc)[:200]}"})
    try:
        patched = apply_patch(lines, reply, lo, hi)
    except PatchError as exc:
        return base.model_copy(update={"explanation": reply.explanation, "note": f"patch rejected: {exc}"})
    fix_dir = (run_dir / f"{f.id}-{attempt}").resolve()
    shutil.rmtree(fix_dir, ignore_errors=True)
    (fix_dir / "before" / rel).parent.mkdir(parents=True, exist_ok=True)
    (fix_dir / "after" / rel).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, fix_dir / "before" / rel)
    (fix_dir / "after" / rel).write_text("".join(patched))
    verified, note = verify(f, fix_dir)
    return base.model_copy(update={
        "diff": unified_diff(lines, patched, rel),
        "explanation": reply.explanation,
        "verified": verified,
        "note": note,
    })
