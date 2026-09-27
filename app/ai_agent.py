"""Guided security agent (docs/AI-PLAN.md "1 guided agent + 4 tools").

Fixed backbone: scan -> prefilter -> triage -> fix -> verify -> story.
At each step the model returns {thought, tool, args} (one call_json with a
per-phase schema whose `tool` is a Literal of the allowed tools, so vLLM's
guided decoding on Brev can only emit a legal choice). Bad choice, bad args
or AI outage -> the backbone default runs and the step says so.

Verify never asks the model: the scanner re-runs the rule that fired and
grades the patch (app/ai_fix.py).

Runs live in a background thread (like repo scans). State is kept in
memory and in data/agent/<run_id>.json after every step; steps are also
mirrored to app/activity.py.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, create_model

from app import activity, ai_core, ai_fix
from app.config import settings
from app.models import (
    AgentFinding,
    AgentFix,
    AgentRun,
    AgentStats,
    AgentStep,
    Finding,
    RepoScanJob,
    ScanStatus,
    Severity,
)

log = logging.getLogger("octoscan.agent")

# Friend A / friend B modules (docs/NEXT.md section 2). Until merged, the
# in-file stand-ins below keep the exact signatures.
try:
    from app import ai_triage as _triage_mod
except Exception:  # pragma: no cover - depends on merge state
    _triage_mod = None
try:
    from app import ai_story as _story_mod
except Exception:  # pragma: no cover
    _story_mod = None

AGENT_DIR = settings.data_dir / "agent"
MAX_RUNNING = 2
PREFILTER_MAX = 30
PREFILTER_MIN = 10
TRIAGE_BATCH = 5
MAX_VERIFIED_FIXES = 3
MAX_FIX_ATTEMPTS = 4          # total patch attempts per run (incl. retries)
MAX_ATTEMPTS_PER_FINDING = 2  # 1 retry with the scanner's feedback
FIX_DEADLINE_S = 600          # stop fixing after 10 min, still write the story
MAX_DEP_ADVICE = 3

_RUNS: dict[str, AgentRun] = {}
_LOCK = threading.RLock()


# ------------------------------------------------------------ stand-ins

class _StubTriage:
    """Rule-based stand-in for app/ai_triage.py (friend A), same signatures."""

    name = "rule-based stand-in (ai_triage not merged)"

    @staticmethod
    def locate(f: Finding) -> tuple[str | None, int | None]:
        return ai_fix.locate(f)

    @staticmethod
    def prefilter(findings: list[Finding], limit: int = 30) -> list[Finding]:
        keep = []
        for f in findings:
            raw = f.raw or {}
            if raw.get("scope") == "dev" or raw.get("likely_test_fixture"):
                continue
            if f.severity == Severity.info or f.scanner in ("ai-code-review", "ai"):
                continue
            keep.append(f)
        return keep[:limit]

    @staticmethod
    def code_window(workdir: Path, rel: str, line: int, radius: int = 20) -> str:
        p = ai_fix._safe_path(workdir, rel)
        if p is None:
            return ""
        return ai_fix.window(p.read_text(errors="replace").splitlines(True), line, radius)[2]

    @staticmethod
    def triage(findings: list[Finding], workdir: Path) -> list[dict]:
        out = []
        for f in findings:
            code = f.scanner in ai_fix.CODE_SCANNERS and f.severity in (
                Severity.critical, Severity.high, Severity.medium)
            code = code or (f.scanner == "osv" and f.severity in (Severity.critical, Severity.high))
            out.append({"finding_id": f.id, "verdict": "real" if code else "review",
                        "confidence": 0.5 if code else 0.3,
                        "reason": "rule-based stand-in: AI triage module not merged yet"})
        return out


class _StubStory:
    name = "rule-based verdict (ai_story not merged)"

    @staticmethod
    def attack_story(real: list[dict], target: str) -> dict:
        severe = [r for r in real if r.get("severity") in ("critical", "high")]
        return {
            "verdict": "not_ready" if severe else "ready",
            "blockers": [str(r.get("title") or "")[:200] for r in severe[:5]],
            "attack_story": (
                f"Rule-based summary: {len(real)} real finding(s), {len(severe)} critical/high. "
                "Fix the blockers before launch." if real else "No confirmed real findings."
            ),
        }


def _triage_fn(name: str):
    fn = getattr(_triage_mod, name, None) if _triage_mod is not None else None
    return fn or getattr(_StubTriage, name)


def _story_fn():
    fn = getattr(_story_mod, "attack_story", None) if _story_mod is not None else None
    return fn or _StubStory.attack_story


# ---------------------------------------------------------------- store

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _path(run_id: str) -> Path:
    return AGENT_DIR / f"{run_id}.json"


def _save(run: AgentRun) -> None:
    with _LOCK:
        _RUNS[run.run_id] = run
        try:
            AGENT_DIR.mkdir(parents=True, exist_ok=True)
            _path(run.run_id).write_text(run.model_dump_json(indent=2))
        except Exception as exc:
            log.warning("agent run save failed: %s", exc)


def get(run_id: str) -> dict | None:
    """API view of a run (frozen keys + additive extras)."""
    with _LOCK:
        run = _RUNS.get(run_id)
        if run is None:
            try:
                run = AgentRun.model_validate_json(_path(run_id).read_text())
            except Exception:
                return None
            if run.status == "running":  # thread died with the old process
                run.status = "failed"
                run.error = "orphaned: server restarted mid-run"
                run.finished_at = run.finished_at or _now()
                _save(run)
        if run.status == "running" and run.phase == "scan" and run.scan_id:
            run.current = activity.feed(run.scan_id).get("current") or run.current
        return run.model_dump(mode="json")


def list_runs(limit: int = 20) -> list[dict]:
    """Newest agent runs (summary only) for the agent page's history list."""
    runs: dict[str, AgentRun] = {}
    try:
        for fp in AGENT_DIR.glob("*.json"):
            try:
                r = AgentRun.model_validate_json(fp.read_text())
                runs[r.run_id] = r
            except Exception:
                continue
    except Exception:
        pass
    with _LOCK:
        runs.update(_RUNS)
        rows = [{
            "run_id": r.run_id, "status": r.status, "repo_url": r.repo_url, "verdict": r.verdict,
            "model": r.stats.model, "fixes_verified": sum(1 for x in r.fixes if x.verified is True),
            "findings": len(r.findings), "created_at": r.created_at.isoformat(),
        } for r in runs.values()]
    rows.sort(key=lambda x: x["created_at"], reverse=True)
    return rows[:limit]


def running_count() -> int:
    with _LOCK:
        return sum(1 for r in _RUNS.values() if r.status == "running")


def start(repo_url: str, target_url: str | None = None) -> AgentRun:
    run = AgentRun(repo_url=repo_url, target_url=target_url)
    _save(run)
    threading.Thread(target=run_agent, args=(run.run_id,), daemon=True).start()
    return run


# ---------------------------------------------------------------- agent

PLANNER_SYSTEM = (
    "You are OctoScan's pre-launch security agent. You work inside a fixed backbone: "
    "scan -> prefilter -> triage -> fix -> verify -> story. At each step choose exactly ONE "
    "tool from allowed_tools and give its args. `thought` is shown live to the user: one or "
    "two plain sentences saying what you do next and why, based on the state. Prefer fixing "
    "high-severity, high-confidence, exploitable code findings first. Never invent ids."
)


class AgentError(RuntimeError):
    pass


def _cached_scan(repo_url: str) -> RepoScanJob | None:
    from app.repo_store import list_repo_jobs, repo_workdir

    want = repo_url.rstrip("/").removesuffix(".git").lower()
    for job in list_repo_jobs():  # newest first
        if job.repo_url.rstrip("/").removesuffix(".git").lower() != want:
            continue
        if job.status != ScanStatus.completed or "semgrep" not in job.scanners_run:
            continue
        if repo_workdir(job.id).is_dir():
            return job
    return None


def _age(ts: datetime | None) -> str:
    if not ts:
        return "unknown age"
    mins = int((_now() - ts).total_seconds() // 60)
    return f"{mins} min" if mins < 120 else f"{mins // 60} h"


class _Agent:
    def __init__(self, run: AgentRun):
        self.run = run
        self.since = _now().isoformat(timespec="seconds")
        self.t0 = time.monotonic()
        self.run_dir = AGENT_DIR / run.run_id
        self._t: dict[int, float] = {}

    # -- bookkeeping -------------------------------------------------------
    def stats(self) -> None:
        s = ai_core.stats(since_ts=self.since)
        self.run.stats = AgentStats(
            model=", ".join(s["models"]), calls=s["calls"], median_latency_ms=s["median_latency_ms"],
            fallback_used=s["fallback_used"], tokens_in=s["tokens_in"], tokens_out=s["tokens_out"],
        )

    def step(self, tool: str, thought: str, args: dict | None = None) -> AgentStep:
        with _LOCK:
            st = AgentStep(n=len(self.run.steps) + 1, thought=thought[:600], tool=tool, args=args or {})
            self.run.steps.append(st)
            self.run.current = f"{tool}: {thought[:200]}"
        activity.current(self.run.run_id, f"[{tool}] {thought[:300]}")
        _save(self.run)
        self._t[st.n] = time.monotonic()
        return st

    def done(self, st: AgentStep, result: str, ok: bool = True) -> None:
        with _LOCK:
            st.result = result[:2000]
            st.status = "done" if ok else "error"
            st.ms = int((time.monotonic() - self._t.get(st.n, time.monotonic())) * 1000)
            self.stats()
        activity.log(self.run.run_id, f"[{st.tool}] {result[:300]}", kind="done" if ok else "error")
        _save(self.run)

    def phase(self, name: str) -> None:
        with _LOCK:
            self.run.phase = name
        _save(self.run)

    # -- the model's decision at each backbone step -------------------------
    def decide(self, phase: str, allowed: dict[str, str], state: dict,
               default: tuple[str, dict], default_thought: str) -> tuple[str, dict, str]:
        tools = tuple(allowed)
        schema = create_model(
            f"Decision_{phase}",
            thought=(str, Field(max_length=600)),
            tool=(Literal[tools], ...),  # type: ignore[valid-type]
            args=(dict[str, Any], Field(default_factory=dict)),
        )
        msgs = [
            {"role": "system", "content": PLANNER_SYSTEM},
            {"role": "user", "content": json.dumps(
                {"phase": phase, "allowed_tools": allowed, "state": state}, default=str)[:12000]},
        ]
        try:
            d, _meta = ai_core.call_json(msgs, schema, max_tokens=700, purpose=f"agent:{phase}")
        except ai_core.AIError as exc:
            return default[0], default[1], (
                f"AI planner unavailable ({str(exc)[:80]}); following the fixed backbone. {default_thought}")
        except Exception as exc:  # schema build / unexpected
            log.warning("planner error: %s", exc)
            return default[0], default[1], f"Following the fixed backbone. {default_thought}"
        return d.tool, dict(d.args or {}), (d.thought or default_thought).strip()

    # -- backbone ---------------------------------------------------------
    def run_all(self) -> None:
        job, findings = self.do_scan()
        workdir = self._workdir(job)
        kept = self.do_prefilter(findings)
        by_id = self.do_triage(kept, workdir)
        self.do_fix(kept, by_id, workdir)
        self.do_story()

    def _workdir(self, job: RepoScanJob) -> Path:
        from app.repo_store import repo_workdir
        return repo_workdir(job.id)

    def do_scan(self) -> tuple[RepoScanJob, list[Finding]]:
        from app.repo_pipeline import run_repo_scan
        from app.repo_store import load_repo_job, save_repo_job

        self.phase("scan")
        cached = _cached_scan(self.run.repo_url)
        allowed = {"scan": "clone the repo (shallow) and run gitleaks + semgrep + osv-scanner, ~1 min"}
        state: dict[str, Any] = {"repo_url": self.run.repo_url}
        if cached:
            allowed["reuse_scan"] = (f"reuse completed scan {cached.id} of this repo from {_age(cached.finished_at)} "
                                     f"ago ({len(cached.findings)} findings); args {{\"scan_id\": \"{cached.id}\"}}")
            state["cached_scan"] = {"scan_id": cached.id, "age": _age(cached.finished_at),
                                    "findings": len(cached.findings), "scanners": cached.scanners_run}
        if self.run.target_url:
            state["target_url"] = f"{self.run.target_url} (web scan is not run by the agent: up to 20 min)"
        tool, args, thought = self.decide(
            "scan", allowed, state, ("scan", {}), "Scanning the repository with the static scanners first.")
        if tool == "reuse_scan" and cached:
            st = self.step("reuse_scan", thought, {"scan_id": cached.id})
            with _LOCK:
                self.run.scan_id = cached.id
            self.done(st, f"reused scan {cached.id}: {len(cached.findings)} findings "
                          f"({', '.join(cached.scanners_run)})")
            return cached, list(cached.findings)
        st = self.step("scan", thought, {})
        job = RepoScanJob(repo_url=self.run.repo_url)
        save_repo_job(job)
        with _LOCK:
            self.run.scan_id = job.id
        _save(self.run)
        run_repo_scan(job.id, run_ai=False)
        job = load_repo_job(job.id)
        if job is None or job.status != ScanStatus.completed:
            err = (job.error if job else "scan job vanished") or "scan failed"
            self.done(st, f"scan failed: {err[:300]}", ok=False)
            raise AgentError(f"scan failed: {err[:300]}")
        by_scanner: dict[str, int] = {}
        for f in job.findings:
            by_scanner[f.scanner] = by_scanner.get(f.scanner, 0) + 1
        self.done(st, f"{len(job.findings)} findings in {job.files_scanned} files: "
                      + ", ".join(f"{k} {v}" for k, v in sorted(by_scanner.items())))
        return job, list(job.findings)

    def do_prefilter(self, findings: list[Finding]) -> list[Finding]:
        self.phase("prefilter")
        dev = sum(1 for f in findings if (f.raw or {}).get("scope") == "dev")
        fixtures = sum(1 for f in findings if (f.raw or {}).get("likely_test_fixture"))
        sev: dict[str, int] = {}
        for f in findings:
            sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
        state = {"total": len(findings), "dev_only": dev, "test_fixtures": fixtures, "by_severity": sev}
        allowed = {"prefilter": (f"drop dev-only deps, test fixtures, info rows and AI meta rows WITHOUT AI, keep "
                                 f"the top `limit` by priority ({PREFILTER_MIN}-{PREFILTER_MAX}); "
                                 "args {\"limit\": N}")}
        tool, args, thought = self.decide(
            "prefilter", allowed, state, ("prefilter", {"limit": PREFILTER_MAX}),
            "Dropping noise without AI so only findings that ship get the model's attention.")
        try:
            limit = int(args.get("limit", PREFILTER_MAX))
        except (TypeError, ValueError):
            limit = PREFILTER_MAX
        limit = max(PREFILTER_MIN, min(PREFILTER_MAX, limit))
        st = self.step("prefilter", thought, {"limit": limit})
        # Code and dependency findings are prefiltered separately: NodeGoat's
        # 92 runtime OSV rows would otherwise fill all 30 slots and leave
        # nothing patchable. Code gets >= 2/3 of the slots when it has them.
        code = [f for f in findings if f.scanner != "osv"]
        deps = [f for f in findings if f.scanner == "osv"]
        try:
            kept_code = list(_triage_fn("prefilter")(code, limit=limit))
            kept_deps = list(_triage_fn("prefilter")(deps, limit=limit))
        except Exception as exc:
            log.warning("prefilter failed, using stand-in: %s", exc)
            kept_code = _StubTriage.prefilter(code, limit=limit)
            kept_deps = _StubTriage.prefilter(deps, limit=limit)
        n_code = min(len(kept_code), max(limit * 2 // 3, limit - len(kept_deps)))
        kept = kept_code[:n_code] + kept_deps[:limit - n_code]
        self.done(st, f"{len(findings)} -> {len(kept)} findings ({n_code} code + {len(kept) - n_code} dependency; "
                      f"dropped {dev} dev-only, {fixtures} test fixtures, info rows)")
        return kept

    def _row(self, f: Finding, item: dict) -> AgentFinding:
        try:
            rel, line = _triage_fn("locate")(f)
        except Exception:
            rel, line = ai_fix.locate(f)
        verdict = str(item.get("verdict") or "review")
        if verdict not in ("real", "false_positive", "review"):
            verdict = "review"
        try:
            conf = max(0.0, min(1.0, float(item.get("confidence") or 0.0)))
        except (TypeError, ValueError):
            conf = 0.0
        return AgentFinding(id=f.id, title=f.title, severity=f.severity.value, file=rel,
                            line=line if isinstance(line, int) else None, verdict=verdict,
                            confidence=conf, reason=str(item.get("reason") or "")[:600], scanner=f.scanner)

    def do_triage(self, kept: list[Finding], workdir: Path) -> dict[str, AgentFinding]:
        self.phase("triage")
        stand_in = _triage_mod is None or not hasattr(_triage_mod, "triage")
        state = {"findings": len(kept), "batch_size": TRIAGE_BATCH,
                 "scanners": sorted({f.scanner for f in kept})}
        allowed = {"triage": ("AI reads each finding with ~40 lines of its code and labels it real / "
                              "false_positive / review with a confidence and reason, 5 per call")}
        tool, args, thought = self.decide(
            "triage", allowed, state, ("triage", {}),
            "Checking every kept finding against its code to drop false alarms.")
        st = self.step("triage", thought, {"findings": len(kept), "batch": TRIAGE_BATCH})
        fn = _triage_fn("triage")
        by_id: dict[str, AgentFinding] = {}
        for i in range(0, len(kept), TRIAGE_BATCH):
            batch = kept[i:i + TRIAGE_BATCH]
            try:
                items = {str(it.get("finding_id")): it for it in (fn(batch, workdir) or []) if isinstance(it, dict)}
            except Exception as exc:
                log.warning("triage batch failed: %s", exc)
                items = {f.id: {"verdict": "review", "confidence": 0.0, "reason": f"triage failed: {str(exc)[:150]}"}
                         for f in batch}
            with _LOCK:
                for f in batch:
                    row = self._row(f, items.get(f.id) or {
                        "verdict": "review", "confidence": 0.0, "reason": "not returned by the model"})
                    by_id[f.id] = row
                    self.run.findings.append(row)
                st.result = f"triaged {min(i + TRIAGE_BATCH, len(kept))}/{len(kept)}"
                self.stats()
            _save(self.run)
        counts = {v: sum(1 for r in by_id.values() if r.verdict == v) for v in ("real", "false_positive", "review")}
        self.done(st, f"{counts['real']} real, {counts['false_positive']} false positive, {counts['review']} "
                      f"to review" + (" (rule-based stand-in: ai_triage not merged)" if stand_in else ""))
        return by_id

    def do_fix(self, kept: list[Finding], by_id: dict[str, AgentFinding], workdir: Path) -> None:
        self.phase("fix")
        real = [f for f in kept if by_id.get(f.id) and by_id[f.id].verdict == "real"]
        cands = [f for f in real if ai_fix.is_patchable(f, workdir)]
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        cands.sort(key=lambda f: (sev_rank.get(f.severity.value, 5), -by_id[f.id].confidence))
        closed: set[str] = set()
        attempts: dict[str, int] = {}
        last_note: dict[str, str] = {}
        verified = total = 0
        fix_start = time.monotonic()
        while verified < MAX_VERIFIED_FIXES and total < MAX_FIX_ATTEMPTS:
            if time.monotonic() - fix_start > FIX_DEADLINE_S:
                st = self.step("finish", "Fix time budget used up; moving on to the verdict.")
                self.done(st, "stopped fixing: time budget")
                break
            open_c = [f for f in cands if f.id not in closed and attempts.get(f.id, 0) < MAX_ATTEMPTS_PER_FINDING]
            if not open_c:
                break
            state = {
                "fixes_left": MAX_VERIFIED_FIXES - verified,
                "candidates": [{
                    "finding_id": f.id, "title": f.title[:160], "severity": f.severity.value,
                    "file": by_id[f.id].file, "line": by_id[f.id].line, "rule": ai_fix.rule_of(f),
                    "confidence": by_id[f.id].confidence, "reason": by_id[f.id].reason[:200],
                    "attempts": attempts.get(f.id, 0), "last_result": last_note.get(f.id, ""),
                } for f in open_c[:8]],
                "fixes_so_far": [{"finding_id": x.finding_id, "verified": x.verified, "note": x.note[:160]}
                                 for x in self.run.fixes],
            }
            allowed = {
                "fix": ("write a minimal patch for ONE candidate and prove it with a re-scan of the rule "
                        "that fired; args {\"finding_id\": \"<id from candidates>\", \"hint\": \"optional "
                        "guidance for the patch, e.g. what failed last time\"}"),
                "finish": "stop fixing and write the launch verdict",
            }
            top = open_c[0]
            tool, args, thought = self.decide(
                "fix", allowed, state, ("fix", {"finding_id": top.id}),
                f"Fixing the most severe real code finding next: {top.title[:120]}.")
            if tool == "finish":
                st = self.step("finish", thought)
                self.done(st, f"{verified} verified fix(es); stopping by choice")
                break
            fid = str(args.get("finding_id") or "")
            chosen = next((f for f in open_c if f.id == fid), None)
            if chosen is None:
                chosen = top
                if fid:
                    thought += f" (model picked unknown id {fid[:20]}; taking the top candidate)"
            hint = str(args.get("hint") or "")[:400]
            if last_note.get(chosen.id):
                hint = (hint + " Last attempt: " + last_note[chosen.id]).strip()
            attempts[chosen.id] = attempts.get(chosen.id, 0) + 1
            total += 1
            row = by_id[chosen.id]
            st = self.step("fix", thought, {"finding_id": chosen.id, "file": row.file, "line": row.line,
                                            "attempt": attempts[chosen.id], **({"hint": hint} if hint else {})})
            fix = ai_fix.fix_finding(chosen, workdir, self.run_dir, hint=hint, attempt=attempts[chosen.id])
            changed = sum(1 for ln in fix.diff.splitlines()
                          if ln[:1] in "+-" and not ln.startswith(("+++", "---")))
            self.done(st, f"patch for {row.file}:{row.line} ({changed} changed lines)" if fix.diff
                      else f"no patch: {fix.note}", ok=bool(fix.diff))
            with _LOCK:
                self.run.fixes = [x for x in self.run.fixes if x.finding_id != chosen.id] + [fix]
            _save(self.run)
            if fix.diff:
                vs = self.step("verify", f"Re-running only {fix.rule or chosen.scanner} on the original and the "
                                         "patched copy: the scanner decides, not the model.",
                               {"finding_id": chosen.id, "rule": fix.rule})
                label = {True: "VERIFIED", False: "NOT FIXED", None: "not verifiable"}[fix.verified]
                self.done(vs, f"{label}: {fix.note}", ok=fix.verified is not False)
            last_note[chosen.id] = fix.note
            if fix.verified is True:
                verified += 1
                closed.add(chosen.id)
                if "-> 0 matches" in fix.note:  # same rule gone from the whole file
                    for f in cands:
                        if f.id != chosen.id and by_id[f.id].file == row.file and ai_fix.rule_of(f) == fix.rule:
                            closed.add(f.id)
            elif fix.note.startswith("AI unavailable"):
                break  # every provider is down: more patch attempts would fail the same way
            elif fix.verified is None and (fix.diff or fix.note.startswith("not a patchable")):
                closed.add(chosen.id)  # retrying cannot change the outcome
        # Dependency findings: advice only, honestly not verifiable by a code re-scan.
        deps = [f for f in real if f.scanner == "osv"][:MAX_DEP_ADVICE]
        if deps:
            st = self.step("fix", "Dependency findings get upgrade advice; a code re-scan cannot prove them, "
                                  "so they stay 'not verified'.", {"findings": [f.id for f in deps]})
            with _LOCK:
                for f in deps:
                    self.run.fixes.append(ai_fix.fix_finding(f, workdir, self.run_dir))
            self.done(st, f"{len(deps)} upgrade advice(s), verified: null")
        if not cands and not deps:
            st = self.step("fix", "No real finding is patchable in code; nothing to fix.")
            self.done(st, "0 candidates")

    def do_story(self) -> None:
        self.phase("story")
        fixed = {x.finding_id for x in self.run.fixes if x.verified is True}
        real = [{**r.model_dump(), "fixed_and_verified": r.id in fixed}
                for r in self.run.findings if r.verdict == "real"]
        state = {"real_findings": len(real), "verified_fixes": len(fixed),
                 "critical_high_real": sum(1 for r in real if r["severity"] in ("critical", "high"))}
        allowed = {"story": ("chain the real findings into how an attacker would break in and give a "
                             "ready / not_ready launch verdict with blockers")}
        tool, args, thought = self.decide(
            "story", allowed, state, ("story", {}),
            "Writing the attack story and the launch verdict from the confirmed findings.")
        st = self.step("story", thought, {"real_findings": len(real)})
        try:
            out = _story_fn()(real, self.run.repo_url) or {}
        except Exception as exc:
            log.warning("story failed, rule-based verdict: %s", exc)
            out = _StubStory.attack_story(real, self.run.repo_url)
        verdict = out.get("verdict")
        if verdict not in ("ready", "not_ready"):
            out = {**_StubStory.attack_story(real, self.run.repo_url), **{
                k: v for k, v in out.items() if k == "attack_story" and v}}
            verdict = out["verdict"]
        blockers = [str(b)[:300] for b in (out.get("blockers") or [])][:10]
        # Never "ready" while critical/high findings are unconfirmed (AI down,
        # low confidence): a human must look first.
        unsure = [r for r in self.run.findings if r.verdict == "review" and r.severity in ("critical", "high")]
        if verdict == "ready" and unsure:
            verdict = "not_ready"
            blockers.append(f"{len(unsure)} critical/high finding(s) need human review (AI could not confirm them)")
        with _LOCK:
            self.run.verdict = verdict
            self.run.blockers = blockers
            self.run.attack_story = str(out.get("attack_story") or "")[:5000]
        self.done(st, f"verdict {verdict}: {len(self.run.blockers)} blocker(s)")


def run_agent(run_id: str) -> None:
    with _LOCK:
        run = _RUNS.get(run_id)
    if run is None:
        return
    agent = _Agent(run)
    activity.clear(run_id)
    activity.log(run_id, f"agent started: {run.repo_url}")
    try:
        agent.run_all()
        with _LOCK:
            run.status = "done"
            run.phase = "done"
            run.current = ""
        activity.log(run_id, f"agent done: verdict {run.verdict}", kind="done")
    except Exception as exc:
        log.exception("agent run %s failed", run_id)
        with _LOCK:
            run.status = "failed"
            run.error = str(exc)[:500]
            run.current = ""
        activity.log(run_id, f"agent failed: {str(exc)[:200]}", kind="error")
    finally:
        with _LOCK:
            agent.stats()
            run.finished_at = _now()
        _save(run)
