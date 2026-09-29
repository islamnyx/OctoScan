"""Repo scan pipeline (Phase 2): clone -> static scanners -> AI review + triage.

Same run controls as web scans (see app/control.py): pause/resume/finish
take effect between steps; resume skips already-finished scanners.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app import activity, ai as ai_layer
from app import ai_review
from app import control
from app.models import Finding, RepoScanJob, ScanStatus, Severity
from app.normalize import prioritize
from app.repo import clone_repo, iter_repo_files
from app.repo_store import load_repo_job, repo_workdir, save_repo_job
from app.scanners.source_gitleaks import GitleaksScanner
from app.scanners.source_osv import OsvScanner
from app.scanners.source_semgrep import SemgrepScanner

# Gitleaks/Semgrep each fall back to builtin heuristics when their
# binary is missing, so no standalone builtin run (avoids dupes).
SOURCE_SCANNERS = [GitleaksScanner, SemgrepScanner, OsvScanner]


def repo_summary(job: RepoScanJob, raw_count: int) -> dict:
    """Top-level rollup the dashboard renders first (Q6)."""
    secret_keys = ("secret", "private-key", "private key", "api-key", "api key",
                   "token", "password", "passwd", "akia", "bcrypt", "jwt")
    secrets = 0
    test_secrets = 0
    for f in job.findings:
        if any(k in f"{f.title or ''} {f.description or ''}".lower() for k in secret_keys):
            if (f.raw or {}).get("likely_test_fixture"):
                test_secrets += 1
            else:
                secrets += 1
    merged = sum(int((f.raw or {}).get("merged_count", 1)) - 1 for f in job.findings)
    # Scope split (Q6/S2): OSV findings carry raw.scope (runtime/dev/
    # mixed/unknown); first-party findings have no scope and count as
    # runtime since that code ships. Severity stays honest — scope is
    # a separate axis for filtering, never a downgrade.
    runtime_counts = {s.value: 0 for s in Severity}
    dev_only = 0
    for f in job.findings:
        if (f.raw or {}).get("scope") == "dev":
            dev_only += 1
        else:
            runtime_counts[f.severity.value] += 1
    return {
        "counts": job.counts(),
        "runtime_counts": runtime_counts,
        "dev_only_findings": dev_only,
        "raw_findings": raw_count,
        "findings": len(job.findings),
        "merged_duplicates": max(0, merged),
        "files_scanned": job.files_scanned,
        "findings_with_secrets": secrets,
        "findings_with_test_secrets": test_secrets,
        "scanners": list(job.scanners_run),
    }


def finalize_repo_job(
    job: RepoScanJob, findings: list[Finding], errors: list[str], *, early: bool = False
) -> RepoScanJob:
    raw_count = len(findings)
    job.findings = prioritize(findings)
    job.summary = repo_summary(job, raw_count)
    job.finished_at = datetime.now(timezone.utc)
    note = "Finished early by user request (partial results). " if early else ""
    if errors and not findings:
        job.status = ScanStatus.failed
        job.error = (note + "; ".join(errors))[:1000]
    else:
        job.status = ScanStatus.completed
        combined = note + ("; ".join(errors) if errors else "")
        job.error = combined[:1000] if combined else None
    save_repo_job(job)
    control.clear_all(job.id, "repo")
    return job


def _pause(job: RepoScanJob, findings: list[Finding], errors: list[str]) -> RepoScanJob:
    raw_count = len(findings)
    job.findings = prioritize(findings)
    job.summary = repo_summary(job, raw_count)
    prior = ([job.error] if job.error else []) + [e for e in errors if e != job.error]
    job.error = "; ".join(prior)[:1000] if prior else job.error
    job.status = ScanStatus.paused
    save_repo_job(job)
    return job


def _ai_configured() -> bool:
    cfg = ai_layer.load_config()
    return bool(cfg.get("base_url") and cfg.get("model"))


def run_repo_scan(scan_id: str, *, run_ai: bool = False, ai_model: str | None = None) -> object:
    """Fresh run (queued) or resume (paused). ai_model overrides the
    saved config's model for this scan's AI calls only."""
    job = load_repo_job(scan_id)
    if job is None:
        raise RuntimeError(f"repo scan {scan_id} not found")
    if job.status not in (ScanStatus.queued, ScanStatus.paused):
        raise RuntimeError(f"repo scan {scan_id} is {job.status}, cannot run")
    job.status = ScanStatus.running
    if job.started_at is None:
        job.started_at = datetime.now(timezone.utc)
    job.finished_at = None
    save_repo_job(job)

    workdir = repo_workdir(job.id)
    findings: list[Finding] = list(job.findings)
    prior_error = job.error
    errors: list[str] = []
    activity.clear(job.id)
    activity.log(job.id, f"repo scan started: {job.repo_url}")

    def _stopped() -> str | None:
        flags = control.read(job.id, "repo")
        if flags["finish"]:
            return "finish"
        if flags["paused"]:
            return "pause"
        return None

    # Clone once — skip on resume (interrupted clones re-clone safely).
    if job.files_scanned == 0 and "gitleaks" not in job.scanners_run and "semgrep" not in job.scanners_run:
        try:
            activity.current(job.id, "cloning repository (shallow)…")
            clone_repo(job.repo_url, workdir, job.branch)
        except Exception as exc:
            job.status = ScanStatus.failed
            job.error = str(exc)[:500]
            job.finished_at = datetime.now(timezone.utc)
            save_repo_job(job)
            return job
        try:
            job.files_scanned = len(iter_repo_files(workdir))
            activity.log(job.id, f"cloned — {job.files_scanned} files indexed", kind="done")
        except Exception:
            job.files_scanned = 0
        save_repo_job(job)

    done = set(job.scanners_run)
    # Dashboard picker: empty = run everything (pre-picker behavior).
    requested = set(job.requested_scanners or [])
    wanted = [c for c in SOURCE_SCANNERS if c.name not in done]
    if requested:
        wanted = [c for c in wanted if c.name in requested]
    for cls in wanted:
        stop = _stopped()
        if stop == "finish":
            return finalize_repo_job(job, findings, errors, early=True)
        if stop == "pause":
            return _pause(job, findings, errors)
        activity.current(job.id, f"{cls.name}: scanning {job.files_scanned} file(s)…")
        try:
            scanner = cls(workdir, job.repo_url)
            result = scanner.run()
            job.scanners_run.append(scanner.name)
            findings.extend(result)
            activity.log(job.id, f"{cls.name}: finished — {len(result)} finding(s)", kind="done")
        except Exception as exc:
            errors.append(f"{cls.name}: {exc}")
            activity.log(job.id, f"{cls.name}: failed — {str(exc)[:200]}", kind="error")
        job.findings = prioritize(findings)
        save_repo_job(job)

    job.findings = prioritize(findings)
    save_repo_job(job)
    if run_ai or "ai-code-review" in done or "ai" in done:
        # AI pass re-runs on resume only if it never completed: a finished
        # ai-analyze regenerates explicitly via the endpoint instead.
        if "ai" not in done:
            stop = _stopped()
            if stop == "finish":
                return finalize_repo_job(job, findings, errors, early=True)
            if stop == "pause":
                return _pause(job, findings, errors)
            if _ai_configured():
                # 1. AI reads the code and finds vulns itself. Strip any
                # partial set from an interrupted run first (no dupes).
                findings = [f for f in findings if f.scanner != "ai-code-review"]
                try:
                    review = ai_review.review_codebase(
                        workdir, job.repo_url, check=_stopped,
                        report=lambda m: activity.current(job.id, m),
                        model=ai_model,
                    )
                    job.scanners_run.append("ai-code-review")
                    findings.extend(review)
                    job.findings = prioritize(findings)
                    save_repo_job(job)
                except Exception as exc:
                    errors.append(f"ai-code-review: {exc}")
                    activity.log(job.id, f"ai-code-review: failed — {str(exc)[:200]}", kind="error")
                # 2. AI triages everything (static + its own review findings).
                stop = _stopped()
                if stop == "finish":
                    return finalize_repo_job(job, findings, errors, early=True)
                if stop == "pause":
                    return _pause(job, findings, errors)
                try:
                    cfg = ai_layer.load_config()
                    if ai_model:
                        cfg["model"] = ai_model
                    if cfg.get("base_url") and cfg.get("model"):
                        activity.current(job.id, "AI: triaging all findings…")
                        job.ai = ai_layer.analyze_findings(job.repo_url, prioritize(findings), cfg=cfg)
                        if "ai" not in job.scanners_run:
                            job.scanners_run.append("ai")
                        activity.log(job.id, "AI triage finished", kind="done")
                except Exception as exc:
                    errors.append(f"ai: {exc}")
                    activity.log(job.id, f"AI triage failed — {str(exc)[:200]}", kind="error")

    if prior_error and prior_error not in errors:
        errors = [prior_error] + errors
    return finalize_repo_job(job, findings, errors)
