import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from app import activity, control
from app.config import settings
from app.models import Finding, ScanJob, ScanStatus
from app.normalize import prioritize
from app.rules import evaluate_gate
from app.scanners import SCANNERS
from app.scanners.headers_scanner import HeadersScanner
from app.scanners.nikto_scanner import NiktoScanner
from app.scanners.nmap_scanner import NmapScanner
from app.scanners.nuclei_scanner import NucleiScanner
from app.scanners.testssl_scanner import TestsslScanner
from app.scanners.zap_scanner import ZapScanner
from app.sensitive import flag_sensitive_files, probe_wellknown
from app.store import load_job, save_job

# ZAP first: it needs a fresh daemon/session + most memory, and its
# spider output (Sites tree) is most reliable before nuclei/nikto hammer
# the target. Light scanners follow so a crash still leaves partials.
SEQUENTIAL_ORDER = [
    ZapScanner,
    HeadersScanner,
    NmapScanner,
    TestsslScanner,
    NiktoScanner,
    NucleiScanner,
]


def finalize_scan(job: ScanJob, findings: list[Finding], errors: list[str], *, early: bool = False) -> ScanJob:
    """Checkpoint + close out a job. Shared by the worker and the finish endpoint."""
    job.findings = prioritize(findings)
    # DAST quality gate (skill Step 4): FAIL on exploitable rules
    # (XSS/SQLi pluginIds, high/critical active findings), WARN on
    # headers/misconfigs. Verdict only — never overrides job.status.
    # Coverage-aware (2026-09-16): partial ascan yields INCOMPLETE, not PASSED.
    job.gate, job.gate_details = evaluate_gate(job.findings, job.coverage)
    job.finished_at = datetime.now(timezone.utc)
    note = "Finished early by user request (partial results). " if early else ""
    if errors and not findings:
        job.status = ScanStatus.failed
        job.error = (note + "; ".join(errors))[:1000]
    else:
        job.status = ScanStatus.completed
        combined = note + ("; ".join(errors) if errors else "")
        job.error = combined[:1000] if combined else None
    save_job(job)
    control.clear_all(job.id, "scan")
    return job


def _pause(job: ScanJob, findings: list[Finding], errors: list[str]) -> ScanJob:
    job.findings = prioritize(findings)
    job.gate, job.gate_details = evaluate_gate(job.findings, job.coverage)
    prior = ([job.error] if job.error else []) + [e for e in errors if e != job.error]
    job.error = "; ".join(prior)[:1000] if prior else job.error
    job.status = ScanStatus.paused
    save_job(job)
    return job


def run_scan(scan_id: str) -> ScanJob:
    """Fresh run (queued) or resume (paused). Skips already-finished scanners."""
    job = load_job(scan_id)
    if job is None:
        raise RuntimeError(f"scan {scan_id} not found")
    if job.status not in (ScanStatus.queued, ScanStatus.paused):
        raise RuntimeError(f"scan {scan_id} is {job.status}, cannot run")
    job.status = ScanStatus.running
    if job.started_at is None:
        job.started_at = datetime.now(timezone.utc)
    job.finished_at = None
    save_job(job)

    workdir = settings.data_dir / "scans" / job.id
    workdir.mkdir(parents=True, exist_ok=True)
    findings: list[Finding] = list(job.findings)
    prior_error = job.error
    errors: list[str] = []
    activity.clear(job.id)
    activity.log(job.id, f"scan started against {job.target_url}")
    if job.auth and (job.auth.cookies or job.auth.headers):
        activity.log(
            job.id,
            f"authenticated scan: session injection "
            f"({len(job.auth.cookies)} cookie(s), {len(job.auth.headers)} header(s))",
        )

    def _run(scanner_cls):
        activity.current(job.id, f"{scanner_cls.name}: scanning {job.target_url}…")
        scanner = scanner_cls(job.target_url, workdir)
        # Authenticated scans (v1): session injection; None = anonymous.
        scanner.auth = job.auth
        findings_result = scanner.run()
        coverage_result = dict(getattr(scanner, "coverage", None) or {})
        activity.log(job.id, f"{scanner_cls.name}: finished — {len(findings_result)} finding(s)", kind="done")
        return scanner.name, findings_result, coverage_result

    # Lower CPU priority so the desktop stays responsive on laptops.
    try:
        os.nice(10)
    except Exception:
        pass

    max_parallel = max(1, settings.scan_max_parallel)
    done = set(job.scanners_run)
    # Dashboard picker: empty = run everything (pre-picker behavior).
    requested = set(job.requested_scanners or [])
    ordered = [c for c in SEQUENTIAL_ORDER if c in SCANNERS and c.name not in done]
    if requested:
        ordered = [c for c in ordered if c.name in requested]

    def _stopped() -> str | None:
        flags = control.read(job.id, "scan")
        if flags["finish"]:
            return "finish"
        if flags["paused"]:
            return "pause"
        return None

    if max_parallel == 1:
        # Sequential low-power mode (default): one scanner at a time,
        # checkpoint after each so a shutdown leaves partial results.
        for cls in ordered:
            stop = _stopped()
            if stop == "finish":
                return finalize_scan(job, findings, errors, early=True)
            if stop == "pause":
                return _pause(job, findings, errors)
            # Lab targets flap (pentest-ground went unreachable mid-scan on
            # 2026-09-16 right after ZAP's active scan). Connection-level
            # failures get one retry after 45s — usually enough for the
            # target to come back — instead of a wasted scan.
            attempts = 0
            while True:
                try:
                    scanner_name, result, coverage = _run(cls)
                    job.scanners_run.append(scanner_name)
                    findings.extend(result)
                    if coverage:
                        job.coverage[scanner_name] = coverage
                    break
                except Exception as exc:
                    retriable = str(exc).startswith("CONNECTION FAILURE:") and attempts == 0
                    if retriable and not _stopped():
                        attempts += 1
                        activity.log(
                            job.id,
                            f"{cls.name}: connection failed, retrying once in 45s — {str(exc)[:150]}",
                            kind="error",
                        )
                        for _ in range(9):
                            if _stopped():
                                break
                            time.sleep(5)
                        if not _stopped():
                            continue
                    errors.append(f"{cls.name}: {exc}")
                    activity.log(job.id, f"{cls.name}: failed — {str(exc)[:200]}", kind="error")
                    break
            job.findings = prioritize(findings)
            save_job(job)
            time.sleep(2)  # let CPU/thermals settle between heavy scanners
    else:
        with ThreadPoolExecutor(max_workers=min(max_parallel, len(ordered) or 1)) as pool:
            futures = {pool.submit(_run, cls): cls.name for cls in ordered}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    scanner_name, result, coverage = future.result()
                    job.scanners_run.append(scanner_name)
                    findings.extend(result)
                    if coverage:
                        job.coverage[scanner_name] = coverage
                except Exception as exc:
                    errors.append(f"{name}: {exc}")
                job.findings = prioritize(findings)
                save_job(job)
                stop = _stopped()
                if stop == "finish":
                    pool.shutdown(wait=False, cancel_futures=True)
                    return finalize_scan(job, findings, errors, early=True)
                if stop == "pause":
                    pool.shutdown(wait=False, cancel_futures=True)
                    return _pause(job, findings, errors)

    # Post-pass: scanners discover far more URLs than their own checks
    # cover (e.g. /ftp/*.kdbx seen only as a URL inside a merged header
    # finding). Re-examine discovered URLs for exposed sensitive files.
    # Pure pattern matching — never fails the scan. Skipped on resume if
    # it already ran (its output is already in findings). Skipped entirely
    # when the dashboard picker excluded sensitive-files.
    want_sensitive = not requested or "sensitive-files" in requested
    if "sensitive-files" not in job.scanners_run and not want_sensitive:
        job.scanners_run.append("sensitive-files")
        # Intentionally no findings: user deselected this check.
        pass
    elif "sensitive-files" not in job.scanners_run:
        stop = _stopped()
        if stop == "finish":
            return finalize_scan(job, findings, errors, early=True)
        if stop == "pause":
            return _pause(job, findings, errors)
        try:
            activity.current(job.id, "sensitive-files: probing discovered URLs…")
            auth_pair = (
                (dict(job.auth.headers), dict(job.auth.cookies)) if job.auth else None
            )
            sensitive = flag_sensitive_files(job.target_url, findings, auth_pair)
            # Active probes: high-value paths no crawler reliably discovers
            # (/.git/HEAD, /.git/config, /.env, /.DS_Store). Runs even when
            # no other scanner found any URL (e.g. headers-only scans).
            try:
                sensitive += probe_wellknown(job.target_url, auth_pair)
            except Exception as exc:
                errors.append(f"sensitive-files-probe: {exc}")
            if sensitive:
                job.findings = prioritize(job.findings + sensitive)
            job.scanners_run.append("sensitive-files")
        except Exception as exc:
            errors.append(f"sensitive-files: {exc}")
    if prior_error and prior_error not in errors:
        errors = [prior_error] + errors
    activity.log(job.id, f"scan finished", kind="done")
    return finalize_scan(job, findings, errors)
