import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from app import control
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
    job.gate, job.gate_details = evaluate_gate(job.findings)
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

    def _run(scanner_cls):
        scanner = scanner_cls(job.target_url, workdir)
        findings_result = scanner.run()
        coverage_result = dict(getattr(scanner, "coverage", None) or {})
        return scanner.name, findings_result, coverage_result

    # Lower CPU priority so the desktop stays responsive on laptops.
    try:
        os.nice(10)
    except Exception:
        pass

    max_parallel = max(1, settings.scan_max_parallel)
    done = set(job.scanners_run)
    ordered = [c for c in SEQUENTIAL_ORDER if c in SCANNERS and c.name not in done]

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
            try:
                scanner_name, result, coverage = _run(cls)
                job.scanners_run.append(scanner_name)
                findings.extend(result)
                if coverage:
                    job.coverage[scanner_name] = coverage
            except Exception as exc:
                errors.append(f"{cls.name}: {exc}")
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
    # it already ran (its output is already in findings).
    if "sensitive-files" not in job.scanners_run:
        stop = _stopped()
        if stop == "finish":
            return finalize_scan(job, findings, errors, early=True)
        if stop == "pause":
            return _pause(job, findings, errors)
    try:
        sensitive = flag_sensitive_files(job.target_url, findings)
        # Active probes: high-value paths no crawler reliably discovers
        # (/.git/HEAD, /.git/config, /.env, /.DS_Store). Runs even when
        # no other scanner found any URL (e.g. headers-only scans).
        try:
            sensitive += probe_wellknown(job.target_url)
        except Exception as exc:
            errors.append(f"sensitive-files-probe: {exc}")
        if sensitive:
            job.findings = prioritize(job.findings + sensitive)
        job.scanners_run.append("sensitive-files")
    except Exception as exc:
        errors.append(f"sensitive-files: {exc}")
    if prior_error and prior_error not in errors:
        errors = [prior_error] + errors
    return finalize_scan(job, findings, errors)
