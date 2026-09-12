import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from app.config import settings
from app.models import Finding, ScanJob, ScanStatus
from app.normalize import prioritize
from app.scanners import SCANNERS
from app.scanners.headers_scanner import HeadersScanner
from app.scanners.nikto_scanner import NiktoScanner
from app.scanners.nmap_scanner import NmapScanner
from app.scanners.nuclei_scanner import NucleiScanner
from app.scanners.testssl_scanner import TestsslScanner
from app.scanners.zap_scanner import ZapScanner
from app.sensitive import flag_sensitive_files
from app.store import load_job, save_job

# Light -> heavy so a crash/interrupt still leaves useful partial results
# and the laptop never spikes all heavy scanners at once.
SEQUENTIAL_ORDER = [
    HeadersScanner,
    NmapScanner,
    TestsslScanner,
    NiktoScanner,
    NucleiScanner,
    ZapScanner,
]


def run_scan(scan_id: str) -> ScanJob:
    job = load_job(scan_id)
    if job is None:
        raise RuntimeError(f"scan {scan_id} not found")
    job.status = ScanStatus.running
    job.started_at = datetime.now(timezone.utc)
    save_job(job)

    workdir = settings.data_dir / "scans" / job.id
    workdir.mkdir(parents=True, exist_ok=True)
    findings: list[Finding] = []
    errors: list[str] = []

    def _run(scanner_cls):
        scanner = scanner_cls(job.target_url, workdir)
        return scanner.name, scanner.run()

    # Lower CPU priority so the desktop stays responsive on laptops.
    try:
        os.nice(10)
    except Exception:
        pass

    max_parallel = max(1, settings.scan_max_parallel)
    ordered = [c for c in SEQUENTIAL_ORDER if c in SCANNERS]

    if max_parallel == 1:
        # Sequential low-power mode (default): one scanner at a time,
        # checkpoint after each so a shutdown leaves partial results.
        for cls in ordered:
            try:
                scanner_name, result = _run(cls)
                job.scanners_run.append(scanner_name)
                findings.extend(result)
            except Exception as exc:
                errors.append(f"{cls.name}: {exc}")
            job.findings = prioritize(findings)
            save_job(job)
            time.sleep(2)  # let CPU/thermals settle between heavy scanners
    else:
        with ThreadPoolExecutor(max_workers=min(max_parallel, len(ordered))) as pool:
            futures = {pool.submit(_run, cls): cls.name for cls in ordered}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    scanner_name, result = future.result()
                    job.scanners_run.append(scanner_name)
                    findings.extend(result)
                except Exception as exc:
                    errors.append(f"{name}: {exc}")
                job.findings = prioritize(findings)
                save_job(job)

    job.findings = prioritize(findings)
    # Post-pass: scanners discover far more URLs than their own checks
    # cover (e.g. /ftp/*.kdbx seen only as a URL inside a merged header
    # finding). Re-examine discovered URLs for exposed sensitive files.
    # Pure pattern matching — never fails the scan.
    try:
        sensitive = flag_sensitive_files(job.target_url, job.findings)
        if sensitive:
            job.findings = prioritize(job.findings + sensitive)
        job.scanners_run.append("sensitive-files")
    except Exception as exc:
        errors.append(f"sensitive-files: {exc}")
    job.finished_at = datetime.now(timezone.utc)
    if errors and not findings:
        job.status = ScanStatus.failed
        job.error = "; ".join(errors)
    else:
        job.status = ScanStatus.completed
        job.error = "; ".join(errors) if errors else None
    save_job(job)
    return job
