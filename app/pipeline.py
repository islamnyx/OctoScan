from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from app.config import settings
from app.models import Finding, ScanJob, ScanStatus
from app.normalize import prioritize
from app.scanners import SCANNERS
from app.store import load_job, save_job


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

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_run, cls): cls.name for cls in SCANNERS}
        for future in as_completed(futures):
            name = futures[future]
            try:
                scanner_name, result = future.result()
                job.scanners_run.append(scanner_name)
                findings.extend(result)
            except Exception as exc:
                errors.append(f"{name}: {exc}")

    job.findings = prioritize(findings)
    job.finished_at = datetime.now(timezone.utc)
    if errors and not findings:
        job.status = ScanStatus.failed
        job.error = "; ".join(errors)
    else:
        job.status = ScanStatus.completed
        job.error = "; ".join(errors) if errors else None
    save_job(job)
    return job
