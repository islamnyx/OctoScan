import json
from pathlib import Path

from app.config import settings
from app.models import ScanJob


def _path(scan_id: str) -> Path:
    return settings.data_dir / "scans" / scan_id / "job.json"


def save_job(job: ScanJob) -> None:
    path = _path(job.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(job.model_dump_json(indent=2))


def load_job(scan_id: str) -> ScanJob | None:
    path = _path(scan_id)
    if not path.exists():
        return None
    return ScanJob.model_validate_json(path.read_text())


def list_jobs() -> list[ScanJob]:
    jobs: list[ScanJob] = []
    root = settings.data_dir / "scans"
    if not root.exists():
        return jobs
    for folder in root.iterdir():
        job_file = folder / "job.json"
        if job_file.exists():
            jobs.append(ScanJob.model_validate_json(job_file.read_text()))
    jobs.sort(key=lambda j: j.created_at, reverse=True)
    return jobs
