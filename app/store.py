import json
import re
from pathlib import Path

from app.config import settings
from app.models import ScanJob

_SCAN_ID_RE = re.compile(r"^[a-fA-F0-9]{8,64}$")


def _path(scan_id: str) -> Path:
    # Path-traversal guard (WSTG OTG-AUTHZ-001): scan_id is a hex uuid we
    # generated, never a free-form path. Reject anything else fail-closed.
    if not _SCAN_ID_RE.match(scan_id or "") or ".." in scan_id or "/" in scan_id:
        raise ValueError("invalid scan id")
    return settings.data_dir / "scans" / scan_id / "job.json"


def save_job(job: ScanJob) -> None:
    path = _path(job.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(job.model_dump_json(indent=2))


def load_job(scan_id: str) -> ScanJob | None:
    try:
        path = _path(scan_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    return ScanJob.model_validate_json(path.read_text())


def list_jobs() -> list[ScanJob]:
    jobs: list[ScanJob] = []
    root = settings.data_dir / "scans"
    if not root.exists():
        return jobs
    for folder in root.iterdir():
        if not folder.is_dir():
            continue
        # Skip stray files / traversal artifacts.
        if not _SCAN_ID_RE.match(folder.name):
            continue
        job_file = folder / "job.json"
        if job_file.exists():
            try:
                jobs.append(ScanJob.model_validate_json(job_file.read_text()))
            except Exception:
                continue
    jobs.sort(key=lambda j: j.created_at, reverse=True)
    return jobs
