import json
import re
from pathlib import Path

from app.config import settings
from app.models import ScanAuth, ScanJob

_SCAN_ID_RE = re.compile(r"^[a-fA-F0-9]{8,64}$")


def _path(scan_id: str) -> Path:
    # Path-traversal guard (WSTG OTG-AUTHZ-001): scan_id is a hex uuid we
    # generated, never a free-form path. Reject anything else fail-closed.
    if not _SCAN_ID_RE.match(scan_id or "") or ".." in scan_id or "/" in scan_id:
        raise ValueError("invalid scan id")
    return settings.data_dir / "scans" / scan_id / "job.json"


def _auth_path(scan_id: str) -> Path:
    # Session material (cookies, Authorization headers) lives in a
    # sidecar, never inside job.json — so stored results, exports and
    # reports can't leak live sessions. Resume reattaches it on load.
    if not _SCAN_ID_RE.match(scan_id or "") or ".." in scan_id or "/" in scan_id:
        raise ValueError("invalid scan id")
    return settings.data_dir / "scans" / scan_id / "auth.json"


def save_job(job: ScanJob) -> None:
    path = _path(job.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = job.model_dump(mode="json")
    auth = data.pop("auth", None)
    path.write_text(json.dumps(data, indent=2))
    if auth:
        _auth_path(job.id).write_text(json.dumps(auth, indent=2))
    else:
        try:
            _auth_path(job.id).unlink(missing_ok=True)
        except Exception:
            pass


def load_job(scan_id: str) -> ScanJob | None:
    try:
        path = _path(scan_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    job = ScanJob.model_validate_json(path.read_text())
    if job.auth is None:
        # Sidecar (new files) — or embedded auth migrated from old files
        # on the next save.
        try:
            sidecar = _auth_path(scan_id)
            if sidecar.exists():
                job.auth = ScanAuth.model_validate(json.loads(sidecar.read_text()))
        except Exception:
            pass
    return job


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
