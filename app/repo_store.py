"""Persistence for repo scans (Phase 2). Mirrors store.py guards."""
from __future__ import annotations

import re
from pathlib import Path

from app.config import settings
from app.models import RepoScanJob

_SCAN_ID_RE = re.compile(r"^[a-fA-F0-9]{8,64}$")


def _path(scan_id: str) -> Path:
    if not _SCAN_ID_RE.match(scan_id or "") or ".." in scan_id or "/" in scan_id:
        raise ValueError("invalid scan id")
    return settings.data_dir / "repos" / scan_id / "job.json"


def save_repo_job(job: RepoScanJob) -> None:
    path = _path(job.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(job.model_dump_json(indent=2))


def load_repo_job(scan_id: str) -> RepoScanJob | None:
    try:
        path = _path(scan_id)
    except ValueError:
        return None
    if not path.exists():
        return None
    return RepoScanJob.model_validate_json(path.read_text())


def list_repo_jobs() -> list[RepoScanJob]:
    jobs: list[RepoScanJob] = []
    root = settings.data_dir / "repos"
    if not root.exists():
        return jobs
    for folder in root.iterdir():
        if not folder.is_dir() or not _SCAN_ID_RE.match(folder.name):
            continue
        job_file = folder / "job.json"
        if job_file.exists():
            try:
                jobs.append(RepoScanJob.model_validate_json(job_file.read_text()))
            except Exception:
                continue
    jobs.sort(key=lambda j: j.created_at, reverse=True)
    return jobs


def repo_workdir(scan_id: str) -> Path:
    return settings.data_dir / "repos" / scan_id / "src"
