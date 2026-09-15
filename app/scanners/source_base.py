"""Source-scanner base (Phase 2). URL scanners use BaseScanner;
source scanners operate on a cloned repo directory instead.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from app.config import ROOT
from app.models import Finding


def repo_relative(repo_path: Path, path: str) -> str:
    """Repo-relative path for titles/locations.

    Binary scanners print paths relative to the process CWD (project
    root), e.g. `data/repos/<id>/src/app/x.js` — relativize so the
    dashboard/API never leak local checkout layout. Falls back to the
    original string for absolute-outside paths.
    """
    try:
        p = Path(path)
        if not p.is_absolute():
            p = ROOT / p
        base = repo_path if repo_path.is_absolute() else ROOT / repo_path
        return str(p.relative_to(base))
    except Exception:
        return path


class SourceScanner(ABC):
    name: str

    def __init__(self, repo_path: Path, repo_url: str = ""):
        self.repo_path = repo_path
        self.repo_url = repo_url

    def _rel(self, path: str) -> str:
        return repo_relative(self.repo_path, path)

    @abstractmethod
    def run(self) -> list[Finding]:
        raise NotImplementedError
