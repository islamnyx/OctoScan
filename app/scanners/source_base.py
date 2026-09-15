"""Source-scanner base (Phase 2). URL scanners use BaseScanner;
source scanners operate on a cloned repo directory instead.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from app.models import Finding


class SourceScanner(ABC):
    name: str

    def __init__(self, repo_path: Path, repo_url: str = ""):
        self.repo_path = repo_path
        self.repo_url = repo_url

    @abstractmethod
    def run(self) -> list[Finding]:
        raise NotImplementedError
