from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.models import Finding


class BaseScanner(ABC):
    name: str

    def __init__(self, target_url: str, workdir: Path):
        self.target_url = target_url.rstrip("/")
        self.workdir = workdir
        parsed = urlparse(self.target_url)
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.scheme = parsed.scheme or "http"
        # Coverage metadata (scan scope actually achieved: spider axes,
        # ascan targets scanned vs cap, skips). Reported here instead of
        # as Severity.info findings so counts() only reflects real vulns.
        self.coverage: dict[str, Any] = {}

    @abstractmethod
    def run(self) -> list[Finding]:
        raise NotImplementedError
