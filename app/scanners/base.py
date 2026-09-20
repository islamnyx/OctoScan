from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from app.models import Finding, ScanAuth


def assert_target_reachable(target_url: str, timeout: float = 10.0) -> None:
    """Fail fast when the target is down instead of emitting fake-clean results.

    Any HTTP response (even 4xx/5xx) counts as reachable — only
    network-level failures raise. Cert verification is off on purpose:
    certificate problems are testssl's job, not a connectivity signal.
    The "CONNECTION FAILURE: " prefix lets the pipeline retry once.
    """
    try:
        httpx.get(target_url, follow_redirects=True, timeout=timeout, verify=False)
    except Exception as exc:
        raise RuntimeError(f"CONNECTION FAILURE: target unreachable: {target_url} ({exc})") from exc


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
        # Session injection for authenticated scans (v1). Set by the
        # pipeline from job.auth after construction; None = anonymous.
        self.auth: ScanAuth | None = None

    def auth_headers(self) -> dict[str, str]:
        """Custom headers to send (Cookie handled separately)."""
        if not self.auth:
            return {}
        return {k: v for k, v in self.auth.headers.items() if k.lower() != "cookie"}

    def auth_cookie_header(self) -> str | None:
        """Combined Cookie header value, or None when no session."""
        if not self.auth:
            return None
        pairs = [f"{k}={v}" for k, v in self.auth.cookies.items()]
        for k, v in self.auth.headers.items():
            if k.lower() == "cookie" and v not in pairs:
                pairs.append(v)
        return "; ".join(pairs) or None

    def _activity(self, message: str) -> None:
        """Live progress for the status page (workdir name = scan id)."""
        try:
            from app import activity

            activity.current(self.workdir.name, f"{self.name}: {message}")
        except Exception:
            pass

    @abstractmethod
    def run(self) -> list[Finding]:
        raise NotImplementedError
