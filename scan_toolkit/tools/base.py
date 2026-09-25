"""Tool runner base — shared subprocess + availability helpers."""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Sequence

from scan_toolkit.config import get_settings
from scan_toolkit.intermediate import IRToolOutput


class ToolRunner(ABC):
    """A deterministic external scanner invoked via CLI or REST.

    Subclasses expose ``name`` and ``run()`` returning an :class:`IRToolOutput`;
    availability is checked up front so a missing tool degrades a stage to a
    clean per-tool error instead of crashing the whole pipeline.
    """

    name: str

    def __init__(self, workdir: Path):
        # per-stage tools dir, e.g. <stage>/tools/<name>/
        self.workdir = workdir
        self.tool_dir = workdir / self.name
        self.tool_dir.mkdir(parents=True, exist_ok=True)
        self._settings = get_settings()

    # -- availability --------------------------------------------------------

    def _which(self, binary: str) -> str | None:
        """Resolve a configured tool path: absolute path or PATH lookup."""
        b = (binary or "").strip()
        if not b:
            return None
        p = Path(b)
        if p.is_absolute():
            return b if p.exists() else None
        return shutil.which(b)

    # -- subprocess ----------------------------------------------------------

    def _run_cmd(
        self,
        cmd: Sequence[str],
        *,
        timeout: int | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        timeout = timeout or self._settings.tool_timeout_seconds
        return subprocess.run(
            [str(c) for c in cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )

    @staticmethod
    def _version_from_output(out: str) -> str | None:
        """Best-effort first token of the first non-empty version line."""
        for line in (out or "").splitlines():
            line = line.strip()
            if line:
                return line.split()[0]
        return None

    @abstractmethod
    def available(self) -> bool:
        """True if the tool binary/service is usable right now."""

    @abstractmethod
    def run(self, **context) -> IRToolOutput:
        """Run the tool, write raw artifacts under tool_dir, return IRToolOutput."""
        raise NotImplementedError