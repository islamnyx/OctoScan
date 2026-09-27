from __future__ import annotations

import json
from pathlib import Path

from scan_toolkit.config import get_settings
from scan_toolkit.intermediate import IRToolOutput
from scan_toolkit.normalize import semgrep_findings
from scan_toolkit.tools.base import ToolRunner

_RAW_JSON = "results.json"


class SemgrepRunner(ToolRunner):
    """semgrep --json against decompiled Java source, using the bundled ruleset."""

    name = "semgrep"

    def available(self) -> bool:
        return self._which(self._settings.semgrep_bin) is not None

    @staticmethod
    def rules_dir() -> Path:
        """Bundled starter mobile ruleset lives in the package."""
        return get_settings().semgrep_rules_dir

    def run(self, target_dir: Path) -> IRToolOutput:
        if not self.available():
            return IRToolOutput(tool=self.name, errors=["semgrep not available on this machine"])
        if not target_dir or not target_dir.exists():
            return IRToolOutput(tool=self.name, errors=["no decompiled source directory to scan"])
        binary = self._which(self._settings.semgrep_bin)
        raw_path = self.tool_dir / _RAW_JSON
        cmd = [
            binary,
            "--config",
            str(self.rules_dir()),
            "--json",
            "--no-git-ignore",  # decompiled source is outside any git repo
            "--output",
            str(raw_path),
            "--severity",
            "ERROR",
            "--severity",
            "WARNING",
            str(target_dir),
        ]
        # push all extra configured configs (e.g. a registry pack) onto the command
        extra_raw = self._settings.semgrep_extra_configs or ""
        for extra in [c.strip() for c in extra_raw.split(",") if c.strip()]:
            cmd += ["--config", extra]
        proc = self._run_cmd(cmd)
        if proc.returncode not in (0, 1):  # semgrep returns 1 when findings are found
            return IRToolOutput(
                tool=self.name,
                raw_path=str(raw_path),
                errors=[proc.stderr.strip() or proc.stdout.strip() or "semgrep failed"],
            )
        if not raw_path.exists():
            return IRToolOutput(
                tool=self.name,
                raw_path=str(raw_path),
                errors=["semgrep produced no JSON output artifact"],
            )
        try:
            raw = json.loads(raw_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            return IRToolOutput(
                tool=self.name,
                raw_path=str(raw_path),
                errors=[f"semgrep JSON unreadable: {exc}"],
            )
        return IRToolOutput(
            tool=self.name,
            version=self._version_from_output(proc.stdout) or raw.get("version"),
            raw_path=str(raw_path.resolve()),
            findings=semgrep_findings(raw),
        )