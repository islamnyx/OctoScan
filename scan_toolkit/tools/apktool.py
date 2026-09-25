from __future__ import annotations

from pathlib import Path

from scan_toolkit.intermediate import IRToolOutput
from scan_toolkit.tools.base import ToolRunner


class ApktoolRunner(ToolRunner):
    """apktool d — decode resources + smali to a directory (no findings)."""

    name = "apktool"

    def available(self) -> bool:
        return self._which(self._settings.apktool_bin) is not None

    def run(self, apk: Path) -> IRToolOutput:
        if not self.available():
            return IRToolOutput(tool=self.name, errors=["apktool not available on this machine"])
        binary = self._which(self._settings.apktool_bin)
        out_dir = self.tool_dir / "decoded"
        proc = self._run_cmd([binary, "d", "-f", "-o", out_dir, apk.resolve()])
        if proc.returncode != 0 or not out_dir.exists():
            return IRToolOutput(
                tool=self.name,
                raw_path=str(out_dir),
                errors=[proc.stderr.strip() or proc.stdout.strip() or "apktool decode failed"],
            )
        return IRToolOutput(
            tool=self.name,
            version=self._version_from_output(proc.stdout),
            raw_path=str(out_dir.resolve()),
        )