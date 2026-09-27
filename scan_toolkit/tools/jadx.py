from __future__ import annotations

from pathlib import Path

from scan_toolkit.intermediate import IRToolOutput
from scan_toolkit.tools.base import ToolRunner

_SOURCES_DIR = "sources"


class JadxRunner(ToolRunner):
    """jadx -d — decompile APK to Java source (feeding Semgrep)."""

    name = "jadx"

    def available(self) -> bool:
        return self._which(self._settings.jadx_bin) is not None

    def sources_dir(self) -> Path:
        return self.tool_dir / _SOURCES_DIR

    def run(self, apk: Path) -> IRToolOutput:
        if not self.available():
            return IRToolOutput(tool=self.name, errors=["jadx not available on this machine"])
        binary = self._which(self._settings.jadx_bin)
        out_dir = self.sources_dir()
        proc = self._run_cmd([binary, "-d", out_dir, apk.resolve()])
        if not (out_dir / "sources").exists():
            # No usable output at all — surface only the tail of stderr,
            # never the full progress log (jadx is chatty on stdout).
            err = (proc.stderr or "").strip().splitlines()
            tail = "\n".join(err[-5:]) if err else (proc.stdout or "").strip()[-500:]
            return IRToolOutput(
                tool=self.name,
                raw_path=str(out_dir),
                errors=[tail or "jadx decompile failed"],
            )
        # jadx writes into <out_dir>/sources; keep raw_path at useful root
        return IRToolOutput(
            tool=self.name,
            version=self._probe_version(binary),
            raw_path=str((out_dir / "sources").resolve()),
        )