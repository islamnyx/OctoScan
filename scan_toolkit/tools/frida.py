"""Frida runner — spawn the app under bundled instrumentation scripts.

Runs each ``*.js`` in ``SCAN_TOOLKIT_FRIDA_SCRIPTS_DIR`` via the Frida CLI::

    frida -D <device> -l <script> -f <package> --no-pause

Each script emits newline-delimited JSON via ``send()``; stdout lines that
parse as event objects (``{"script": ..., "event": ...}``) become findings
via ``normalize.frida_findings``.  ``hook-error`` events are surfaced as
tool errors, not findings.  Non-JSON lines (frida CLI chatter) are ignored.

Requires a booted emulator/device with frida-server running — the emulator
runner (tools/emulator.py) provides the device; direct-attached devices work
too when ``device`` is given explicitly.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from scan_toolkit.intermediate import IRToolOutput
from scan_toolkit.normalize import frida_findings
from scan_toolkit.tools.base import ToolRunner

log = logging.getLogger(__name__)


class FridaRunner(ToolRunner):
    name = "frida"

    def available(self) -> bool:
        return self._which(self._settings.frida_bin) is not None

    def scripts(self) -> list[Path]:
        scripts_dir = self._settings.frida_scripts_dir
        if not scripts_dir.exists():
            return []
        return sorted(scripts_dir.glob("*.js"))

    def run(  # type: ignore[override]
        self,
        package: str,
        device: str | None = None,
        scripts: list[Path | str] | None = None,
    ) -> IRToolOutput:
        if not self.available():
            return IRToolOutput(tool=self.name, errors=[
                "frida CLI not available — install frida-tools (pip install frida-tools) "
                "and ensure frida-server runs on the target device",
            ])
        if not package or not package.strip():
            return IRToolOutput(tool=self.name, errors=["no app package name given"])

        selected = [Path(s) for s in scripts] if scripts is not None else self.scripts()
        if not selected:
            return IRToolOutput(tool=self.name, errors=[
                f"no Frida scripts in {self._settings.frida_scripts_dir}",
            ])

        binary = self._which(self._settings.frida_bin)
        all_events: list[dict] = []
        hook_errors: list[str] = []
        raw_lines: list[str] = []

        for script in selected:
            proc = self._run_cmd([
                binary,
                *(["-D", device] if device else ["-U"]),
                "-l", str(script),
                "-f", package.strip(),
                "--no-pause",
            ])
            raw_lines.append(f"### {script.name} (rc={proc.returncode})")
            raw_lines.append(proc.stdout)
            if proc.stderr.strip():
                raw_lines.append(f"[stderr] {proc.stderr.strip()}")
            if proc.returncode != 0:
                hook_errors.append(
                    f"{script.name}: frida exited rc={proc.returncode} "
                    f"({(proc.stderr or proc.stdout).strip()[:200]})"
                )
            events, errs = _parse_frida_stdout(proc.stdout)
            all_events.extend(events)
            hook_errors.extend(f"{script.name}: {e}" for e in errs)

        raw_path = self.tool_dir / "frida_events.jsonl"
        raw_path.write_text("\n".join(raw_lines))

        return IRToolOutput(
            tool=self.name,
            version=self._version_from_output(""),
            raw_path=str(raw_path.resolve()),
            findings=frida_findings(all_events),
            errors=hook_errors,
        )


def _parse_frida_stdout(stdout: str) -> tuple[list[dict], list[str]]:
    """Split frida CLI stdout into (events, hook-error strings).

    Newer frida CLIs print ``send()`` payloads as bare JSON lines; older
    ones wrap them as ``{"type": "send", "payload": ...}``.  Both shapes
    are accepted; anything else is ignored as CLI chatter.
    """
    events: list[dict] = []
    hook_errors: list[str] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = _unwrap(obj)
        if event is None:
            continue
        if event.get("event") == "hook-error":
            hook_errors.append(
                f"{event.get('hook', '?')}: {event.get('error', 'unknown')}"
            )
        else:
            events.append(event)
    return events, hook_errors


def _unwrap(obj: Any) -> dict | None:
    """Normalise one stdout line to an event dict, or None to skip."""
    if not isinstance(obj, dict):
        return None
    # New CLI: the payload IS the line.
    if isinstance(obj.get("event"), str):
        return obj
    # Old CLI: {"type": "send", "payload": {...} or "<json string>"}.
    payload = obj.get("payload")
    if isinstance(payload, dict) and isinstance(payload.get("event"), str):
        return payload
    if isinstance(payload, str):
        try:
            inner = json.loads(payload)
        except json.JSONDecodeError:
            return None
        if isinstance(inner, dict) and isinstance(inner.get("event"), str):
            return inner
    return None
