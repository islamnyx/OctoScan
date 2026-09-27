"""mitmproxy runner — passive analysis of captured API traffic (HAR).

The runner does NOT drive the app (that needs the Phase 8 emulator).
It parses analyst-captured per-role HAR files (mitmdump ``--savehar``)
and runs deterministic passive checks (cleartext HTTP, secrets in URLs).

Standard capture workflow for the analyst::

    mitmdump --mode regular -w flows/user.mitm --savehar flows/user.har
    # drive the app as the 'user' test account, then Ctrl+C; repeat per role

Scan interface: ``run(har_path=...)`` for one file, or
``run_all(flows_dir=...)`` for the whole per-role directory.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from scan_toolkit.api_traffic import load_role_captures, parse_har, passive_checks
from scan_toolkit.intermediate import IRToolOutput
from scan_toolkit.tools.base import ToolRunner

log = logging.getLogger(__name__)


class MitmRunner(ToolRunner):
    """Parse HAR captures + run passive checks. No live proxy involved."""

    name = "mitmproxy"

    def available(self) -> bool:
        # Parsing needs no binary — always available.  If the analyst wants
        # live capture, mitmdump presence is reported in notes by the stage.
        return True

    def run(self, har_path: Path) -> IRToolOutput:  # type: ignore[override]
        """Parse one HAR file and run passive checks over its calls."""
        if not har_path.exists():
            return IRToolOutput(tool=self.name, errors=[f"HAR file not found: {har_path}"])
        try:
            har = json.loads(har_path.read_text())
        except json.JSONDecodeError as exc:
            return IRToolOutput(tool=self.name, errors=[f"{har_path.name} is not valid JSON: {exc}"])
        try:
            calls = parse_har(har, role=har_path.stem)
        except ValueError as exc:
            return IRToolOutput(tool=self.name, errors=[f"{har_path.name}: {exc}"])

        raw_path = self.tool_dir / f"{har_path.stem}_calls.json"
        raw_path.write_text(json.dumps([c.model_dump() for c in calls], indent=2))

        findings = passive_checks(calls)
        return IRToolOutput(
            tool=self.name,
            version="har-passive-v1",
            raw_path=str(raw_path.resolve()),
            findings=findings,
        )

    def run_all(self, flows_dir: Path) -> IRToolOutput:
        """Parse every ``*.har`` in a flows dir (one file per role)."""
        try:
            captures = load_role_captures(flows_dir)
        except ValueError as exc:
            return IRToolOutput(tool=self.name, errors=[str(exc)])
        if not captures:
            return IRToolOutput(
                tool=self.name,
                errors=[f"no .har captures in {flows_dir} — capture traffic per role first"],
            )
        all_findings = []
        for role, calls in captures.items():
            all_findings.extend(passive_checks(calls))

        raw_path = self.tool_dir / "all_calls.json"
        raw_path.write_text(json.dumps(
            {role: [c.model_dump() for c in calls] for role, calls in captures.items()},
            indent=2,
        ))
        return IRToolOutput(
            tool=self.name,
            version="har-passive-v1",
            raw_path=str(raw_path.resolve()),
            findings=all_findings,
        )
