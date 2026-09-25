"""Grype CLI runner — fallback/alternative to OSV.dev for SCA.

Grype scans a directory (or container image) for known vulnerabilities in
dependencies.  We point it at the decompiled APK directory and parse the
JSON output.

Config: SCAN_TOOLKIT_GRYPE_BIN (default: 'grype')
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from scan_toolkit.intermediate import IRFinding, IRToolOutput
from scan_toolkit.tools.base import ToolRunner

log = logging.getLogger(__name__)

_RAW_JSON = "grype_results.json"


class GrypeRunner(ToolRunner):
    """Run grype against a decompiled APK directory."""

    name = "grype"

    def available(self) -> bool:
        return self._which(self._settings.grype_bin) is not None

    def run(self, target_dir: Path) -> IRToolOutput:  # type: ignore[override]
        if not self.available():
            return IRToolOutput(tool=self.name, errors=["grype not available on this machine"])
        if not target_dir.exists():
            return IRToolOutput(tool=self.name, errors=[f"target directory does not exist: {target_dir}"])

        binary = self._which(self._settings.grype_bin)
        raw_path = self.tool_dir / _RAW_JSON

        proc = self._run_cmd([
            binary,
            f"dir:{target_dir}",
            "-o", "json",
        ])

        if proc.returncode != 0:
            return IRToolOutput(
                tool=self.name,
                errors=[proc.stderr.strip() or proc.stdout.strip() or "grype failed"],
            )

        # Grype outputs JSON to stdout.
        try:
            raw = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return IRToolOutput(
                tool=self.name,
                errors=[f"grype output not valid JSON: {exc}"],
            )

        raw_path.write_text(json.dumps(raw, indent=2))

        findings = _grype_to_findings(raw)
        version = raw.get("descriptor", {}).get("version")

        return IRToolOutput(
            tool=self.name,
            version=version,
            raw_path=str(raw_path.resolve()),
            findings=findings,
        )


def _grype_to_findings(raw: dict) -> list[IRFinding]:
    """Convert Grype JSON output to IRFinding list."""
    findings: list[IRFinding] = []
    for match in raw.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        related = match.get("relatedVulnerabilities", [])

        vuln_id = vuln.get("id", "")
        severity_raw = vuln.get("severity", "").lower()
        severity = severity_raw if severity_raw in ("critical", "high", "medium", "low") else "medium"

        pkg_name = artifact.get("name", "unknown")
        pkg_version = artifact.get("version", "unknown")
        pkg_type = artifact.get("type", "")

        # Try to get CVE from related vulnerabilities.
        cve = None
        cwes: list[str] = []
        for rv in related:
            rv_id = rv.get("id", "")
            if rv_id.startswith("CVE-"):
                cve = rv_id
            for cwe in rv.get("cwes", []):
                cwes.append(f"CWE-{cwe}" if not str(cwe).startswith("CWE-") else str(cwe))
        if not cve and vuln_id.startswith("CVE-"):
            cve = vuln_id

        description = vuln.get("description", "")
        fix_versions = [
            fv.get("version") for fv in vuln.get("fix", {}).get("versions", [])
            if fv.get("version")
        ]

        findings.append(IRFinding(
            tool="grype",
            rule_id=vuln_id,
            category="dependency_vulnerability",
            title=f"{vuln_id}: {pkg_name}@{pkg_version}",
            severity=severity,
            confidence="high",
            cwe_id=cwes[0] if cwes else None,
            file=None,
            description=description[:2000] or f"Vulnerability {vuln_id} in {pkg_name}",
            evidence=json.dumps({
                "vuln_id": vuln_id,
                "cve": cve,
                "package": pkg_name,
                "version": pkg_version,
                "type": pkg_type,
                "fix_versions": fix_versions,
            }, indent=2),
            recommendation=(
                f"Upgrade {pkg_name} to version {fix_versions[-1]} or later."
                if fix_versions
                else f"Check for updates to {pkg_name}."
            ),
            raw={
                "grype_id": vuln_id,
                "cve": cve,
                "severity_raw": severity_raw,
                "artifact_type": pkg_type,
            },
        ))

    return findings
