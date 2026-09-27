"""OSV.dev API client — query for known vulnerabilities in dependencies.

Uses the OSV.dev batch query API (POST /v1/querybatch) to look up
vulnerabilities for Maven packages extracted from the APK.  This is a
free, no-auth API maintained by Google.

The runner produces IRToolOutput with IRFinding entries for each
vulnerability found.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from scan_toolkit.intermediate import IRFinding, IRToolOutput
from scan_toolkit.tools.base import ToolRunner
from scan_toolkit.tools.deps import Dependency

log = logging.getLogger(__name__)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_RAW_JSON = "osv_results.json"
_MAX_BATCH = 1000  # OSV batch limit


class OsvRunner(ToolRunner):
    """Query OSV.dev for vulnerabilities in extracted dependencies."""

    name = "osv"

    def __init__(self, workdir: Path, *, transport: httpx.BaseTransport | None = None):
        super().__init__(workdir)
        self._transport = transport

    def available(self) -> bool:
        # OSV.dev is a public API — always "available" (failures handled at call time).
        return True

    def run(self, dependencies: list[Dependency]) -> IRToolOutput:  # type: ignore[override]
        if not dependencies:
            return IRToolOutput(tool=self.name, errors=["no dependencies to scan"])

        queries = []
        for dep in dependencies:
            q: dict[str, Any] = {"package": {"name": dep.name, "ecosystem": dep.ecosystem}}
            if dep.version:
                q["version"] = dep.version
            queries.append(q)

        # Batch in chunks if needed.
        all_results: list[dict] = []
        errors: list[str] = []
        for i in range(0, len(queries), _MAX_BATCH):
            chunk = queries[i:i + _MAX_BATCH]
            try:
                results = self._query_batch(chunk)
                all_results.extend(results)
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(f"OSV batch query failed: {exc}")

        # Write raw results.
        raw_path = self.tool_dir / _RAW_JSON
        raw_path.write_text(json.dumps(all_results, indent=2, default=str))

        # Convert to IRFinding.
        findings = _osv_to_findings(dependencies, all_results)

        return IRToolOutput(
            tool=self.name,
            version="osv.dev-api-v1",
            raw_path=str(raw_path.resolve()),
            findings=findings,
            errors=errors,
        )

    def _query_batch(self, queries: list[dict]) -> list[dict]:
        """POST to OSV.dev batch endpoint, return list of result dicts."""
        kwargs: dict[str, Any] = {
            "timeout": self._settings.tool_timeout_seconds,
            "follow_redirects": True,
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport

        with httpx.Client(**kwargs) as client:
            resp = client.post(_OSV_BATCH_URL, json={"queries": queries})
            resp.raise_for_status()
            data = resp.json()
            return data.get("results", [])


def _osv_to_findings(
    deps: list[Dependency], results: list[dict]
) -> list[IRFinding]:
    """Convert OSV batch results to IRFinding list."""
    findings: list[IRFinding] = []
    for i, result in enumerate(results):
        vulns = result.get("vulns") or []
        dep = deps[i] if i < len(deps) else None
        dep_name = dep.name if dep else "unknown"
        dep_version = dep.version if dep else "unknown"
        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            aliases = vuln.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE-")), None)
            summary = vuln.get("summary") or vuln.get("details", "")[:500]
            severity_str = _osv_severity(vuln)
            cwes = _extract_cwes(vuln)

            findings.append(IRFinding(
                tool="osv",
                rule_id=vuln_id,
                category="dependency_vulnerability",
                title=f"{vuln_id}: {dep_name}" + (f"@{dep_version}" if dep_version else ""),
                severity=severity_str,
                confidence="high",  # OSV matches are version-precise
                cwe_id=cwes[0] if cwes else None,
                file=None,
                description=summary[:2000],
                evidence=json.dumps({
                    "vuln_id": vuln_id,
                    "cve": cve,
                    "aliases": aliases,
                    "package": dep_name,
                    "version": dep_version,
                    "fixed_versions": _fixed_versions(vuln),
                }, indent=2),
                recommendation=_remediation(vuln, dep_name),
                raw={
                    "osv_id": vuln_id,
                    "cve": cve,
                    "aliases": aliases,
                    "ecosystem": dep.ecosystem if dep else "Maven",
                    "severity_raw": vuln.get("database_specific", {}).get("severity"),
                },
            ))
    return findings


def _osv_severity(vuln: dict) -> str:
    """Derive severity string from OSV vulnerability data."""
    # Try CVSS from severity array.
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS vector — parse the base score if present
        if "CVSS" in sev.get("type", ""):
            try:
                # Extract numeric score from vector or direct score field
                score = float(score_str) if score_str.replace(".", "").isdigit() else None
                if score is not None:
                    if score >= 9.0:
                        return "critical"
                    if score >= 7.0:
                        return "high"
                    if score >= 4.0:
                        return "medium"
                    return "low"
            except (ValueError, TypeError):
                pass

    # Try database_specific severity.
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if isinstance(db_sev, str):
        low = db_sev.lower()
        if low in ("critical", "high", "medium", "low", "info"):
            return low

    # Default to medium (conservative — not high, not dismissive).
    return "medium"


def _extract_cwes(vuln: dict) -> list[str]:
    """Pull CWE IDs from OSV vulnerability data."""
    cwes = vuln.get("database_specific", {}).get("cwe_ids", [])
    if isinstance(cwes, list):
        return [c for c in cwes if isinstance(c, str) and c.startswith("CWE-")]
    return []


def _fixed_versions(vuln: dict) -> list[str]:
    """Extract fixed versions from the affected ranges."""
    fixed: list[str] = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return fixed


def _remediation(vuln: dict, dep_name: str) -> str:
    """Generate a remediation string."""
    fixed = _fixed_versions(vuln)
    if fixed:
        return f"Upgrade {dep_name} to version {fixed[-1]} or later."
    return f"Check for updates to {dep_name} or find an alternative library."
