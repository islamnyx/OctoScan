"""OSV dependency scan (Phase 2, P3).

Runs `osv-scanner scan source` over the cloned repo (lockfiles /
manifests) and reports known CVEs per package. Falls back to an
informational note when the binary is missing so repo scans work
without installs. `--no-ignore` is required: clones carry a .git dir
whose ignore rules otherwise hide every manifest.
"""
from __future__ import annotations

import json
import subprocess

from app.config import settings
from app.models import Finding, Severity
from app.scanners.source_base import SourceScanner

SEV_MAP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MODERATE": Severity.medium,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
}


def _fixed_versions(vuln: dict) -> list[str]:
    fixed: list[str] = []
    affected = vuln.get("affected")
    if not isinstance(affected, list):
        return fixed
    for aff in affected:
        if not isinstance(aff, dict):
            continue
        ranges = aff.get("ranges")
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            if not isinstance(rng, dict):
                continue
            events = rng.get("events")
            if not isinstance(events, list):
                continue
            for ev in events:
                if isinstance(ev, dict) and ev.get("fixed") and ev["fixed"] not in fixed:
                    fixed.append(str(ev["fixed"]))
    return fixed[:3]


class OsvScanner(SourceScanner):
    name = "osv"

    def run(self) -> list[Finding]:
        out = self.repo_path / ".osv-report.json"
        cmd = [
            settings.osv_bin, "scan", "source",
            "--no-ignore",
            "--format", "json",
            "--output-file", str(out),
            "--recursive", str(self.repo_path),
        ]
        try:
            # Exit 1 = vulns found, not a failure; only crashes matter.
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            return self._unavailable("osv-scanner binary not found")
        except subprocess.TimeoutExpired:
            raise RuntimeError("osv-scanner timed out")
        if not out.exists():
            return self._unavailable("osv-scanner produced no report")
        try:
            data = json.loads(out.read_text() or "{}")
            results = data.get("results", [])
        except Exception:
            return self._unavailable("osv-scanner output unparseable")
        if not isinstance(results, list):
            return self._unavailable("osv-scanner output unparseable")

        findings: list[Finding] = []
        for res in results:
            if not isinstance(res, dict):
                continue
            lockfile = self._rel(str((res.get("source") or {}).get("path", "")) or "lockfile")
            packages = res.get("packages")
            if not isinstance(packages, list):
                continue
            for pkg in packages:
                if not isinstance(pkg, dict):
                    continue
                info = pkg.get("package") or {}
                name = str(info.get("name", "?"))
                version = str(info.get("version", "?"))
                ecosystem = str(info.get("ecosystem", "?"))
                vulns = pkg.get("vulnerabilities")
                if not isinstance(vulns, list):
                    continue
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue
                    vid = str(vuln.get("id", "OSV"))
                    aliases = [str(a) for a in (vuln.get("aliases") or []) if isinstance(a, str)]
                    cve = next((a for a in aliases if a.startswith("CVE-")), None)
                    db = vuln.get("database_specific")
                    db = db if isinstance(db, dict) else {}
                    sev = SEV_MAP.get(str(db.get("severity", "")).upper(), Severity.medium)
                    cwe = [str(c) for c in (db.get("cwe_ids") or []) if isinstance(c, str)][:5]
                    summary = str(vuln.get("summary") or vuln.get("details") or vid)[:300]
                    fixed = _fixed_versions(vuln)
                    rec = f"Upgrade {name} to {', '.join('>=' + f for f in fixed)}." if fixed else f"Upgrade {name} to a patched release."
                    findings.append(
                        Finding(
                            scanner=self.name,
                            title=f"OSV {name}@{version}: {vid}" + (f" ({cve})" if cve else ""),
                            severity=sev,
                            description=f"{summary} [{ecosystem} {name}@{version}, {vid}].",
                            evidence=f"{name}@{version} ({ecosystem})",
                            location=f"{self.repo_url}#{lockfile}" if self.repo_url else lockfile,
                            recommendation=rec,
                            cve=cve,
                            cwe=cwe,
                            raw={"package": name, "version": version, "ecosystem": ecosystem,
                                 "osv_id": vid, "aliases": aliases, "fixed": fixed},
                        )
                    )
                    if len(findings) >= 100:
                        return findings
        if not findings:
            findings.append(Finding(
                scanner=self.name, title="No known CVEs in dependencies (osv)",
                severity=Severity.info,
                description="OSV scan of lockfiles/manifests completed without matches.",
                location=self.repo_url or str(self.repo_path),
            ))
        return findings

    def _unavailable(self, note: str) -> list[Finding]:
        return [Finding(
            scanner=self.name, title="SCA unavailable (osv-scanner not installed)",
            severity=Severity.info,
            description=f"Dependency scan skipped. {note}; install osv-scanner for CVE coverage.",
            location=self.repo_url or str(self.repo_path),
        )]
