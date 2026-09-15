"""OSV dependency scan (Phase 2, P3 + audit-2 rollup).

Runs `osv-scanner scan source` over the cloned repo (lockfiles /
manifests) and reports known CVEs. Same advisory affecting N installed
versions rolls up into ONE finding listing every install (Q1) instead of
N duplicate rows. `--no-ignore` is required: clones carry a .git dir
whose ignore rules otherwise hide every manifest.
"""
from __future__ import annotations

import json
import subprocess

from app.config import ROOT, settings
from app.cvss import max_cvss
from app.models import Finding, Severity
from app.scanners.source_base import SourceScanner

SEV_MAP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MODERATE": Severity.medium,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
}

_SEV_RANK = {
    Severity.critical: 5, Severity.high: 4, Severity.medium: 3,
    Severity.low: 2, Severity.info: 1,
}


def _root_direct_deps(repo_path) -> set[str] | None:
    """Names from the root package.json (any dep section). None if the
    repo isn't npm-rooted or the manifest is unreadable (-> 'unknown')."""
    try:
        base = repo_path if repo_path.is_absolute() else ROOT / repo_path
        manifest = json.loads((base / "package.json").read_text())
        if not isinstance(manifest, dict):
            return None
        names: set[str] = set()
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = manifest.get(section)
            if isinstance(deps, dict):
                names.update(str(k) for k in deps)
        return names
    except Exception:
        return None


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

        direct = _root_direct_deps(self.repo_path)
        groups: dict[str, dict] = {}
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
                kind = "unknown" if direct is None else ("direct" if name in direct else "transitive")
                vulns = pkg.get("vulnerabilities")
                if not isinstance(vulns, list):
                    continue
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue
                    vid = str(vuln.get("id", "OSV"))
                    aliases = [str(a) for a in (vuln.get("aliases") or []) if isinstance(a, str)]
                    cve = next((a for a in aliases if a.startswith("CVE-")), None)
                    key = cve or vid
                    db = vuln.get("database_specific")
                    db = db if isinstance(db, dict) else {}
                    sev = SEV_MAP.get(str(db.get("severity", "")).upper(), Severity.medium)
                    score = max_cvss(vuln.get("severity"))
                    cwe = [str(c) for c in (db.get("cwe_ids") or []) if isinstance(c, str)][:5]
                    summary = str(vuln.get("summary") or vuln.get("details") or vid)[:300]
                    g = groups.setdefault(key, {
                        "cve": cve, "vid": vid, "vids": [], "aliases": [],
                        "summary": summary, "sev": Severity.info,
                        "cvss": None, "cwe": cwe, "lockfile": lockfile,
                        "installs": [], "fixed": [],
                    })
                    if vid not in g["vids"]:
                        g["vids"].append(vid)
                    for a in aliases:
                        if a not in g["aliases"]:
                            g["aliases"].append(a)
                    if _SEV_RANK[sev] > _SEV_RANK[g["sev"]]:
                        g["sev"] = sev
                    if score is not None and (g["cvss"] is None or score > g["cvss"]):
                        g["cvss"] = score
                    for c in cwe:
                        if c not in g["cwe"] and len(g["cwe"]) < 5:
                            g["cwe"].append(c)
                    g["installs"].append({
                        "package": name, "version": version,
                        "ecosystem": ecosystem, "kind": kind,
                    })
                    for f in _fixed_versions(vuln):
                        if f not in g["fixed"]:
                            g["fixed"].append(f)

        findings: list[Finding] = []
        for key, g in groups.items():
            installs = g["installs"]
            names = sorted({i["package"] for i in installs})
            head = names[0] + (f" +{len(names) - 1} more" if len(names) > 1 else "")
            n = len(installs)
            shown = ", ".join(
                f"{i['package']}@{i['version']} ({i['kind']})" for i in installs[:8]
            ) + (f" +{n - 8} more" if n > 8 else "")
            directs = sorted({i["package"] for i in installs if i["kind"] == "direct"})
            if directs:
                rec = f"Bump {', '.join(directs)} in package.json"
                if g["fixed"]:
                    rec += f" to {', '.join('>=' + f for f in g['fixed'])}"
                rec += "; then `npm audit fix` to clear transitive copies."
            elif g["fixed"]:
                rec = f"Transitive only — `npm audit fix` or bump the parent to reach {', '.join('>=' + f for f in g['fixed'])}."
            else:
                rec = "Transitive only — `npm audit fix` or bump the parent to a patched release."
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"OSV {key} in {head}" + (f" ({n} installs)" if n > 1 else ""),
                    severity=g["sev"],
                    description=f"{g['summary']} Affected installs ({n}): {shown}.",
                    evidence=shown[:400],
                    location=f"{self.repo_url}#{g['lockfile']}" if self.repo_url else g["lockfile"],
                    recommendation=rec,
                    cve=g["cve"],
                    cvss=g["cvss"],
                    cwe=g["cwe"],
                    raw={"osv_id": g["vid"], "osv_ids": g["vids"], "aliases": g["aliases"],
                         "fixed": g["fixed"], "affected": installs},
                )
            )
        findings.sort(
            key=lambda f: ({"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[f.severity.value], f.cvss or 0),
            reverse=True,
        )
        if not findings:
            findings.append(Finding(
                scanner=self.name, title="No known CVEs in dependencies (osv)",
                severity=Severity.info,
                description="OSV scan of lockfiles/manifests completed without matches.",
                location=self.repo_url or str(self.repo_path),
            ))
        return findings[:100]

    def _unavailable(self, note: str) -> list[Finding]:
        return [Finding(
            scanner=self.name, title="SCA unavailable (osv-scanner not installed)",
            severity=Severity.info,
            description=f"Dependency scan skipped. {note}; install osv-scanner for CVE coverage.",
            location=self.repo_url or str(self.repo_path),
        )]
