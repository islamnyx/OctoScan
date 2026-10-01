import json
import subprocess

from app.config import settings
from app.models import Finding, Severity
from app.normalize import clean_cwe
from app.scanners.base import BaseScanner, assert_target_reachable


NUCLEI_SEVERITY_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "unknown": Severity.info,
}


def _nuclei_severity(raw: str | None) -> Severity:
    return NUCLEI_SEVERITY_MAP.get((raw or "info").strip().lower(), Severity.info)


# Recon-class templates run hot at medium in stock Nuclei. An
# unauthenticated metrics read is fingerprinting fuel, not a direct
# vuln — downgrade to low (verified live: Juice Shop /metrics, 26 KB).
NUCLEI_SEVERITY_OVERRIDES: dict[str, Severity] = {
    "prometheus-metrics": Severity.low,
}


class NucleiScanner(BaseScanner):
    name = "nuclei"

    ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}

    def _severity_filter(self) -> list[str]:
        raw = (settings.nuclei_severity or "").strip().lower()
        if not raw:
            return []
        wanted = [s.strip() for s in raw.replace(";", ",").split(",") if s.strip()]
        # Fail-closed on typo: unknown token = loud error, not silent full run.
        unknown = [s for s in wanted if s not in self.ALLOWED_SEVERITIES]
        if unknown:
            raise RuntimeError(
                f"invalid NUCLEI_SEVERITY {unknown}: use comma list of {sorted(self.ALLOWED_SEVERITIES)}"
            )
        # De-dupe, keep canonical order critical→info.
        order = ["critical", "high", "medium", "low", "info"]
        return [s for s in order if s in wanted]

    def run(self) -> list[Finding]:
        out_path = self.workdir / "nuclei.jsonl"
        severities = self._severity_filter()
        cmd = [
            settings.nuclei_bin,
            "-u",
            self.target_url,
            "-jsonl",
            "-o",
            str(out_path),
            "-silent",
            "-nc",
            "-fr",  # follow redirects
            "-timeout",
            "10",
            "-retries",
            "1",
        ]
        if severities:
            cmd += ["-severity", ",".join(severities)]
        # Target-safe throttling (see config): full depth, bounded pressure.
        cmd += [
            "-rate-limit", str(settings.nuclei_rate_limit),
            "-concurrency", str(settings.nuclei_concurrency),
            "-bulk-size", str(settings.nuclei_bulk_size),
        ]
        exclude = [t.strip() for t in (settings.nuclei_exclude_tags or "").split(",") if t.strip()]
        if exclude:
            cmd += ["-exclude-tags", ",".join(exclude)]
        # Authenticated scans (v1): session injection via custom headers.
        if self.auth:
            for h, v in self.auth_headers().items():
                cmd += ["-H", f"{h}: {v}"]
            cookie = self.auth_cookie_header()
            if cookie:
                cmd += ["-H", f"Cookie: {cookie}"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        if "no templates found" in combined.lower() or "templates not installed" in combined.lower():
            return [
                Finding(
                    scanner=self.name,
                    title="Nuclei templates not installed",
                    severity=Severity.info,
                    description="Nuclei ran but no templates are installed. Run `nuclei -update-templates` on the scanner host.",
                    location=self.target_url,
                )
            ]
        if not out_path.exists():
            raise RuntimeError(f"nuclei produced no output: {(proc.stderr or proc.stdout or 'empty')[-200:]}")
        return self._parse(out_path)

    def _parse(self, path) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        # Defense-in-depth: enforce the severity gate on parsed output too,
        # so a nuclei build that ignores -severity can't leak info noise in.
        try:
            allowed = set(self._severity_filter()) or self.ALLOWED_SEVERITIES
        except RuntimeError:
            allowed = self.ALLOWED_SEVERITIES
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            template_id = str(item.get("template-id") or item.get("templateID") or "")
            info = item.get("info") or {}
            name = info.get("name") or template_id or "Nuclei finding"
            matched_at = item.get("matched-at") or item.get("host") or self.target_url
            matcher = str(item.get("matcher-name") or "")
            key = (template_id, str(matched_at), matcher)
            if key in seen:
                continue
            seen.add(key)
            severity = _nuclei_severity(info.get("severity"))
            tuned_from = None
            override = NUCLEI_SEVERITY_OVERRIDES.get(template_id or "")
            if override is not None and override != severity:
                tuned_from, severity = severity.value, override
            if severity.value not in allowed:
                continue
            cve = info.get("cve-id") or info.get("cveID")
            if isinstance(cve, list):
                cve = cve[0] if cve else None
            raw_cwe = info.get("cwe-id") or info.get("cweID")
            if isinstance(raw_cwe, list):
                raw_cwe = raw_cwe[0] if raw_cwe else None
            cwe = clean_cwe(raw_cwe)
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            extracted = item.get("extracted-results") or []
            evidence = "; ".join(str(e) for e in extracted[:3]) or matcher
            # The stock http-missing-security-headers template reports one
            # match per absent header with the header as matcher-name.
            # Expose it as `header` so normalize._concept merges these with
            # the headers/ZAP/Nikto findings for the same root cause.
            header = matcher if template_id == "http-missing-security-headers" else None
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Nuclei {template_id}: {name}" if template_id else name,
                    severity=severity,
                    description=str(info.get("description") or name),
                    evidence=evidence[:500],
                    location=str(matched_at),
                    recommendation="Review this Nuclei finding against the affected asset and patch / harden as indicated by the template references.",
                    cve=str(cve) if cve else None,
                    raw={
                        "template_id": template_id,
                        "header": header,
                        "matcher": matcher or None,
                        "type": item.get("type"),
                        "cwe": str(cwe) if cwe else None,
                        "references": refs[:5] if isinstance(refs, list) else [],
                        "template_url": item.get("template-url"),
                        "severity_tuned_from": tuned_from,
                    },
                )
            )
        if not findings:
            # Empty output is ambiguous: clean target OR nuclei never reached
            # it (unreachable target also yields a 0-byte file). Disambiguate
            # with a cheap probe so a down target can't masquerade as clean.
            assert_target_reachable(self.target_url)
            findings.append(
                Finding(
                    scanner=self.name,
                    title="No Nuclei findings",
                    severity=Severity.info,
                    description="Nuclei completed its full template run without matches.",
                    location=self.target_url,
                )
            )
        return findings
