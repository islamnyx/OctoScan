import json
import subprocess

from app.config import settings
from app.models import Finding, Severity
from app.scanners.base import BaseScanner


# Nikto emits no severity — map by ID/keywords. Header findings (013587)
# duplicate our fast headers scanner, so keep them info-only here.
HEADER_DUP_IDS = {"013587"}
INFO_IDS = {"999990", "007342", "999957", "999956", "999955"}

HIGH_KEYWORDS = (
    "command execution",
    "remote file inclusion",
    "sql injection",
    "cross-site scripting",
    "directory traversal",
    "path traversal",
    "arbitrary file",
    "arbitrary code",
    "buffer overflow",
    "authentication bypass",
)
MEDIUM_KEYWORDS = (
    "password",
    "backup",
    "config file",
    "directory listing",
    "information disclosure",
    "admin",
    "phpinfo",
    "server-status",
    "server-info",
)


def _severity(vuln_id: str, msg: str) -> Severity:
    vid = str(vuln_id)
    if vid in HEADER_DUP_IDS:
        return Severity.info
    if vid in INFO_IDS:
        return Severity.info
    low_msg = msg.lower()
    if any(k in low_msg for k in HIGH_KEYWORDS):
        return Severity.high
    if any(k in low_msg for k in MEDIUM_KEYWORDS):
        return Severity.medium
    return Severity.low


class NiktoScanner(BaseScanner):
    name = "nikto"

    def run(self) -> list[Finding]:
        out_base = self.workdir / "nikto"
        cmd = [
            settings.nikto_bin,
            "-h",
            self.target_url,
            "-Format",
            "json",
            "-o",
            str(out_base),
            "-ask",
            "no",
            "-nolookup",
            "-maxtime",
            "240s",
            "-timeout",
            "10",
            "-Tuning",
            "x6",  # all except DoS
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
        )
        out_path = self._find_output(out_base)
        if out_path is None:
            raise RuntimeError(
                (proc.stderr.strip() or proc.stdout.strip() or "nikto produced no JSON output")[-300:]
            )
        return self._parse(out_path)

    @staticmethod
    def _find_output(out_base):
        candidates = [
            out_base.with_suffix(".json"),
            out_base.with_name(out_base.name + ".json"),
            out_base.with_name(out_base.name + ".json.json"),
        ]
        for c in candidates:
            if c.exists():
                return c
        matches = sorted(out_base.parent.glob("nikto*.json*"))
        return matches[0] if matches else None

    def _parse(self, path) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        payload = json.loads(path.read_text())
        hosts = payload if isinstance(payload, list) else [payload]
        for host in hosts:
            vulns = host.get("vulnerabilities", host) if isinstance(host, dict) else []
            if isinstance(vulns, dict):
                vulns = [vulns]
            if not isinstance(vulns, list):
                continue
            for item in vulns:
                if not isinstance(item, dict):
                    continue
                vid = str(item.get("id") or "")
                method = str(item.get("method") or "")
                rel_url = str(item.get("url") or "/")
                msg = str(item.get("msg") or "Nikto finding")
                # Same id can repeat for different messages (e.g. one
                # 013587 per missing header) — include msg in the key.
                key = (vid, method, rel_url, msg)
                if key in seen:
                    continue
                seen.add(key)
                location = self.target_url.rstrip("/") + rel_url
                findings.append(
                    Finding(
                        scanner=self.name,
                        title=f"Nikto {vid}: {msg[:100]}" if vid else msg[:120],
                        severity=_severity(vid, msg),
                        description=msg,
                        evidence=f"{method} {rel_url}".strip(),
                        location=location,
                        recommendation=item.get("references") or "Review this Nikto finding and harden the exposed path/config.",
                        raw={"nikto_id": vid, "method": method, "url": rel_url},
                    )
                )
        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    title="No Nikto findings",
                    severity=Severity.info,
                    description="Nikto completed without findings.",
                    location=self.target_url,
                )
            )
        return findings
