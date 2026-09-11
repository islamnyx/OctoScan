import json
import subprocess
from pathlib import Path

from app.config import settings
from app.models import Finding, Severity
from app.normalize import from_testssl
from app.scanners.base import BaseScanner


class TestsslScanner(BaseScanner):
    name = "testssl"

    def run(self) -> list[Finding]:
        if self.scheme != "https" and self.port != 443:
            return [
                Finding(
                    scanner=self.name,
                    title="Skipped TLS check (target is not HTTPS)",
                    severity=Severity.info,
                    description="testssl.sh only runs against HTTPS targets.",
                    location=self.target_url,
                )
            ]
        out_json = self.workdir / "testssl.json"
        cmd = [
            str(settings.testssl_bin),
            "--fast",
            "--quiet",
            "--jsonfile",
            str(out_json),
            f"{self.host}:{self.port}",
        ]
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
        )
        if not out_json.exists():
            raise RuntimeError("testssl.sh produced no JSON output")
        return self._parse(out_json)

    NOISY_IDS = {
        "rating_spec", "rating_doc", "scanProblem", "scanTime", "HPKP",
        "cookie_count", "HTTP_status_code", "HTTP_clock_skew",
        "HTTP_headerTime", "HTTP_headerAge",
    }
    NOISY_PREFIXES = (
        "intermediate_cert", "cert_fingerprint", "cert_notBefore",
        "cert_chain", "clientsimulation", "banner_",
    )

    def _is_noisy(self, item: dict) -> bool:
        title = str(item.get("id") or item.get("cwe") or "")
        for prefix in self.NOISY_PREFIXES:
            if title.startswith(prefix):
                return True
        if title in self.NOISY_IDS:
            return True
        if "score" in title.lower() or "weighted" in title.lower():
            return True
        return False

    def _parse(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        payload = json.loads(path.read_text())
        rows = payload if isinstance(payload, list) else payload.get("scanResult", payload)
        if isinstance(rows, dict):
            rows = rows.get("scanResult") or [rows]
        for block in rows:
            items = block.get("findings", block) if isinstance(block, dict) else block
            if isinstance(items, dict):
                items = [items]
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                if self._is_noisy(item):
                    continue
                severity_raw = item.get("severity") or item.get("finding")
                if severity_raw in (None, "OK"):
                    continue
                severity = from_testssl(str(item.get("severity", "INFO")))
                if severity == Severity.info and str(item.get("severity", "")).upper() == "OK":
                    continue
                title = item.get("id") or item.get("cwe") or "TLS finding"
                findings.append(
                    Finding(
                        scanner=self.name,
                        title=str(title),
                        severity=severity,
                        description=str(item.get("finding") or item.get("cwe") or title),
                        evidence=str(item.get("finding") or ""),
                        location=f"{self.host}:{self.port}",
                        recommendation="Harden TLS: disable weak protocols/ciphers and enable modern config.",
                        cve=item.get("cve"),
                        raw=item,
                    )
                )
        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    title="No TLS issues detected",
                    severity=Severity.info,
                    description="testssl.sh completed without actionable TLS findings.",
                    location=f"{self.host}:{self.port}",
                )
            )
        return findings
