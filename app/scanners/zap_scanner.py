import json
import time
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.models import Finding, Severity
from app.normalize import from_zap_risk
from app.scanners.base import BaseScanner


class ZapScanner(BaseScanner):
    name = "zap"

    def run(self) -> list[Finding]:
        api_key = settings.zap_api_key
        base = settings.zap_base_url
        client = httpx.Client(timeout=30.0)
        target = self.target_url
        try:
            r = client.get(f"{base}/JSON/core/view/version/", params={"apikey": api_key})
            r.raise_for_status()
            client.get(
                f"{base}/JSON/core/action/accessUrl/",
                params={"apikey": api_key, "url": target, "followRedirects": "true"},
            )
            spider = client.get(
                f"{base}/JSON/spider/action/scan/",
                params={"apikey": api_key, "url": target, "maxChildren": "5"},
            )
            spider.raise_for_status()
            self._wait_percent(client, f"{base}/JSON/spider/view/status/", api_key)
            ascan = client.get(
                f"{base}/JSON/ascan/action/scan/",
                params={"apikey": api_key, "url": target, "recurse": "true"},
            )
            ascan.raise_for_status()
            self._wait_percent(client, f"{base}/JSON/ascan/view/status/", api_key)
            alerts = client.get(
                f"{base}/JSON/core/view/alerts/",
                params={"apikey": api_key, "baseurl": target},
            )
            alerts.raise_for_status()
            data = alerts.json()
            (self.workdir / "zap-alerts.json").write_text(json.dumps(data, indent=2))
            return self._parse(data.get("alerts", []))
        finally:
            client.close()

    def _wait_percent(self, client: httpx.Client, url: str, api_key: str) -> None:
        deadline = time.time() + settings.scan_timeout_seconds
        while time.time() < deadline:
            r = client.get(url, params={"apikey": api_key})
            r.raise_for_status()
            status = str(r.json().get("status", "0"))
            if status == "100":
                return
            time.sleep(3)
        raise RuntimeError(f"ZAP scan timed out: {url}")

    def _parse(self, alerts: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for alert in alerts:
            title = alert.get("alert") or alert.get("name") or "ZAP alert"
            location = alert.get("url") or self.target_url
            if "assets/public/assets/public" in location:
                continue
            key = (title, location)
            if key in seen:
                continue
            seen.add(key)
            risk = alert.get("risk") or alert.get("riskcode")
            findings.append(
                Finding(
                    scanner=self.name,
                    title=title,
                    severity=from_zap_risk(risk),
                    description=alert.get("description") or alert.get("other") or title,
                    evidence=alert.get("evidence") or alert.get("param") or "",
                    location=location,
                    recommendation=alert.get("solution") or "Review and remediate this ZAP finding.",
                    cve=(alert.get("cweid") and f"CWE-{alert.get('cweid')}") or None,
                    raw={"pluginid": alert.get("pluginid"), "risk": risk},
                )
            )
        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    title="No ZAP alerts",
                    severity=Severity.info,
                    description="Spider + passive + active scan completed without alerts.",
                    location=self.target_url,
                )
            )
        return findings
