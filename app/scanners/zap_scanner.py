import hashlib
import json
import time
from urllib.parse import urlparse, urlunparse

import httpx

from app.config import settings
from app.models import Finding, Severity
from app.normalize import from_zap_risk
from app.scanners.base import BaseScanner

# Noise filter: ZAP spider often flags bundled static assets.
# Keep narrow to avoid hiding real findings.
NOISY_PATH_SUBSTRINGS = ("assets/public/assets/public",)
STATIC_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".js", ".css")


def _normalize_url(url: str) -> str:
    try:
        p = urlparse(url)
        path = p.path or "/"
        # collapse trailing slash except root
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        # strip fragment, keep query (different query = different location)
        return urlunparse((p.scheme.lower(), p.netloc.lower(), path, "", p.query, ""))
    except Exception:
        return url


def _dedup_key(alert: dict, norm_url: str) -> tuple[str, str, str, str]:
    plugin_id = str(alert.get("pluginId") or alert.get("pluginid") or "")
    title = alert.get("alert") or alert.get("name") or "ZAP alert"
    param = str(alert.get("param") or "")
    cwe = str(alert.get("cweid") or "")
    # Prefer stable plugin-based key, fallback to title
    primary = plugin_id if plugin_id else hashlib.sha1(title.encode()).hexdigest()[:8]
    return (primary, norm_url, param, cwe)


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
                # Classic spider only; JS-heavy SPAs (Juice Shop) need the
                # AJAX spider for real coverage — known gap: active-scan
                # vulns (SQLi/XSS) stay invisible until that's wired in.
                # maxChildren=10 (was 5) widens breadth cheaply in the meantime.
                params={"apikey": api_key, "url": target, "maxChildren": "10"},
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
        seen: set[tuple[str, str, str, str]] = set()
        for alert in alerts:
            title = alert.get("alert") or alert.get("name") or "ZAP alert"
            location = alert.get("url") or self.target_url
            norm_url = _normalize_url(location)
            if any(s in norm_url for s in NOISY_PATH_SUBSTRINGS):
                continue
            # Drop low-value static-asset noise (e.g. User Agent Fuzzer on /assets/*.js)
            # but keep anything with meaningful risk.
            risk_raw = alert.get("risk") or alert.get("riskcode") or "0"
            if norm_url.lower().endswith(STATIC_EXTENSIONS) and str(risk_raw).lower() in ("0", "1", "low", "informational", "info"):
                continue
            key = _dedup_key(alert, norm_url)
            if key in seen:
                continue
            seen.add(key)
            risk = risk_raw
            findings.append(
                Finding(
                    scanner=self.name,
                    title=title,
                    severity=from_zap_risk(risk),
                    description=alert.get("description") or alert.get("other") or title,
                    evidence=alert.get("evidence") or alert.get("param") or "",
                    location=norm_url,
                    recommendation=alert.get("solution") or "Review and remediate this ZAP finding.",
                    cve=(alert.get("cweid") and f"CWE-{alert.get('cweid')}") or None,
                    raw={
                        "pluginid": alert.get("pluginId") or alert.get("pluginid"),
                        "cweid": alert.get("cweid"),
                        "param": alert.get("param"),
                        "risk": risk,
                        "dedup_key": "|".join(key),
                    },
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
