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
        if not api_key:
            raise RuntimeError(
                "ZAP_API_KEY not set — start ZAP with auth: "
                "-config api.key=$ZAP_API_KEY -config api.disablekey=false, "
                "and set ZAP_API_KEY in .env to the same value"
            )
        base = settings.zap_base_url
        client = httpx.Client(timeout=30.0)
        target = self.target_url
        try:
            # Fail-closed on open daemons: if the version endpoint answers
            # WITHOUT a key, the daemon runs with api.disablekey=true and
            # anyone on the box can drive scans via the ZAP API.
            try:
                open_probe = client.get(f"{base}/JSON/core/view/version/")
                if open_probe.status_code == 200:
                    raise RuntimeError(
                        "ZAP daemon allows unauthenticated API access "
                        "(api.disablekey=true?). Restart with "
                        "-config api.disablekey=false -config api.key=$ZAP_API_KEY"
                    )
            except RuntimeError:
                raise
            except Exception:
                pass  # probe best-effort; authed check below is authoritative
            r = client.get(f"{base}/JSON/core/view/version/", params={"apikey": api_key})
            if r.status_code in (401, 403):
                raise RuntimeError("ZAP API key rejected (401/403) — check ZAP_API_KEY matches the daemon's api.key")
            r.raise_for_status()
            client.get(
                f"{base}/JSON/core/action/accessUrl/",
                params={"apikey": api_key, "url": target, "followRedirects": "true"},
            )
            spider = client.get(
                f"{base}/JSON/spider/action/scan/",
                # maxChildren=10 (was 5) widens classic-spider breadth cheaply;
                # JS-heavy SPAs (Juice Shop) additionally get the AJAX spider
                # below so active-scan vulns (SQLi/XSS) become visible.
                params={"apikey": api_key, "url": target, "maxChildren": "10"},
            )
            spider.raise_for_status()
            # Track OUR scan by id: the global status endpoint can report
            # 100 from an older/stopped scan while ours is still crawling.
            spider_id = str(spider.json().get("scan") or "")
            self._wait_scan(client, f"{base}/JSON/spider/view/status/", api_key, spider_id)
            # If the spider found zero URLs the target is almost certainly
            # down or refusing connections (verified 2026-09-12: enscs died
            # mid-campaign, spider completed in 0.09s with nothing). Fail
            # loudly here instead of a misleading ascan 400 later.
            found = self._spider_result_count(client, base, api_key, spider_id)
            if found == 0:
                raise RuntimeError(
                    f"ZAP spider found 0 URLs for {target} — target looks down "
                    "or unreachable from ZAP; active scan not attempted"
                )
            # Ensure the target actually landed in the Sites tree before
            # ascan, polling with backoff for indexing lag. Raises if the
            # tree stays empty (dead target) instead of hanging in ajax.
            scan_target = self._ensure_in_tree(client, base, api_key, target)
            ajax_ok = self._run_ajax_spider(client, base, api_key, scan_target) if found != 0 else False
            try:
                ascan = client.get(
                    f"{base}/JSON/ascan/action/scan/",
                    params={"apikey": api_key, "url": scan_target, "recurse": "true"},
                )
                ascan.raise_for_status()
                ascan_id = str(ascan.json().get("scan") or "")
                self._wait_scan(client, f"{base}/JSON/ascan/view/status/", api_key, ascan_id)
                ascan_skipped = None
            except Exception as exc:
                # url_not_found: tree race or spider found nothing. Don't
                # fail the whole scanner — fall back to passive alerts.
                if "url_not_found" not in str(exc).lower() and "400" not in str(exc):
                    raise
                ascan_skipped = str(exc)[:200]
            alerts = client.get(
                f"{base}/JSON/core/view/alerts/",
                params={"apikey": api_key, "baseurl": target},
            )
            alerts.raise_for_status()
            data = alerts.json()
            data["_spider_coverage"] = {"classic_spider": True, "ajax_spider": ajax_ok}
            (self.workdir / "zap-alerts.json").write_text(json.dumps(data, indent=2))
            findings = self._parse(data.get("alerts", []))
            if ascan_skipped:
                findings.append(
                    Finding(
                        scanner=self.name,
                        title="ZAP active scan skipped (target not in scan tree)",
                        severity=Severity.info,
                        description=f"Passive/spider results only. Active scan refused the URL: {ascan_skipped}",
                        location=target,
                    )
                )
            return findings
        finally:
            client.close()

    def _wait_scan(self, client: httpx.Client, url: str, api_key: str, scan_id: str = "") -> None:
        """Poll a %-status endpoint until 100, scoped to scan_id when known."""
        deadline = time.time() + settings.scan_timeout_seconds
        params = {"apikey": api_key}
        if scan_id:
            params["scanId"] = scan_id
        while time.time() < deadline:
            r = client.get(url, params=params)
            r.raise_for_status()
            status = str(r.json().get("status", "0"))
            if status == "100":
                return
            time.sleep(3)
        raise RuntimeError(f"ZAP scan timed out: {url}")

    def _wait_percent(self, client: httpx.Client, url: str, api_key: str) -> None:
        self._wait_scan(client, url, api_key)

    def _spider_result_count(self, client: httpx.Client, base: str, api_key: str, scan_id: str = "") -> int:
        # Scope to our scanId: the global results view accumulates stale
        # URLs from earlier scans in the same ZAP session.
        params = {"apikey": api_key}
        if scan_id:
            params["scanId"] = scan_id
        try:
            r = client.get(f"{base}/JSON/spider/view/results/", params=params)
            r.raise_for_status()
            return len(r.json().get("results") or [])
        except Exception:
            return -1  # unknown: don't block the scan on a view error

    def _ensure_in_tree(self, client: httpx.Client, base: str, api_key: str, target: str) -> str:
        """Return a tree-backed URL to feed ascan, polling for indexing lag.

        Raises a clear error if the tree stays empty (dead target) — the
        old silent fallback produced a confusing ascan 400 downstream.
        """
        def _tree_urls() -> list[str]:
            try:
                r = client.get(f"{base}/JSON/core/view/urls/", params={"apikey": api_key, "baseurl": target})
                r.raise_for_status()
                urls = r.json().get("urls") or []
                return [u for u in urls if isinstance(u, str) and u]
            except Exception:
                return []

        for _ in range(5):
            urls = _tree_urls()
            if urls:
                return urls[0] if target not in urls else target
            time.sleep(3)
        try:
            client.get(
                f"{base}/JSON/core/action/accessUrl/",
                params={"apikey": api_key, "url": target, "followRedirects": "true"},
            )
            time.sleep(3)
        except Exception:
            pass
        urls = _tree_urls()
        if urls:
            return urls[0] if target not in urls else target
        raise RuntimeError(
            f"ZAP Sites tree has no URLs for {target} after spider — "
            "target looks down or unreachable; active scan not attempted"
        )

    def _run_ajax_spider(self, client: httpx.Client, base: str, api_key: str, target: str) -> bool:
        """Run ZAP's AJAX spider (browser-driven, for JS-heavy SPAs).

        Returns True when it ran. Returns False (and lets the scan continue
        on classic-spider URLs) when the ajaxSpider addon isn't installed
        or it doesn't finish in budget — never fails the whole scan.
        """
        try:
            r = client.get(
                f"{base}/JSON/ajaxSpider/action/scan/",
                params={"apikey": api_key, "url": target},
            )
            r.raise_for_status()
            if "does not exist" in r.text:
                return False
        except Exception:
            return False
        # Cap AJAX crawl so it can't eat the whole scan budget.
        deadline = time.time() + min(300, settings.scan_timeout_seconds // 3)
        status_url = f"{base}/JSON/ajaxSpider/view/status/"
        try:
            while time.time() < deadline:
                s = client.get(status_url, params={"apikey": api_key})
                s.raise_for_status()
                if str(s.json().get("status", "")).lower() == "stopped":
                    return True
                time.sleep(3)
        except Exception:
            return False
        # Timed out: stop it if we can, then proceed with what was found.
        try:
            client.get(f"{base}/JSON/ajaxSpider/action/stop/", params={"apikey": api_key})
        except Exception:
            pass
        return False

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
