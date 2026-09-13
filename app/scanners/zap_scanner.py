import hashlib
import json
import time
from urllib.parse import urlparse, urlunparse

import httpx

from app.config import settings
from app.models import Finding, Severity
from app.normalize import from_zap_risk
from app.scanners.base import BaseScanner

# Seed paths with query params / API routes so active scan has injectable
# targets even when the classic spider only finds static assets.
# Juice Shop SQLi lives at /rest/products/search?q= — spider never
# discovers ? URLs on its own, so without seeds ascan fires at / + .js
# and finds only passive issues (CSP/timestamp), never SQLi/XSS.
SEED_PATHS = (
    "/rest/products/search?q=ZapTest",
    "/rest/products/search?q='",
    "/search?q=ZapTest",
    "/#/search?q=ZapTest",
    "/rest/user/login",
    "/api",
    "/ftp",
)
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
            # Fresh session per scan: clears the Sites tree / stale spider
            # results from earlier scans (134-node buildup OOMed the 1GB
            # daemon on 2026-09-13). Best-effort, never fails the scan.
            try:
                client.get(
                    f"{base}/JSON/core/action/newSession/",
                    params={"apikey": api_key, "name": "scan", "overwrite": "true"},
                )
            except Exception:
                pass
            client.get(
                f"{base}/JSON/core/action/accessUrl/",
                params={"apikey": api_key, "url": target, "followRedirects": "true"},
            )
            # Seed injectable URLs into the Sites tree (cheap, no browser).
            # accessUrl forces ZAP to proxy/fetch each seed so ascan has
            # ?q= / /rest/* targets even if spider found only static files.
            # Also try OpenAPI import (Juice Shop exposes /api-docs) —
            # populates REST routes without AJAX/firefox RAM cost.
            self._seed_targets(client, base, api_key, target)
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
            if settings.zap_enable_ajax_spider and found != 0:
                ajax_ok = self._run_ajax_spider(client, base, api_key, scan_target)
            else:
                ajax_ok = False
            # Capped active scan (OOM fix 2026-09-13): old code did
            # recurse=true over the whole 130-node Juice Shop tree while
            # ~18 firefox-esr from the AJAX spider were still alive ->
            # 11.8G peak -> systemd-oomd killed java+firefox+uvicorn.
            # Now: recurse=false on the seed + top-N dynamic URLs only,
            # static assets excluded (they never yield ascan vulns).
            ascan_targets = self._select_ascan_targets(client, base, api_key, target, scan_target)
            ascan_skipped = None
            scanned = 0
            # Shared budget (timeout fix 2026-09-13): dividing 900s by 20
            # targets gave 60s each, but one Juice Shop host alone needs
            # 103s -> every scan timed out. Now one total budget for all
            # targets, up to 300s per target, stop cleanly when exhausted.
            ascan_budget = min(settings.zap_ascan_budget_seconds, max(300, settings.scan_timeout_seconds // 2))
            ascan_deadline = time.time() + ascan_budget
            try:
                for t in ascan_targets:
                    remaining = ascan_deadline - time.time()
                    if remaining < 30:
                        ascan_skipped = (
                            f"ascan budget exhausted after {scanned}/{len(ascan_targets)} targets "
                            f"({int(ascan_budget)}s shared budget); passive/spider results for the rest"
                        )
                        break
                    ascan = client.get(
                        f"{base}/JSON/ascan/action/scan/",
                        params={
                            "apikey": api_key,
                            "url": t,
                            "recurse": "true" if settings.zap_ascan_recurse else "false",
                        },
                    )
                    ascan.raise_for_status()
                    ascan_id = str(ascan.json().get("scan") or "")
                    self._wait_scan(
                        client, f"{base}/JSON/ascan/view/status/", api_key, ascan_id,
                        timeout_s=int(min(settings.zap_ascan_per_target_seconds, remaining)),
                    )
                    scanned += 1
                if not ascan_targets:
                    ascan_skipped = "no dynamic targets in tree; passive/spider results only"
            except Exception as exc:
                # Timeout or url_not_found: keep partial ascan results and
                # fall back to passive/spider alerts instead of failing the
                # whole scanner (last scan lost all ZAP findings on a 60s
                # per-target timeout). Only unknown errors still raise.
                msg = str(exc).lower()
                if "timed out" in msg or "url_not_found" in msg or "400" in msg:
                    ascan_skipped = str(exc)[:200] + f" (partial: {scanned}/{len(ascan_targets)} targets scanned)"
                else:
                    raise
            alerts = client.get(
                f"{base}/JSON/core/view/alerts/",
                params={"apikey": api_key, "baseurl": target},
            )
            alerts.raise_for_status()
            data = alerts.json()
            coverage = {
                "classic_spider": True,
                "ajax_spider": ajax_ok,
                "ajax_enabled": settings.zap_enable_ajax_spider,
                "ascan_scanned": scanned,
                "ascan_targets": len(ascan_targets),
                "ascan_cap": settings.zap_ascan_max_targets,
                "ascan_recurse": settings.zap_ascan_recurse,
                "ascan_skipped": ascan_skipped,
            }
            data["_spider_coverage"] = coverage
            (self.workdir / "zap-alerts.json").write_text(json.dumps(data, indent=2))
            # Coverage lives on self.coverage (persisted to job.coverage by
            # the pipeline), NOT as Severity.info findings — meta notes used
            # to inflate the info count and pollute the dashboard.
            self.coverage = coverage
            findings = self._parse(data.get("alerts", []))
            return findings
        finally:
            client.close()

    def _wait_scan(self, client: httpx.Client, url: str, api_key: str, scan_id: str = "", timeout_s: int = 0) -> None:
        """Poll a %-status endpoint until 100, scoped to scan_id when known."""
        deadline = time.time() + (timeout_s or settings.scan_timeout_seconds)
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

    def _seed_targets(self, client: httpx.Client, base: str, api_key: str, target: str) -> None:
        """Best-effort tree seeding: injectable URLs + OpenAPI routes.

        All cheap (plain HTTP via ZAP proxy, no firefox). Never raises.
        """
        root = target.rstrip("/")
        for path in SEED_PATHS:
            try:
                client.get(
                    f"{base}/JSON/core/action/accessUrl/",
                    params={"apikey": api_key, "url": f"{root}{path}", "followRedirects": "true"},
                )
            except Exception:
                pass
        # OpenAPI import populates /rest/* routes without a browser.
        for doc in ("/api-docs/swagger.json", "/api-docs/openapi.json", "/swagger.json"):
            try:
                r = client.get(
                    f"{base}/JSON/openapi/action/importUrl/",
                    params={"apikey": api_key, "url": f"{root}{doc}"},
                )
                if r.status_code == 200 and "false" not in r.text.lower()[:50]:
                    break
            except Exception:
                pass

    def _select_ascan_targets(self, client: httpx.Client, base: str, api_key: str, target: str, seed: str) -> list[str]:
        """Pick capped active-scan targets: injectable URLs first.

        Priority: URLs with query params (?q= → SQLi/XSS sink), then
        /rest/* /api/* routes, then seed, then remaining dynamic URLs.
        Filters out static assets (.js/.css/images/fonts/.map) which burn
        ascan time/memory but never produce SQLi/XSS/etc. alerts.
        """
        try:
            r = client.get(f"{base}/JSON/core/view/urls/", params={"apikey": api_key, "baseurl": target})
            r.raise_for_status()
            urls = [u for u in (r.json().get("urls") or []) if isinstance(u, str) and u]
        except Exception:
            return [seed]
        dynamic = [u for u in urls if not u.lower().split("?")[0].endswith(STATIC_EXTENSIONS)]

        def _rank(u: str) -> int:
            if "?" in u:
                return 0
            low = u.lower()
            if "/rest/" in low or "/api/" in low:
                return 1
            if u == seed:
                return 2
            return 3

        dynamic_sorted = sorted(set(dynamic), key=_rank)
        # Seed first, then tree order, deduped, capped.
        ordered: list[str] = []
        for u in [seed, *dynamic_sorted]:
            if u not in ordered:
                ordered.append(u)
            if len(ordered) >= max(1, settings.zap_ascan_max_targets):
                break
        return ordered or [seed]

    def _run_ajax_spider(self, client: httpx.Client, base: str, api_key: str, target: str) -> bool:
        """Run ZAP's AJAX spider (browser-driven, for JS-heavy SPAs).

        OFF by default (ZAP_ENABLE_AJAX_SPIDER=false): each run spawns
        firefox-esr processes that pile up (~18 seen on Juice Shop) and
        OOM the box. Enable only with RAM headroom. Always time-boxed and
        never fails the whole scan.
        """
        if not settings.zap_enable_ajax_spider:
            return False
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
        deadline = time.time() + max(30, min(settings.zap_ajax_timeout_seconds, settings.scan_timeout_seconds // 3))
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
