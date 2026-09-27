import hashlib
import json
import re
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
    "/rest/user/login",
    "/api",
    "/ftp",
)
# NOTE: "/#/search?q=ZapTest" was removed (2026-09-27): URLs containing '#'
# are SPA routes that return index.html, never the real SQLi sink, so they
# only burn ascan budget. _select_ascan_targets also drops '#' URLs.
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
        auth_rules: list[str] = []
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
            self._activity(f"connected to ZAP {r.json().get('version', '')}, resetting session")
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
            # Authenticated scans (v1): inject the session into ALL ZAP
            # traffic (spider + ascan) via replacer request-header rules.
            # Verified 2026-09-16: REQ_HEADER rules fire even when the
            # header is absent, including on API-initiated requests.
            # Removed in the outer finally so sessions never leak scans.
            auth_rules = self._apply_auth_rules(client, base, api_key)
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
            self._activity("spider crawling the target…")
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
            self._activity(f"spider finished — {found} URL(s) discovered")
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
            # Shared budget: one total budget for all targets (per-target
            # timeouts lost whole scans before). Throttled threads + per-target
            # cap below let all 20 targets get a turn without flooding the target.
            ascan_budget = min(settings.zap_ascan_budget_seconds, max(300, settings.scan_timeout_seconds // 2))
            ascan_deadline = time.time() + ascan_budget
            # Per-target cap (fix B, 2026-09-27): split the shared budget
            # across targets (min 60s) so one slow host can no longer eat the
            # whole budget. Enforced BOTH inside ZAP (max scan duration) and
            # by our poll timeout (cap + 20s).
            per_target_cap = max(60, int(ascan_budget // max(1, len(ascan_targets)))) if ascan_targets else 60
            self._activity(f"ascan plan: {len(ascan_targets)} target(s), {ascan_budget}s shared budget, {per_target_cap}s per-target cap")
            # Gentle but thorough (2026-09-16): throttle the shared daemon
            # for this scan, restore afterwards in finally.
            prev_throttle = self._throttle_ascan(client, base, api_key)
            prev_max_dur = self._set_max_scan_duration(client, base, api_key, per_target_cap)
            # Every ascan id we start (fix C): stopped + removed in finally
            # so timed-out scans never pile up as orphan RUNNING scans.
            started_ids: list[str] = []
            skip_notes: list[str] = []
            try:
                for i, t in enumerate(ascan_targets, 1):
                    self._activity(f"active scan {i}/{len(ascan_targets)}: {t[:80]}")
                    remaining = ascan_deadline - time.time()
                    if remaining < 30:
                        skip_notes.append(
                            f"ascan budget exhausted after {scanned}/{len(ascan_targets)} targets "
                            f"({int(ascan_budget)}s shared budget); passive/spider results for the rest"
                        )
                        break
                    cap = int(min(per_target_cap, remaining))
                    ascan_id = ""
                    try:
                        try:
                            ascan = client.get(
                                f"{base}/JSON/ascan/action/scan/",
                                params={
                                    "apikey": api_key,
                                    "url": t,
                                    "recurse": "true" if settings.zap_ascan_recurse else "false",
                                },
                            )
                        except (httpx.ConnectError, httpx.TimeoutException) as exc:
                            # Fix A: only "daemon unreachable" aborts the loop.
                            if not self._daemon_alive(client, base, api_key):
                                raise RuntimeError(f"ZAP daemon unreachable, aborting ascan loop: {exc}") from exc
                            skip_notes.append(f"{t[:60]}: connection blip (daemon alive), continued")
                            continue
                        try:
                            ascan.raise_for_status()
                        except httpx.HTTPStatusError as exc:
                            code = exc.response.status_code if exc.response is not None else 0
                            safe = re.sub(r"apikey=[^&\s'\"]+", "apikey=***", str(exc))[:200]
                            if code == 400 or "url_not_found" in safe.lower():
                                skip_notes.append(f"{t[:60]}: skipped ({safe})")
                                continue
                            if not self._daemon_alive(client, base, api_key):
                                raise RuntimeError(f"ZAP daemon unreachable (HTTP {code}), aborting ascan loop") from exc
                            skip_notes.append(f"{t[:60]}: HTTP {code}, continued ({safe})")
                            continue
                        ascan_id = str(ascan.json().get("scan") or "")
                        if not ascan_id:
                            skip_notes.append(f"{t[:60]}: ZAP returned no scan id, continued")
                            continue
                        started_ids.append(ascan_id)
                        try:
                            self._wait_scan(
                                client, f"{base}/JSON/ascan/view/status/", api_key, ascan_id,
                                timeout_s=cap + 20,
                            )
                        except RuntimeError as exc:
                            # Fix A: per-target timeout -> stop THIS scan,
                            # record the reason, continue with the next target.
                            self._stop_ascan(client, base, api_key, ascan_id)
                            skip_notes.append(f"{t[:60]}: ascan timed out at cap {cap}s, stopped, continued")
                            continue
                        scanned += 1
                    except RuntimeError:
                        raise
                    except Exception as exc:
                        # One weird target must never kill the other 19:
                        # stop its scan (if any), record, continue.
                        self._stop_ascan(client, base, api_key, ascan_id)
                        safe = re.sub(r"apikey=[^&\s'\"]+", "apikey=***", str(exc))[:200]
                        skip_notes.append(f"{t[:60]}: {safe}, continued")
                        continue
                if not ascan_targets:
                    skip_notes.append("no dynamic targets in tree; passive/spider results only")
                if skip_notes:
                    # httpx errors embed the request URL incl. ?apikey=… —
                    # never persist the key in job.json/coverage.
                    safe_notes = [re.sub(r"apikey=[^&\s'\"]+", "apikey=***", n) for n in skip_notes]
                    ascan_skipped = f"(partial: {scanned}/{len(ascan_targets)} targets scanned) " + "; ".join(safe_notes)
                    ascan_skipped = ascan_skipped[:1000]
            finally:
                self._cleanup_ascans(client, base, api_key, started_ids)
                self._restore_max_scan_duration(client, base, api_key, prev_max_dur)
                self._restore_throttle(client, base, api_key, prev_throttle)
            alerts = client.get(
                f"{base}/JSON/core/view/alerts/",
                params={"apikey": api_key, "baseurl": target},
            )
            alerts.raise_for_status()
            data = alerts.json()
            self._activity(f"collecting alerts ({len(data.get('alerts', []))} raw)")
            coverage = {
                "classic_spider": True,
                "ajax_spider": ajax_ok,
                "ajax_enabled": settings.zap_enable_ajax_spider,
                "ascan_scanned": scanned,
                "ascan_targets": len(ascan_targets),
                "ascan_cap": settings.zap_ascan_max_targets,
                "ascan_per_target_cap": per_target_cap,
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
            # Session hygiene: auth rules must not survive into later scans.
            try:
                self._clear_auth_rules(client, base, api_key, auth_rules)
            except Exception:
                pass
            client.close()

    def _throttle_ascan(self, client: httpx.Client, base: str, api_key: str) -> tuple[int, int]:
        """Save the daemon's ascan throttle, apply ours. Best-effort.

        The daemon is shared across scans; the caller restores the previous
        values in a finally block. Returns (threads, delay_ms).
        """
        prev: tuple[int, int] = (24, 0)
        try:
            t = client.get(f"{base}/JSON/ascan/view/optionThreadPerHost/", params={"apikey": api_key})
            d = client.get(f"{base}/JSON/ascan/view/optionDelayInMs/", params={"apikey": api_key})
            prev = (int(t.json().get("ThreadPerHost", 24)), int(d.json().get("DelayInMs", 0)))
        except Exception:
            pass
        try:
            client.get(
                f"{base}/JSON/ascan/action/setOptionThreadPerHost/",
                params={"apikey": api_key, "Integer": settings.zap_ascan_thread_per_host},
            )
            client.get(
                f"{base}/JSON/ascan/action/setOptionDelayInMs/",
                params={"apikey": api_key, "Integer": settings.zap_ascan_delay_ms},
            )
            self._activity(
                f"ascan throttle: {settings.zap_ascan_thread_per_host} threads/host, "
                f"{settings.zap_ascan_delay_ms}ms delay (was {prev[0]}/{prev[1]})"
            )
        except Exception:
            pass
        return prev

    def _restore_throttle(
        self, client: httpx.Client, base: str, api_key: str, prev: tuple[int, int]
    ) -> None:
        """Restore daemon throttle values saved by _throttle_ascan. Best-effort."""
        try:
            client.get(
                f"{base}/JSON/ascan/action/setOptionThreadPerHost/",
                params={"apikey": api_key, "Integer": prev[0]},
            )
            client.get(
                f"{base}/JSON/ascan/action/setOptionDelayInMs/",
                params={"apikey": api_key, "Integer": prev[1]},
            )
        except Exception:
            pass

    def _daemon_alive(self, client: httpx.Client, base: str, api_key: str) -> bool:
        """Authed liveness probe: True iff the daemon answers with our key."""
        try:
            r = client.get(f"{base}/JSON/core/view/version/", params={"apikey": api_key}, timeout=10.0)
            return r.status_code == 200 and '"version"' in r.text
        except Exception:
            return False

    def _stop_ascan(self, client: httpx.Client, base: str, api_key: str, scan_id: str) -> None:
        """Stop one ascan by id. Best-effort, never raises."""
        if not scan_id:
            return
        try:
            client.get(
                f"{base}/JSON/ascan/action/stop/",
                params={"apikey": api_key, "scanId": scan_id},
            )
        except Exception:
            pass

    def _cleanup_ascans(self, client: httpx.Client, base: str, api_key: str, scan_ids: list[str]) -> None:
        """Stop + remove every ascan we started (fix C, 2026-09-27).

        Timed-out ascans left RUNNING pile up across scans and wedge the
        daemon; removing them keeps back-to-back scans healthy. Best-effort.
        """
        for sid in scan_ids:
            try:
                client.get(
                    f"{base}/JSON/ascan/action/stop/",
                    params={"apikey": api_key, "scanId": sid},
                )
            except Exception:
                pass
            try:
                client.get(
                    f"{base}/JSON/ascan/action/removeScan/",
                    params={"apikey": api_key, "scanId": sid},
                )
            except Exception:
                pass

    def _set_max_scan_duration(
        self, client: httpx.Client, base: str, api_key: str, cap_s: int
    ) -> int | None:
        """Enforce the per-target cap inside ZAP (fix B). Returns prev mins.

        ZAP takes minutes (min 1); our poll timeout (cap + 20s) is the
        precise guard. None = unsupported daemon, poll cap still applies.
        """
        prev: int | None = None
        try:
            r = client.get(
                f"{base}/JSON/ascan/view/optionMaxScanDurationInMins/",
                params={"apikey": api_key},
            )
            prev = int(r.json().get("MaxScanDurationInMins", 0)) or None
        except Exception:
            pass
        try:
            client.get(
                f"{base}/JSON/ascan/action/setOptionMaxScanDurationInMins/",
                params={"apikey": api_key, "Integer": max(1, -(-cap_s // 60))},
            )
            self._activity(f"ascan max duration capped at {max(1, -(-cap_s // 60))} min/target (was {prev})")
        except Exception:
            self._activity("ascan max-duration option unsupported, poll cap only")
        return prev

    def _restore_max_scan_duration(
        self, client: httpx.Client, base: str, api_key: str, prev: int | None
    ) -> None:
        """Restore the daemon's max scan duration saved by _set_max_scan_duration."""
        if prev is None:
            return
        try:
            client.get(
                f"{base}/JSON/ascan/action/setOptionMaxScanDurationInMins/",
                params={"apikey": api_key, "Integer": prev},
            )
        except Exception:
            pass

    def _apply_auth_rules(self, client: httpx.Client, base: str, api_key: str) -> list[str]:
        """Inject session headers into all ZAP traffic. Returns rule descriptions.

        Uses replacer request-header rules scoped to the target host
        (verified live 2026-09-16 against a header-echo server). Caller
        removes them via _clear_auth_rules in a finally block.
        """
        if not self.auth or (not self.auth.cookies and not self.auth.headers):
            return []
        scope = f".*{re.escape(self.host)}.*"
        pairs = [(k, v) for k, v in self.auth_headers().items()]
        cookie = self.auth_cookie_header()
        if cookie:
            pairs.append(("Cookie", cookie))
        added: list[str] = []
        for name, value in pairs:
            desc = f"octoscan-auth-{self.workdir.name}-{name}"
            try:
                client.get(
                    f"{base}/JSON/replacer/action/addRule/",
                    params={
                        "apikey": api_key,
                        "description": desc,
                        "enabled": "true",
                        "matchType": "REQ_HEADER",
                        "matchString": name,
                        "matchRegex": "false",
                        "replacement": value,
                        "initiators": "",
                        "url": scope,
                    },
                )
                added.append(desc)
                self._activity(f"auth injected into ZAP traffic: {name}")
            except Exception:
                pass
        return added

    def _clear_auth_rules(self, client: httpx.Client, base: str, api_key: str, rules: list[str]) -> None:
        """Remove replacer rules added by _apply_auth_rules. Best-effort."""
        for desc in rules:
            try:
                client.get(
                    f"{base}/JSON/replacer/action/removeRule/",
                    params={"apikey": api_key, "description": desc},
                )
            except Exception:
                pass

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

        Priority (fix D, 2026-09-27): URLs with a query string AND a
        /rest/ or /api/ path rank first (the real SQLi sink is
        /rest/products/search?q=); bare SPA routes (/#/..., /search?q=)
        rank last. URLs containing '#' (client-side SPA routes serving
        index.html) are dropped outright. Static assets (.js/.css/images/
        fonts/.map) are excluded — they never yield ascan vulns.
        """
        try:
            r = client.get(f"{base}/JSON/core/view/urls/", params={"apikey": api_key, "baseurl": target})
            r.raise_for_status()
            urls = [u for u in (r.json().get("urls") or []) if isinstance(u, str) and u]
        except Exception:
            return [seed]
        dynamic = [
            u for u in urls
            if "#" not in u and not u.lower().split("?")[0].endswith(STATIC_EXTENSIONS)
        ]

        def _rank(u: str) -> int:
            low = u.lower()
            has_q = "?" in u
            restful = "/rest/" in low or "/api/" in low
            if has_q and restful:
                return 0
            if has_q:
                return 1
            if restful:
                return 2
            if u == seed:
                return 3
            return 4

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
