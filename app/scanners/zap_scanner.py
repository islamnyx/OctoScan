import hashlib
import json
import re
import time
from urllib.parse import urlparse, urlunparse

import httpx

from app.config import settings
from app.models import Finding, Severity
from app.normalize import AUTH_PATH_RE, LOGIN_PATH_RE, clean_cwe, from_zap_risk
from app.owasp import owasp_for
from app.scanners.base import BaseScanner, ScanStopped

# Seed paths with query params / API routes so active scan has injectable
# targets even when the classic spider only finds static assets.
# Juice Shop SQLi lives at /rest/products/search?q= — spider never
# discovers ? URLs on its own, so without seeds ascan fires at / + .js
# and finds only passive issues (CSP/timestamp), never SQLi/XSS.
# NOTE: bare /api was dropped (2026-10-03): it answers HTTP 500 with no
# injectable params — an ascan slot burned for an error page.
SEED_PATHS = (
    "/rest/products/search?q=ZapTest",
    "/rest/products/search?q='",
    "/search?q=ZapTest",
    "/rest/user/login",
    "/ftp",
)
# NOTE: "/#/search?q=ZapTest" was removed (2026-09-27): URLs containing '#'
# are SPA routes that return index.html, never the real SQLi sink, so they
# only burn ascan budget. _select_ascan_targets also drops '#' URLs.
# Noise filter: ZAP spider often flags bundled static assets.
# Keep narrow to avoid hiding real findings.
NOISY_PATH_SUBSTRINGS = ("assets/public/assets/public",)
STATIC_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".js", ".css")
# Junk signatures: ZAP bookkeeping alerts with zero security signal.
# Dropped only at informational risk — never above info.
JUNK_INFO_TITLES = frozenset({"Modern Web Application", "User Agent Fuzzer"})

# ZAP pluginId -> OWASP Top 10 2021 category. Covers the plugins we
# actually see; unknown plugins fall back to the central CWE table
# (app/owasp.py), then to [] (never invented). NOTE: plugin 10109
# (Modern TLS info) is deliberately absent — it reports cweid -1
# ("none") and any category would be fabricated (fixed b730b65).
PLUGIN_OWASP: dict[str, str] = {
    "40018": "A03:2021-Injection",  # SQL Injection
    "40019": "A03:2021-Injection",  # SQL Injection (MySQL)
    "40020": "A03:2021-Injection",  # SQL Injection (PostgreSQL)
    "40021": "A03:2021-Injection",  # SQL Injection (MSSQL)
    "40022": "A03:2021-Injection",  # SQL Injection (Oracle)
    "40012": "A03:2021-Injection",  # Cross Site Scripting (Reflected)
    "40014": "A03:2021-Injection",  # Cross Site Scripting (Persistent)
    "40032": "A03:2021-Injection",  # .htaccess Information Leak
    "90033": "A03:2021-Injection",  # Loosely Scoped Cookie
    "90022": "A05:2021-Security Misconfiguration",  # Application Error Disclosure
    "10098": "A01:2021-Broken Access Control",  # CORS misconfiguration
    "10038": "A05:2021-Security Misconfiguration",  # CSP missing
    "10055": "A05:2021-Security Misconfiguration",  # CSP directive fallback
    "10035": "A05:2021-Security Misconfiguration",  # HSTS missing
    "10020": "A05:2021-Security Misconfiguration",  # X-Frame-Options missing
    "10021": "A05:2021-Security Misconfiguration",  # X-Content-Type-Options missing
    "10015": "A05:2021-Security Misconfiguration",  # Incomplete cache-control
    "2": "A01:2021-Broken Access Control",  # Private IP disclosure
}


def _owasp_for(plugin_id: str, cwe_id: str) -> list[str]:
    """OWASP category for a ZAP alert. [] when unknown — never guessed."""
    if plugin_id and plugin_id in PLUGIN_OWASP:
        return [PLUGIN_OWASP[plugin_id]]
    return owasp_for(cwe=cwe_id)


# ZAP pluginId -> finding class for the central OWASP table (app/owasp.py).
PLUGIN_CLASS: dict[str, str] = {
    "40018": "sqli", "40019": "sqli", "40020": "sqli",
    "40021": "sqli", "40022": "sqli",
    "40012": "xss", "40014": "xss",
    "90022": "error-disclosure",
    "10098": "cors",
    "10038": "missing-security-header", "10035": "missing-security-header",
    "10055": "missing-security-header",
    "10020": "missing-security-header", "10021": "missing-security-header",
    "10015": "missing-security-header",
    "2": "private-ip",
    "10096": "timestamp-disclosure",
}


# Polling transports (socket.io long-polling URLs carry transport IDs
# that passive rules misread as session IDs / missing headers). Never
# an ascan target and never reported — counted in coverage instead.
SOCKETIO_MARKERS = ("/socket.io", "socket.io?")

# Static dead-ends: no params, no behavior — ascan injects into a void.
# Dropped from targets outright (passive findings about them, if any,
# still report normally).
JUNK_ASCAN_BASENAMES = frozenset({
    "sitemap.xml", "swagger.json", "openapi.json", "robots.txt",
    "favicon.ico", "favicon-16x16.png", "favicon-32x32.png",
})


def _target_value(u: str) -> int:
    """Ascan value score (higher = scan earlier). Injectable surface
    first: parameterized API routes, then bare API routes, then any
    parameterized URL; bare pages last. Static dead-ends score ~0 and
    are cut by the ceiling/budget before they burn slots."""
    low = u.lower()
    if low.rsplit("/", 1)[-1].split("?", 1)[0] in JUNK_ASCAN_BASENAMES:
        return -1000
    score = 0
    has_q = "?" in u and "=" in u.split("?", 1)[1]
    if has_q:
        score += 100
    elif "?" in u:
        score += 40
    if "/rest/" in low or "/api/" in low or low.rstrip("/").endswith("/api-docs"):
        score += 120
    if LOGIN_PATH_RE.search(u or "") or AUTH_PATH_RE.search(u or ""):
        score += 30
    return score


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


# ZAP pluginIds for SQL injection (plain + MySQL + PostgreSQL + MSSQL).
SQLI_PLUGINS = frozenset({"40018", "40019", "40020", "40021", "40022"})

SQLI_FIX = (
    "Use parameterized queries / prepared statements so user input is never "
    "concatenated into SQL (JDBC PreparedStatement, Node pg/mysql2 placeholders, "
    "PHP PDO::prepare, Python DB-API parameters). Prefer ORM bound parameters, "
    "validate + type-check input server-side, and run the DB user with least "
    "privilege (no DROP/ALTER/GRANT). A WAF rule is defense-in-depth, not a fix."
)


def _evidence_and_fix(alert: dict) -> tuple[str, str]:
    """Evidence with payload + response snippet for injection findings.

    Stock ZAP evidence is often just the param name; for SQLi the finding
    must carry what was sent (attack payload), where (param), and what
    came back (response snippet) — otherwise nobody can reproduce it.
    """
    pluginid = str(alert.get("pluginId") or alert.get("pluginid") or "")
    solution = alert.get("solution") or "Review and remediate this ZAP finding."
    if pluginid in SQLI_PLUGINS:
        param = str(alert.get("param") or "")
        payload = str(alert.get("attack") or "")
        snippet = str(alert.get("evidence") or "")[:300]
        parts = [p for p in (
            f"param={param}" if param else "",
            f"payload={payload}" if payload else "",
            f"response={snippet}" if snippet else "",
        ) if p]
        return (" | ".join(parts) or solution, SQLI_FIX)
    return (alert.get("evidence") or alert.get("param") or "", solution)


def _available_mb() -> int | None:
    """Free + reclaimable RAM in MB (MemAvailable), else None (fail-open)."""
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return None


def _firefox_pids() -> set[int]:
    """PIDs of running firefox binaries (any owner). Best-effort."""
    try:
        import subprocess

        out = subprocess.run(
            ["ps", "-eo", "pid,comm"], capture_output=True, text=True, timeout=10
        ).stdout
    except Exception:
        return set()
    pids: set[int] = set()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[1] in ("firefox-esr", "firefox", "firefox-bin"):
            try:
                pids.add(int(parts[0]))
            except ValueError:
                pass
    return pids


def _reap_firefox(pids: set[int], grace_s: float = 10.0) -> None:
    """SIGTERM then SIGKILL firefox PIDs spawned by our crawl.

    Only PIDs in `pids` (snapshotted as new during our run) are signalled —
    pre-existing PIDs such as a desktop browser are never touched. PIDs are
    re-validated as firefox before each signal (PID reuse guard).
    """
    import os
    import signal
    import subprocess
    import time as _time

    def _is_firefox(pid: int) -> bool:
        try:
            out = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm="],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()
            return out in ("firefox-esr", "firefox", "firefox-bin")
        except Exception:
            return False

    targets = [p for p in pids if _is_firefox(p)]
    for pid in targets:
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
    deadline = _time.time() + grace_s
    while _time.time() < deadline and any(_is_firefox(p) for p in targets):
        _time.sleep(1)
    for pid in targets:
        if _is_firefox(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass


def _swagger_ui_init_paths(js_text: str) -> list[str]:
    """Extract API paths embedded in a swagger-ui-init.js bundle.

    Juice Shop serves no raw swagger.json (the URL returns the Swagger
    UI HTML shell); its spec lives as a `swaggerDoc` object inside
    swagger-ui-init.js. Returns path keys (e.g. ["/orders"]) found
    under the first "paths" object, servers ignored. [] on any error.
    """
    try:
        text = js_text or ""
        idx = text.find('"paths"')
        if idx < 0:
            return []
        brace = text.find("{", idx)
        if brace < 0:
            return []
        depth = 0
        end = -1
        for i in range(brace, min(len(text), brace + 20000)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end < 0:
            return []
        import json as _json

        try:
            obj = _json.loads(text[brace:end + 1])
        except Exception:
            return []
        if not isinstance(obj, dict):
            return []
        return [p for p in obj.keys() if isinstance(p, str) and p.startswith("/")]
    except Exception:
        return []


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
            # Purge first: killed workers leak ENABLED stale rules.
            # Removed in the outer finally so sessions never leak scans.
            self._purge_stale_auth_rules(client, base, api_key)
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
            seed_info = self._seed_targets(client, base, api_key, target)
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
                    self._check_stop("zap ascan")
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
                    except ScanStopped:
                        # User pressed pause/finish mid-target: do NOT
                        # swallow into skip_notes — propagate so the
                        # finally blocks stop ZAP and the pipeline ends now.
                        raise
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
                "spider_found": found,
                "ajax_spider": ajax_ok,
                "ajax_enabled": settings.zap_enable_ajax_spider,
                "ajax_note": getattr(self, "_ajax_note", ""),
                "ajax_browsers": settings.zap_ajax_browsers,
                "ajax_max_states": settings.zap_ajax_max_states,
                "ascan_scanned": scanned,
                "ascan_targets": len(ascan_targets),
                "ascan_cap": settings.zap_ascan_max_targets,
                "ascan_per_target_cap": per_target_cap,
                "ascan_recurse": settings.zap_ascan_recurse,
                "ascan_skipped": ascan_skipped,
                "openapi_doc": (seed_info or {}).get("openapi_doc"),
                "openapi_urls_added": (seed_info or {}).get("openapi_urls_added", 0),
                "openapi_note": (seed_info or {}).get("openapi_note") or "",
                "target_selection": getattr(self, "_target_stats", {}),
            }
            data["_spider_coverage"] = coverage
            (self.workdir / "zap-alerts.json").write_text(json.dumps(data, indent=2))
            # Coverage lives on self.coverage (persisted to job.coverage by
            # the pipeline), NOT as Severity.info findings — meta notes used
            # to inflate the info count and pollute the dashboard.
            self.coverage = coverage
            findings = self._parse(data.get("alerts", []))
            # _parse counts socket.io exclusions; record after the fact.
            self.coverage["socketio_dropped"] = getattr(self, "socketio_dropped", 0)
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

    def _purge_stale_auth_rules(self, client: httpx.Client, base: str, api_key: str) -> int:
        """Remove leftover octoscan-auth-* replacer rules from dead runs.

        _clear_auth_rules runs in a finally block, so a killed worker
        (SIGKILL, pkill, restart mid-scan) leaks an ENABLED rule carrying
        a stale session — the next scan for the same host then sends two
        Authorization headers (stale + fresh) with undefined winner.
        Purging at startup self-heals. Returns rules removed.
        """
        try:
            r = client.get(f"{base}/JSON/replacer/view/rules/", params={"apikey": api_key})
            r.raise_for_status()
            rules = r.json().get("rules") or []
        except Exception:
            return 0
        removed = 0
        for rule in rules:
            desc = str(rule.get("description") or "")
            if desc.startswith("octoscan-auth-"):
                try:
                    client.get(
                        f"{base}/JSON/replacer/action/removeRule/",
                        params={"apikey": api_key, "description": desc},
                    )
                    removed += 1
                except Exception:
                    pass
        if removed:
            self._activity(f"purged {removed} stale auth rule(s) from dead runs")
        return removed

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
            self._check_stop("zap wait")
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
            self._check_stop("zap sites-tree")
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

    def _seed_targets(self, client: httpx.Client, base: str, api_key: str, target: str) -> dict:
        """Best-effort tree seeding: injectable URLs + OpenAPI routes.

        All cheap (plain HTTP via ZAP proxy, no firefox). Never raises.
        Returns what was achieved so run() can record honest coverage:
        {"openapi_doc": url|None, "openapi_urls_added": n, "openapi_note": str}.
        CORRECTION (Oct 2026): a swagger.json URL showing up in ZAP's
        evidence text does NOT prove a spec file is served — Juice Shop's
        /api-docs/swagger.json returns the Swagger *UI* HTML shell, so
        importUrl answers OK while the Sites tree grows by zero. The real
        spec is embedded in /api-docs/swagger-ui-init.js (swaggerDoc
        object); parse its paths and seed those instead. Verified import
        = Result OK *and* the Sites tree actually grew.
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
        # Verified import = Result OK *and* the Sites tree actually grew
        # (ZAP answers OK even when the "document" is an HTML shell).
        info: dict = {"openapi_doc": None, "openapi_urls_added": 0, "openapi_note": ""}
        try:
            before = len(client.get(
                f"{base}/JSON/core/view/urls/",
                params={"apikey": api_key, "baseurl": target},
            ).json().get("urls") or [])
        except Exception:
            before = -1
        for doc in ("/api-docs/swagger.json", "/api-docs/openapi.json", "/swagger.json", "/openapi.json"):
            try:
                r = client.get(
                    f"{base}/JSON/openapi/action/importUrl/",
                    params={"apikey": api_key, "url": f"{root}{doc}"},
                )
                try:
                    ok = r.status_code == 200 and r.json().get("Result") == "OK"
                except Exception:
                    ok = False
                if not ok:
                    continue
                try:
                    after = len(client.get(
                        f"{base}/JSON/core/view/urls/",
                        params={"apikey": api_key, "baseurl": target},
                    ).json().get("urls") or [])
                except Exception:
                    after = before
                added = max(0, after - before) if before >= 0 else 0
                if added > 0:
                    info = {"openapi_doc": f"{root}{doc}", "openapi_urls_added": added, "openapi_note": ""}
                    break
                # Import "succeeded" but the tree did not grow: the URL
                # served the Swagger UI shell, not a spec. Keep looking.
                info["openapi_note"] = f"{doc} served UI shell, not a spec (tree unchanged)"
            except Exception:
                pass
        # Fallback: Juice Shop embeds its spec in
        # /api-docs/swagger-ui-init.js (a JS file defining a swaggerDoc
        # object). Parse its "paths" keys and seed each route so ascan
        # covers real API surface even when no raw spec file exists.
        if info["openapi_urls_added"] == 0:
            try:
                js = httpx.get(f"{root}/api-docs/swagger-ui-init.js", follow_redirects=True, timeout=15.0)
                if js.status_code == 200 and "swaggerDoc" in js.text:
                    paths = _swagger_ui_init_paths(js.text)
                    added = 0
                    for p in paths[:30]:
                        try:
                            client.get(
                                f"{base}/JSON/core/action/accessUrl/",
                                params={"apikey": api_key, "url": f"{root}{p}", "followRedirects": "true"},
                            )
                            added += 1
                        except Exception:
                            pass
                    if paths:
                        info = {
                            "openapi_doc": f"{root}/api-docs/swagger-ui-init.js",
                            "openapi_urls_added": added,
                            "openapi_note": f"parsed {len(paths)} embedded spec path(s); /rest/* not in spec",
                        }
            except Exception:
                pass
        return info

    def _select_ascan_targets(self, client: httpx.Client, base: str, api_key: str, target: str, seed: str) -> list[str]:
        """Pick active-scan targets deliberately: injectable URLs first.

        Priority: /rest/* or /api/* with a query string first (the real
        SQLi sink is /rest/products/search?q=), bare API routes second,
        other parameterized URLs third, seed fourth, everything else
        last. Dropped outright: '#' SPA routes, static assets, /assets/*
        trees, /socket.io/* polling endpoints, and paths that serve the
        SPA shell (verified by body comparison — they can never yield
        ascan vulns, only burn budget).
        The list is budget-driven: ordered best-first up to a safety
        ceiling, and the ascan loop stops on the shared time budget, not
        on the count. Selection stats land in coverage.
        """
        stats = {"tree_urls": 0, "dropped_static": 0, "dropped_shell": 0,
                 "dropped_socketio": 0, "kept": 0}
        try:
            r = client.get(f"{base}/JSON/core/view/urls/", params={"apikey": api_key, "baseurl": target})
            r.raise_for_status()
            urls = [u for u in (r.json().get("urls") or []) if isinstance(u, str) and u]
        except Exception:
            self._target_stats = stats
            return [seed]
        stats["tree_urls"] = len(urls)

        def _path(u: str) -> str:
            return u.lower().split("?", 1)[0]

        dynamic = []
        for u in urls:
            if "#" in u:
                continue
            low_path = _path(u)
            if low_path.endswith(STATIC_EXTENSIONS):
                stats["dropped_static"] += 1
                continue
            if "/assets/" in low_path:
                stats["dropped_static"] += 1
                continue
            if any(m in u.lower() for m in SOCKETIO_MARKERS):
                stats["dropped_socketio"] += 1
                continue
            if low_path.rsplit("/", 1)[-1].split("?", 1)[0] in JUNK_ASCAN_BASENAMES:
                stats["dropped_static"] += 1
                continue
            dynamic.append(u)

        # Drop SPA-shell paths: a different URL serving byte-identical
        # content to / is the app shell, never a distinct attack surface.
        # Parameterized and /rest/* URLs are always kept (never shell);
        # everything else is verified, bounded and fail-open.
        dynamic = self._drop_shell_paths(dynamic)
        stats["dropped_shell"] = self._shell_dropped

        # Value order, not arrival order: injectable API routes first so
        # the time budget (not the ceiling) decides depth. Ties keep tree
        # order via a stable sort.
        dynamic_sorted = sorted(set(dynamic), key=_target_value, reverse=True)
        # Seed first, then ranked order, deduped. The safety ceiling binds
        # the list, but the shared TIME budget decides how many actually
        # get scanned — the cut (eligible minus kept) is recorded below so
        # it stays visible instead of silent.
        ranked: list[str] = []
        for u in [seed, *dynamic_sorted]:
            if u not in ranked:
                ranked.append(u)
        ceiling = max(1, settings.zap_ascan_max_targets)
        ordered = ranked[:ceiling]
        stats["kept"] = len(ordered)
        stats["eligible"] = len(ranked)
        stats["cut"] = len(ranked) - len(ordered)
        stats["ranked_targets"] = ordered
        stats["cut_sample"] = ranked[ceiling:ceiling + 5]
        self._target_stats = stats
        self._activity(
            f"ascan targets: {len(ordered)} kept from {stats['tree_urls']} tree URLs "
            f"(static {stats['dropped_static']}, shell {stats['dropped_shell']}, "
            f"socket.io {stats['dropped_socketio']})"
        )
        return ordered or [seed]

    _shell_dropped = 0

    def _drop_shell_paths(self, urls: list[str]) -> list[str]:
        """Drop bare pages serving the SPA shell. Bounded + fail-open.

        Only candidates WITHOUT a query string and outside /rest/* are
        verified (at most 20 GETs, 4 s each); parameterized and REST URLs
        are injectable surface by construction and always kept. Network
        errors keep the URL.
        """
        self._shell_dropped = 0
        try:
            import httpx as _httpx

            root = _httpx.get(self.target_url, follow_redirects=True, timeout=10.0)
            root_body = root.content if root.status_code == 200 else None
        except Exception:
            return urls
        if root_body is None:
            return urls
        kept: list[str] = []
        checked = 0
        for u in urls:
            low = u.lower()
            verify = "?" not in u and "/rest/" not in low
            if verify and checked < 20:
                checked += 1
                try:
                    import httpx as _httpx

                    r = _httpx.get(u, follow_redirects=True, timeout=4.0)
                    if r.status_code == 200 and r.content == root_body:
                        self._shell_dropped += 1
                        continue
                except Exception:
                    pass  # fail-open: keep on any network error
            kept.append(u)
        return kept

    def _run_ajax_spider(self, client: httpx.Client, base: str, api_key: str, target: str) -> bool:
        """Run ZAP's AJAX spider (browser-driven, for JS-heavy SPAs) inside a cage.

        Bounds (all env-tunable, restored afterwards): 1 browser, depth 5,
        200 crawl states, 5-min ZAP-side cap + our own poll deadline. Skips
        when free RAM is below zap_ajax_min_free_mb. Afterwards the spider
        is stopped and any firefox processes it spawned are reaped by PID —
        pre-existing PIDs (your desktop browser) are never touched.
        Never fails the whole scan: False = proceed with classic-spider URLs.
        """
        if not settings.zap_enable_ajax_spider:
            return False
        free_mb = _available_mb()
        if free_mb is not None and free_mb < settings.zap_ajax_min_free_mb:
            self._ajax_note = (
                f"skipped: {free_mb} MB free < {settings.zap_ajax_min_free_mb} MB minimum"
            )
            self._activity(f"ajax spider {self._ajax_note}")
            return False
        self._ajax_note = ""
        try:
            before_urls = self._tree_size(client, base, api_key, target)
        except Exception:
            before_urls = -1
        prev = self._cage_ajax(client, base, api_key)
        browsers_before = _firefox_pids()
        completed = False
        try:
            try:
                r = client.get(
                    f"{base}/JSON/ajaxSpider/action/scan/",
                    params={"apikey": api_key, "url": target, "subtreeOnly": "true"},
                )
                r.raise_for_status()
            except Exception:
                # Older daemon or bad param: retry bare before giving up.
                try:
                    r = client.get(
                        f"{base}/JSON/ajaxSpider/action/scan/",
                        params={"apikey": api_key, "url": target},
                    )
                    r.raise_for_status()
                except Exception:
                    return False
            if "does not exist" in r.text:
                return False
            # Cap AJAX crawl so it can't eat the whole scan budget.
            deadline = time.time() + max(
                30, min(settings.zap_ajax_timeout_seconds, settings.scan_timeout_seconds // 3)
            )
            status_url = f"{base}/JSON/ajaxSpider/view/status/"
            try:
                while time.time() < deadline:
                    self._check_stop("zap ajax-spider")
                    s = client.get(status_url, params={"apikey": api_key})
                    s.raise_for_status()
                    if str(s.json().get("status", "")).lower() == "stopped":
                        completed = True
                        break
                    time.sleep(5)
            except ScanStopped:
                raise
            except Exception:
                completed = False
        finally:
            try:
                client.get(f"{base}/JSON/ajaxSpider/action/stop/", params={"apikey": api_key})
            except Exception:
                pass
            self._uncage_ajax(client, base, api_key, prev)
            _reap_firefox(_firefox_pids() - browsers_before)
        try:
            states = self._ajax_states(client, base, api_key)
            after_urls = self._tree_size(client, base, api_key, target)
        except Exception:
            states, after_urls = -1, -1
        grown = (after_urls - before_urls) if (before_urls >= 0 and after_urls >= 0) else -1
        self._ajax_note = (
            f"{'completed' if completed else 'time-boxed'}: "
            f"{states} states, {grown if grown >= 0 else '?'} new URLs "
            f"({settings.zap_ajax_browsers} browser, depth {settings.zap_ajax_max_depth}, "
            f"states cap {settings.zap_ajax_max_states})"
        )
        self._activity(f"ajax spider {self._ajax_note}")
        return True

    def _tree_size(self, client: httpx.Client, base: str, api_key: str, target: str) -> int:
        r = client.get(f"{base}/JSON/core/view/urls/", params={"apikey": api_key, "baseurl": target})
        r.raise_for_status()
        return len(r.json().get("urls") or [])

    def _ajax_states(self, client: httpx.Client, base: str, api_key: str) -> int:
        try:
            r = client.get(f"{base}/JSON/ajaxSpider/view/numberOfResults/", params={"apikey": api_key})
            r.raise_for_status()
            return int(r.json().get("numberOfResults", -1))
        except Exception:
            return -1

    def _cage_ajax(self, client: httpx.Client, base: str, api_key: str) -> dict[str, int]:
        """Save daemon AJAX options, apply ours. Returns previous values."""
        prev: dict[str, int] = {}
        want = {
            "NumberOfBrowsers": settings.zap_ajax_browsers,
            "MaxCrawlDepth": settings.zap_ajax_max_depth,
            "MaxCrawlStates": settings.zap_ajax_max_states,
            "MaxDuration": settings.zap_ajax_max_minutes,
        }
        getters = {
            "NumberOfBrowsers": "optionNumberOfBrowsers",
            "MaxCrawlDepth": "optionMaxCrawlDepth",
            "MaxCrawlStates": "optionMaxCrawlStates",
            "MaxDuration": "optionMaxDuration",
        }
        setters = {
            "NumberOfBrowsers": "setOptionNumberOfBrowsers",
            "MaxCrawlDepth": "setOptionMaxCrawlDepth",
            "MaxCrawlStates": "setOptionMaxCrawlStates",
            "MaxDuration": "setOptionMaxDuration",
        }
        for key, view in getters.items():
            try:
                r = client.get(f"{base}/JSON/ajaxSpider/view/{view}/", params={"apikey": api_key})
                prev[key] = int(r.json().get(key, 0))
            except Exception:
                pass
        for key, action in setters.items():
            try:
                client.get(
                    f"{base}/JSON/ajaxSpider/action/{action}/",
                    params={"apikey": api_key, "Integer": want[key]},
                )
            except Exception:
                pass
        self._activity(
            f"ajax cage: {want['NumberOfBrowsers']} browser, depth {want['MaxCrawlDepth']}, "
            f"{want['MaxCrawlStates']} states, {want['MaxDuration']} min (was {prev})"
        )
        return prev

    def _uncage_ajax(self, client: httpx.Client, base: str, api_key: str, prev: dict[str, int]) -> None:
        """Restore daemon AJAX options saved by _cage_ajax. Best-effort."""
        setters = {
            "NumberOfBrowsers": "setOptionNumberOfBrowsers",
            "MaxCrawlDepth": "setOptionMaxCrawlDepth",
            "MaxCrawlStates": "setOptionMaxCrawlStates",
            "MaxDuration": "setOptionMaxDuration",
        }
        for key, val in prev.items():
            try:
                client.get(
                    f"{base}/JSON/ajaxSpider/action/{setters[key]}/",
                    params={"apikey": api_key, "Integer": val},
                )
            except Exception:
                pass

    def _parse(self, alerts: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        socketio_dropped = 0
        self.socketio_dropped = 0
        for alert in alerts:
            title = alert.get("alert") or alert.get("name") or "ZAP alert"
            location = alert.get("url") or self.target_url
            norm_url = _normalize_url(location)
            if any(s in norm_url for s in NOISY_PATH_SUBSTRINGS):
                continue
            # socket.io polling endpoints: transport IDs trip passive
            # rules (session-in-URL, missing-header FPs). Excluded from
            # scanning AND reporting; counted in coverage for honesty.
            if any(m in norm_url for m in SOCKETIO_MARKERS):
                socketio_dropped += 1
                self.socketio_dropped = socketio_dropped
                continue
            # Drop low-value static-asset noise (e.g. User Agent Fuzzer on /assets/*.js)
            # but keep anything with meaningful risk.
            risk_raw = alert.get("risk") or alert.get("riskcode") or "0"
            if title in JUNK_INFO_TITLES and str(risk_raw).lower() in ("0", "1", "low", "informational", "info"):
                continue
            if norm_url.lower().endswith(STATIC_EXTENSIONS) and str(risk_raw).lower() in ("0", "1", "low", "informational", "info"):
                continue
            key = _dedup_key(alert, norm_url)
            if key in seen:
                continue
            seen.add(key)
            risk = risk_raw
            pluginid = str(alert.get("pluginId") or alert.get("pluginid") or "")
            param = str(alert.get("param") or "")
            evidence, recommendation = _evidence_and_fix(alert)
            # CWE goes in `cwe` (list), OWASP in `owasp` (list); `cve`
            # stays None — ZAP reports weaknesses, not CVE ids, and the
            # old code filing "CWE-89" into `cve` broke the dashboard's
            # CVE column (fixed Oct 2026 by merging scan-quality-v2).
            # ZAP uses cweid -1/0/"0" for "no CWE" — never emit CWE--1/CWE-0.
            cwe_id = str(alert.get("cweid") or "").strip()
            cwe = [clean_cwe(cwe_id)] if clean_cwe(cwe_id) else []
            cwe = [c for c in cwe if c]
            owasp = _owasp_for(pluginid, cwe_id)
            findings.append(
                Finding(
                    scanner=self.name,
                    title=title,
                    severity=from_zap_risk(risk),
                    description=alert.get("description") or alert.get("other") or title,
                    evidence=evidence,
                    location=norm_url,
                    recommendation=recommendation,
                    cwe=cwe,
                    owasp=owasp,
                    request=norm_url + (f" param={param}" if param else ""),
                    response=(evidence or "")[:500],
                    raw={
                        "pluginid": pluginid,
                        "cweid": alert.get("cweid"),
                        "finding_class": PLUGIN_CLASS.get(pluginid),
                        "param": alert.get("param"),
                        "attack": alert.get("attack"),
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
