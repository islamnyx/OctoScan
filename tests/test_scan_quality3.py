"""Third scan-quality batch (Oct 2026): OpenAPI honesty, CWE/OWASP merge,
auth-aware merging, coverage not-applicable, auth export metadata,
estimated-CVSS flags.

Covers the review round on the 10-item batch:
- swagger.json serves the UI shell -> parse swagger-ui-init.js instead
- ZAP findings carry cwe/owasp lists (cve stays None), incl. Private IP
- merged rep URL prefers auth endpoints; login-500 escalated + linked
- robots <-> /ftp/ listing linked both directions
- testssl/nmap skips live in coverage, not in finding counts
- export carries auth {used, type} without the secret
"""

from __future__ import annotations

from app.models import Finding, ScanAuth, ScanJob, Severity
from app.normalize import correlate, dedupe, escalate_auth_errors, prioritize


def _f(**kw):
    base = dict(scanner="zap", title="t", severity=Severity.low, description="d")
    base.update(kw)
    return Finding(**base)


def test_owasp_for_plugin_cwe_fallback_and_unknown():
    from app.scanners.zap_scanner import _owasp_for

    assert _owasp_for("40018", "89") == ["A03:2021-Injection"]
    assert _owasp_for("10038", "") == ["A05:2021-Security Misconfiguration"]
    assert _owasp_for("2", "") == ["A01:2021-Broken Access Control"]
    assert _owasp_for("99999", "79") == ["A03:2021-Injection"]
    assert _owasp_for("99999", "0") == []
    assert _owasp_for("99999", "-1") == []
    assert _owasp_for("", "") == []
    # plugin 10109 reports cweid -1 ("none"): no invented category.
    assert _owasp_for("10109", "-1") == []


def test_zap_private_ip_disclosure_survives_with_taxonomy(tmp_path):
    from app.scanners.zap_scanner import ZapScanner

    z = ZapScanner("http://127.0.0.1:9/", tmp_path)
    out = z._parse([{
        "alert": "Private IP Disclosure", "risk": "Low", "cweid": "200",
        "url": "http://127.0.0.1:9/", "pluginId": "2", "param": "",
        "evidence": "10.0.0.5", "description": "Private IP in response.",
        "solution": "Remove private IPs from responses.",
    }])
    assert len(out) == 1
    assert out[0].cwe == ["CWE-200"]
    assert out[0].owasp == ["A01:2021-Broken Access Control"]
    assert out[0].cve is None


def test_swagger_ui_init_paths_parsed():
    from app.scanners.zap_scanner import _swagger_ui_init_paths

    js = ('var options = {"swaggerDoc": {"openapi": "3.0.0", '
          '"paths": {"/orders": {"post": {}}, "/orders/{id}": {"get": {}}}}}};')
    assert _swagger_ui_init_paths(js) == ["/orders", "/orders/{id}"]
    assert _swagger_ui_init_paths("window.onload = function() {}") == []
    assert _swagger_ui_init_paths("") == []


def test_dedupe_rep_url_prefers_auth_endpoint():
    a = _f(title="Application Error Disclosure", severity=Severity.low,
           location="http://h/api",
           raw={"pluginid": "90022", "param": ""})
    b = _f(title="Application Error Disclosure", severity=Severity.low,
           location="http://h/rest/user/login",
           raw={"pluginid": "90022", "param": ""})
    c = _f(title="Application Error Disclosure", severity=Severity.low,
           location="http://h/rest/user",
           raw={"pluginid": "90022", "param": ""})
    out = dedupe([a, b, c])
    assert len(out) == 1
    # The exact login sink wins over /api and over broader /rest/user.
    assert out[0].location == "http://h/rest/user/login"
    assert "http://h/api" in (out[0].raw.get("affected_urls") or [])


def test_correlate_login_500_via_merged_urls():
    merged_err = _f(title="Application Error Disclosure",
                    location="http://h/api", evidence="HTTP 500",
                    raw={"affected_urls": ["http://h/api", "http://h/rest/user/login"]})
    sqli = _f(title="SQL Injection", severity=Severity.high,
              location="http://h/rest/products/search?q=x")
    out = correlate([merged_err, sqli])
    s = [f for f in out if f.title == "SQL Injection"][0]
    assert "login_500_candidate" in (s.raw or {})
    assert "OR 1=1" in s.description


def test_escalate_auth_error_and_sqli_link():
    login = _f(title="Application Error Disclosure",
               location="http://h/rest/user/login",
               evidence="HTTP 500 Internal Server Error")
    sqli = _f(title="SQL Injection", severity=Severity.high,
              location="http://h/rest/products/search?q=x")
    out = escalate_auth_errors([login, sqli])
    by_title = {f.title: f for f in out}
    assert by_title["Application Error Disclosure"].severity == Severity.medium
    assert "auth-error-needs-review" in by_title["Application Error Disclosure"].raw["review_tags"]
    assert "same sink" in by_title["Application Error Disclosure"].description


def test_prioritize_applies_escalation_before_sort():
    f = _f(title="Application Error Disclosure", location="http://h/login")
    out = prioritize([f])
    assert out[0].severity == Severity.medium
    assert out[0].cvss == 5.5
    assert out[0].raw["cvss_estimated"] is True


def test_correlate_links_robots_and_listing_both_ways():
    rob = _f(scanner="nikto", title="Nikto 999996: robots.txt",
             location="http://h/robots.txt")
    listing = _f(scanner="sensitive-files", title="Exposed directory listing: /ftp",
                 location="http://h/ftp", severity=Severity.medium)
    out = correlate([rob, listing])
    # Folded into ONE finding: the low robots row disappears, the listing
    # carries the chain + fold record.
    assert [f.location for f in out] == ["http://h/ftp"]
    chained = out[0]
    assert "attack_chain" in (chained.raw or {})
    assert "robots.txt" in chained.description
    assert (chained.raw or {}).get("robots_folded") == ["http://h/robots.txt"]


def test_correlate_keeps_significant_robots():
    rob = _f(scanner="nikto", title="Nikto 999996: robots.txt",
             location="http://h/robots.txt", severity=Severity.medium)
    listing = _f(scanner="sensitive-files", title="Exposed directory listing: /ftp",
                 location="http://h/ftp", severity=Severity.medium)
    out = correlate([rob, listing])
    assert len(out) == 2  # medium+ robots rows are never folded away


def test_looks_dir_like_covers_slashless_ftp():
    from app.sensitive import _is_listing, _looks_dir_like

    assert _looks_dir_like("http://h/ftp/")
    assert _looks_dir_like("http://h/ftp")  # ZAP strips the trailing slash
    assert _looks_dir_like("http://h/files")
    assert not _looks_dir_like("http://h/")
    assert not _looks_dir_like("http://h/a.js")
    # Extensionless routes probe too (one GET, _is_listing says no) — harmless.
    assert _looks_dir_like("http://h/rest/user/login")
    # Juice Shop /ftp/ is serve-index ("listing directory /ftp/"), not the app shell.
    body = (b"<!DOCTYPE html><html><head><title>listing directory /ftp/</title></head>"
            b"<body><a href='a'>a</a><a href='b'>b</a><a href='c'>c</a></body></html>")
    assert _is_listing(body)
    assert not _is_listing(b"<!doctype html><html><body>Juice Shop app</body></html>")
    from app import sensitive as sens

    assert any(p[0] == "/ftp/" for p in sens.WELLKNOWN_PROBES)


def test_testssl_http_skip_lands_in_coverage(tmp_path):
    from app.scanners.testssl_scanner import TestsslScanner

    t = TestsslScanner("http://127.0.0.1:9/", tmp_path)
    assert t.run() == []
    assert t.coverage["status"] == "not-applicable"
    assert "TLS" in t.coverage["reason"] or "tls" in t.coverage["reason"].lower()


def test_export_auth_meta_without_secret(tmp_path, monkeypatch):
    from app.config import settings
    from app.store import load_job, save_job

    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    job = ScanJob(target_url="http://127.0.0.1:9/",
                  auth=ScanAuth(headers={"Authorization": "Bearer SECRET"}))
    save_job(job)
    import json as _json

    disk = _json.loads((tmp_path / "data" / "scans" / job.id / "job.json").read_text())
    assert "auth" not in disk

    from app.main import _auth_export_meta

    back = load_job(job.id)
    meta = _auth_export_meta(back)
    assert meta == {"used": True, "type": "bearer"}
    anon = _auth_export_meta(ScanJob(target_url="http://127.0.0.1:9/"))
    assert anon == {"used": False, "type": None}


def _zap_with_auth(target, tmp_path):
    from app.models import ScanAuth
    from app.scanners.zap_scanner import ZapScanner

    z = ZapScanner(target, tmp_path)
    z.auth = ScanAuth(headers={"Authorization": "Bearer TOK"})
    return z


def test_auth_rule_scope_follows_target_host(tmp_path):
    """Replacer scope must match the scan's own host (localhost vs 127.0.0.1)."""
    client = _FakeClient({})
    z127 = _zap_with_auth("http://127.0.0.1:3000/", tmp_path)
    added = z127._apply_auth_rules(client, "base", "key")
    assert added, "auth headers must produce a rule"
    scopes = [c[1].get("url") for c in client.calls if "/action/addRule/" in c[0]]
    assert scopes and all("127\\.0\\.0\\.1" in s for s in scopes)
    assert not any("localhost" in s for s in scopes)

    client2 = _FakeClient({})
    zlocal = _zap_with_auth("http://localhost:3000/", tmp_path)
    zlocal._apply_auth_rules(client2, "base", "key")
    scopes2 = [c[1].get("url") for c in client2.calls if "/action/addRule/" in c[0]]
    assert scopes2 and all("localhost" in s for s in scopes2)


def test_purge_removes_only_our_stale_rules(tmp_path):
    from app.scanners.zap_scanner import ZapScanner

    class _RulesClient(_FakeClient):
        def get(self, url, params=None):
            if "/view/rules/" in url:
                return _FakeResp({"rules": [
                    {"description": "octoscan-auth-deadbeef-Authorization"},
                    {"description": "Remove CSP"},
                    {"description": "octoscan-auth-deadbeef-Cookie"},
                ]})
            return super().get(url, params=params)

    z = ZapScanner("http://127.0.0.1:9/", tmp_path)
    client = _RulesClient({})
    assert z._purge_stale_auth_rules(client, "base", "key") == 2
    removed = [c[1].get("description") for c in client.calls if "/action/removeRule/" in c[0]]
    assert sorted(removed) == ["octoscan-auth-deadbeef-Authorization", "octoscan-auth-deadbeef-Cookie"]


def test_purge_fail_open(tmp_path):
    from app.scanners.zap_scanner import ZapScanner

    class _BrokenClient:
        def get(self, url, params=None):
            raise RuntimeError("daemon down")

    z = ZapScanner("http://127.0.0.1:9/", tmp_path)
    assert z._purge_stale_auth_rules(_BrokenClient(), "base", "key") == 0


class _FakeResp:
    def __init__(self, payload=None, text=""):
        self._payload = payload or {}
        self.text = text

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeClient:
    """Records GETs; serves option views from a dict."""

    def __init__(self, options):
        self.options = dict(options)
        self.calls = []

    def get(self, url, params=None):
        self.calls.append((url, dict(params or {})))
        if "/view/option" in url:
            key = url.rsplit("/view/option", 1)[1].rstrip("/")
            return _FakeResp({key: str(self.options.get(key, 0))})
        if "/action/setOption" in url:
            key = url.rsplit("/action/setOption", 1)[1].rstrip("/")
            self.options[key] = int((params or {}).get("Integer", 0))
            return _FakeResp({"Result": "OK"})
        return _FakeResp({"Result": "OK"})


def test_ajax_cage_sets_bounds_and_restores(tmp_path):
    from app.scanners.zap_scanner import ZapScanner

    z = ZapScanner("http://127.0.0.1:9/", tmp_path)
    client = _FakeClient({"NumberOfBrowsers": 12, "MaxCrawlDepth": 10,
                          "MaxCrawlStates": 0, "MaxDuration": 60})
    prev = z._cage_ajax(client, "base", "key")
    assert prev == {"NumberOfBrowsers": 12, "MaxCrawlDepth": 10,
                    "MaxCrawlStates": 0, "MaxDuration": 60}
    assert client.options["NumberOfBrowsers"] == 1  # caged, not 12
    assert client.options["MaxCrawlStates"] == 200
    z._uncage_ajax(client, "base", "key", prev)
    assert client.options["NumberOfBrowsers"] == 12  # daemon values restored
    assert client.options["MaxDuration"] == 60


def test_ajax_skipped_when_low_memory(tmp_path, monkeypatch):
    from app.config import settings
    from app.scanners import zap_scanner as zmod
    from app.scanners.zap_scanner import ZapScanner

    monkeypatch.setattr(zmod, "_available_mb", lambda: 100)
    monkeypatch.setattr(settings, "zap_ajax_min_free_mb", 1500)
    monkeypatch.setattr(settings, "zap_enable_ajax_spider", True)
    z = ZapScanner("http://127.0.0.1:9/", tmp_path)
    assert z._run_ajax_spider(object(), "base", "key", "http://127.0.0.1:9/") is False
    assert "skipped" in (z._ajax_note or "")


def test_ajax_disabled_flag(tmp_path, monkeypatch):
    from app.config import settings
    from app.scanners.zap_scanner import ZapScanner

    monkeypatch.setattr(settings, "zap_enable_ajax_spider", False)
    z = ZapScanner("http://127.0.0.1:9/", tmp_path)
    assert z._run_ajax_spider(object(), "base", "key", "http://127.0.0.1:9/") is False


def test_available_mb_and_firefox_pids_shapes():
    from app.scanners import zap_scanner as zmod

    free = zmod._available_mb()
    assert free is None or (isinstance(free, int) and free > 0)
    pids = zmod._firefox_pids()
    assert isinstance(pids, set)
    zmod._reap_firefox(set())  # empty set = no-op, never raises
