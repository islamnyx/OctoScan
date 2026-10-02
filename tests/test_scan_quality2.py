"""Second scan-quality batch (Oct 2026): canonical severities, representative
URLs, correlation chains, CVSS estimates, SQLi evidence, Nikto generic
catch-all + HSTS drop, ascan ranking, OpenAPI verification, wider
sensitive-files probes, auth sidecar.
"""

from __future__ import annotations

from app.models import Finding, Severity
from app.normalize import (
    CONCEPT_SEVERITY,
    _canonical_severity,
    clean_cwe,
    correlate,
    dedupe,
    prioritize,
)


def _f(**kw):
    base = dict(scanner="zap", title="t", severity=Severity.low, description="d")
    base.update(kw)
    return Finding(**base)


def test_concept_severity_table_sane():
    assert CONCEPT_SEVERITY["cors-star"] == Severity.medium
    assert CONCEPT_SEVERITY["hsts-missing"] == Severity.low
    assert CONCEPT_SEVERITY["permissions-policy-missing"] == Severity.info
    assert _canonical_severity("zap-10096-") == Severity.info
    assert _canonical_severity("zap-40018-q") is None
    assert _canonical_severity("cors-star") == Severity.medium


def test_clean_cwe():
    assert clean_cwe("89") == "CWE-89"
    assert clean_cwe(79) == "CWE-79"
    assert clean_cwe("CWE-89") == "CWE-89"
    for bad in ("0", 0, "-1", "", None, "abc"):
        assert clean_cwe(bad) is None


def test_dedupe_canonical_severity_and_rep_url(tmp_path):
    a = _f(title="Cross-Domain Misconfiguration", severity=Severity.low,
           location="http://h/rest/products/search?q=ZapTest",
           raw={"pluginid": "10098"})
    b = _f(title="Cross-Domain Misconfiguration", severity=Severity.high,
           location="http://h/", raw={"pluginid": "10098"})
    out = dedupe([a, b])
    assert len(out) == 1
    assert out[0].severity == Severity.medium  # canonical cors-star
    assert out[0].raw.get("severity_normalized_from") == "high"
    assert out[0].location == "http://h/"  # shortest = representative


def test_correlate_robots_ftp_listing():
    rob = _f(scanner="nikto", title="Nikto 999996: robots", location="http://h/robots.txt")
    listing = _f(scanner="sensitive-files", title="Exposed directory listing: /ftp/",
                 location="http://h/ftp/", severity=Severity.medium)
    other = _f(title="Content Security Policy (CSP) Header Not Set", location="http://h/")
    out = correlate([rob, listing, other])
    chained = [f for f in out if f.location == "http://h/ftp/"][0]
    assert "attack_chain" in (chained.raw or {})
    assert "robots.txt" in chained.description
    plain = [f for f in out if "Content Security Policy" in f.title][0]
    assert "attack_chain" not in (plain.raw or {})


def test_correlate_login_500_points_at_sqli():
    login = _f(scanner="zap", title="Application Error Disclosure",
               location="http://h/rest/user/login", evidence="HTTP/1.1 500 Internal Server Error")
    sqli = _f(title="SQL Injection", severity=Severity.high,
              location="http://h/rest/products/search?q=x")
    out = correlate([login, sqli])
    s = [f for f in out if f.title == "SQL Injection"][0]
    assert "login_500_candidate" in (s.raw or {})
    assert "OR 1=1" in s.description


def test_prioritize_fills_cvss_estimates():
    out = prioritize([
        _f(title="SQL Injection", severity=Severity.high),
        _f(title="X", severity=Severity.info),
    ])
    by_title = {f.title: f for f in out}
    assert by_title["SQL Injection"].cvss == 8.0
    assert by_title["SQL Injection"].raw["cvss_estimated"] is True
    assert by_title["X"].cvss == 0.0
    # real scores survive untouched
    real = _f(title="R", severity=Severity.high, cvss=7.3)
    assert prioritize([real])[0].cvss == 7.3
    assert "cvss_estimated" not in (prioritize([real])[0].raw or {})


def test_zap_sqli_evidence_carries_payload_param_response(tmp_path):
    from app.scanners.zap_scanner import ZapScanner

    z = ZapScanner("http://127.0.0.1:9/", tmp_path)
    out = z._parse([{
        "alert": "SQL Injection", "risk": "High", "cweid": "89",
        "url": "http://127.0.0.1:9/rest/products/search?q=x",
        "pluginId": "40018", "param": "q", "attack": "'\"",
        "evidence": "HTTP/1.1 500 Internal Server Error",
        "description": "SQL injection may be possible.", "solution": "old",
    }])
    assert len(out) == 1
    f = out[0]
    assert "param=q" in f.evidence
    assert "payload=" in f.evidence
    assert "response=" in f.evidence
    assert "parameterized" in f.recommendation
    assert f.cwe == ["CWE-89"]
    assert f.cve is None
    assert f.owasp == ["A03:2021-Injection"]
    assert f.raw["attack"] == "'\""


def test_nikto_hsts_dropped_on_http(tmp_path):
    from app.scanners.nikto_scanner import NiktoScanner

    n = NiktoScanner("http://127.0.0.1:9/", tmp_path)
    items = [{"id": "013587", "method": "GET", "url": "/",
              "msg": "Suggested security header missing: strict-transport-security."}]
    http_out = n._build_findings(items)
    assert all("013587" not in (f.title or "") for f in http_out)
    n2 = NiktoScanner("https://example.com/", tmp_path)
    assert any("013587" in (f.title or "") for f in n2._build_findings(items))


def test_nikto_generic_catchall_demotes_unknown_stack(tmp_path):
    from app.scanners.nikto_scanner import NiktoScanner

    n = NiktoScanner("http://127.0.0.1:9/", tmp_path)
    n._root_fetched = True
    n._root_body = b"<html>shell</html>"
    import httpx as _httpx

    class _R:
        status_code = 200
        content = b"<html>shell</html>"

    real_get = _httpx.get
    _httpx.get = lambda *a, **k: _R()
    try:
        out = n._build_findings([{
            "id": "009999", "method": "GET", "url": "/weird-admin-panel",
            "msg": "An admin interface was identified.",
        }])
    finally:
        _httpx.get = real_get
    # Proven catch-all: coverage note, not a finding row (only "ran clean" remains).
    assert [f.title for f in out] == ["No Nikto findings"]
    assert n.coverage["spa_catchall"]["count"] == 1
    assert "/weird-admin-panel" in n.coverage["spa_catchall"]["paths"]


def test_ascan_rank_api_params_first_drop_assets_socketio():
    from app.scanners.zap_scanner import ZapScanner

    z = ZapScanner.__new__(ZapScanner)

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"urls": [
                "http://h/assets/app.js",
                "http://h/socket.io/?EIO=4",
                "http://h/",
                "http://h/search?q=ZapTest",
                "http://h/rest/user/login",
                "http://h/rest/products/search?q=x",
            ]}

    class _C:
        def get(self, *a, **k):
            return _Resp()

    out = z._select_ascan_targets(_C(), "base", "key", "http://h", "http://h/rest/products/search?q=x")
    assert not any("/assets/" in u or "socket.io" in u for u in out)
    assert out[0] == "http://h/rest/products/search?q=x"
    rest_idx = out.index("http://h/rest/user/login")
    q_idx = out.index("http://h/search?q=ZapTest")
    assert rest_idx < q_idx  # bare API routes before bare parameterized


def test_sensitive_new_probes_and_listing():
    from app import sensitive as sens

    assert any(p[0] == "/server-status" for p in sens.WELLKNOWN_PROBES)
    assert any(p[0] == "/.svn/entries" for p in sens.WELLKNOWN_PROBES)
    assert any(p[0] == "/web.config" for p in sens.WELLKNOWN_PROBES)
    assert any(p[0] == "/composer.json" for p in sens.WELLKNOWN_PROBES)
    assert sens._is_listing(b"<html><head><title>Index of /ftp/</title></head><body><a href='x'>Parent Directory</a>")
    assert not sens._is_listing(b"<html><body>Juice Shop app shell</body></html>")
    assert sens._is_server_status(b"<html><title>Apache Status</title>Server Version requests currently being processed")
    assert sens._is_svn_entries(b"8\ndir\n123\n")
    assert sens._is_web_config(b'<?xml><configuration><appSettings><add key="x"/></appSettings></configuration>')
    assert sens._is_composer_json(b'{"name": "juice-shop", "require": {"express": "^4"}}')


def test_store_auth_sidecar(tmp_path, monkeypatch):
    from app.config import settings
    from app.models import ScanAuth, ScanJob
    from app.store import load_job, save_job

    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    job = ScanJob(target_url="http://127.0.0.1:9/",
                  auth=ScanAuth(headers={"Authorization": "Bearer SECRET"}))
    save_job(job)
    import json as _json

    disk = _json.loads((tmp_path / "data" / "scans" / job.id / "job.json").read_text())
    assert "auth" not in disk
    assert "SECRET" not in (tmp_path / "data" / "scans" / job.id / "job.json").read_text()
    side = _json.loads((tmp_path / "data" / "scans" / job.id / "auth.json").read_text())
    assert side["headers"]["Authorization"] == "Bearer SECRET"
    back = load_job(job.id)
    assert back.auth.headers["Authorization"] == "Bearer SECRET"
    assert back.model_dump(mode="json", exclude={"auth"}).get("auth") is None
