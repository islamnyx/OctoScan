"""Fourth scan-quality batch (Oct 2026): deliberate targeting, socket.io
exclusion, deterministic attribution, central OWASP table, Nikto folding,
Nuclei exposure pass, evidence quality, login/SQLi verification.
"""

from __future__ import annotations

from app.models import Finding, Severity
from app.normalize import correlate, dedupe
from app.owasp import owasp_for


def _f(**kw):
    base = dict(scanner="zap", title="t", severity=Severity.low, description="d")
    base.update(kw)
    return Finding(**base)


def test_owasp_table_cwe_consistent():
    # CWE-497 is A01 on Private IP AND on Timestamp Disclosure alike.
    assert owasp_for(cwe="497") == ["A01:2021-Broken Access Control"]
    assert owasp_for(cwe="CWE-497") == ["A01:2021-Broken Access Control"]
    assert owasp_for(cwe="1395") == ["A06:2021-Vulnerable and Outdated Components"]
    assert owasp_for(cwe="598") == ["A01:2021-Broken Access Control"]
    assert owasp_for(cwe="89") == ["A03:2021-Injection"]
    assert owasp_for(cwe="-1") == []
    assert owasp_for(cwe="0") == []
    assert owasp_for() == []


def test_owasp_table_finding_class():
    assert owasp_for(finding_class="metrics-exposure") == ["A01:2021-Broken Access Control"]
    assert owasp_for(finding_class="missing-security-header") == ["A05:2021-Security Misconfiguration"]
    assert owasp_for(finding_class="vulnerable-library") == ["A06:2021-Vulnerable and Outdated Components"]
    assert owasp_for(finding_class="tls-weakness") == ["A02:2021-Cryptographic Failures"]
    assert owasp_for(finding_class="no-such-class") == []
    # CWE beats class beats title keywords.
    assert owasp_for(cwe="89", finding_class="cors", title="Cross-Domain") == ["A03:2021-Injection"]
    assert owasp_for(title="Content Security Policy (CSP) Header Not Set") == ["A05:2021-Security Misconfiguration"]


def test_sitewide_rep_is_origin_root():
    a = _f(title="Content Security Policy (CSP) Header Not Set", severity=Severity.medium,
           location="http://h/rest/user/login", raw={"pluginid": "10038"})
    b = _f(title="Content Security Policy (CSP) Header Not Set", severity=Severity.medium,
           location="http://h/", raw={"pluginid": "10038"})
    out = dedupe([a, b])
    assert len(out) == 1
    assert out[0].location == "http://h/"
    assert "http://h/rest/user/login" in (out[0].raw.get("affected_urls") or [])


def test_zap_socketio_dropped_and_counted(tmp_path):
    from app.scanners.zap_scanner import ZapScanner

    z = ZapScanner("http://127.0.0.1:9/", tmp_path)
    out = z._parse([
        {"alert": "Session ID in URL Rewrite", "risk": "Medium", "cweid": "598",
         "url": "http://127.0.0.1:9/socket.io?EIO=4&transport=polling",
         "pluginId": "3", "description": "sid", "solution": "fix"},
        {"alert": "SQL Injection", "risk": "High", "cweid": "89",
         "url": "http://127.0.0.1:9/rest/products/search?q=x",
         "pluginId": "40018", "param": "q", "description": "sqli", "solution": "fix"},
    ])
    assert [f.title for f in out] == ["SQL Injection"]
    assert z.socketio_dropped == 1


def test_target_selection_rank_and_drops():
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
    assert z._target_stats["dropped_socketio"] == 1
    assert z._target_stats["kept"] == len(out)


def test_nikto_named_catchall_folded(tmp_path):
    from app.scanners.zap_scanner import ZapScanner  # noqa: F401  (import order)
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
        out = n._build_findings([
            {"id": "002739", "method": "GET", "url": "/.htpasswd",
             "msg": "/.htpasswd: Contains authorization information."},
            {"id": "007303", "method": "GET", "url": "/JAMonAdmin.jsp",
             "msg": "JAMonAdmin.jsp available: Java application monitor."},
        ])
    finally:
        _httpx.get = real_get
    # Folded into coverage, not a finding row (only the "ran clean" note remains).
    assert [f.title for f in out] == ["No Nikto findings"]
    assert n.coverage["spa_catchall"]["count"] == 2
    assert ".htpasswd" in n.coverage["spa_catchall"]["reason"]
    assert "JAMonAdmin" in n.coverage["spa_catchall"]["reason"]


def test_nuclei_classification_and_evidence(tmp_path):
    import json

    from app.scanners.nuclei_scanner import NucleiScanner, _response_evidence

    jl = tmp_path / "nuclei.jsonl"
    jl.write_text(json.dumps({
        "template-id": "prometheus-metrics",
        "info": {"name": "Prometheus Metrics - Detect", "severity": "medium",
                 "classification": {"cwe-id": ["cwe-200"], "cvss-score": 5.3}},
        "matched-at": "http://h/metrics",
    }) + "\n")
    out = NucleiScanner("http://h", tmp_path)._parse(jl)
    assert len(out) == 1
    assert out[0].cwe == ["CWE-200"]
    assert out[0].cvss == 5.3  # measured, not the 5.5 bucket estimate
    assert "metrics" in out[0].recommendation.lower()

    ev = _response_evidence("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n# HELP x\ny")
    assert ev.startswith("HTTP 200")
    assert "# HELP" in ev


def test_nuclei_exposure_info_kept_only_when_allowed(tmp_path):
    import json

    from app.scanners.nuclei_scanner import NucleiScanner

    jl = tmp_path / "nuclei.jsonl"
    jl.write_text(json.dumps({
        "template-id": "swagger-api",
        "info": {"name": "Public Swagger API - Detect", "severity": "info"},
        "matched-at": "http://h/api-docs/",
    }) + "\n")
    z = NucleiScanner("http://h", tmp_path)
    assert z._parse(jl) == []  # main pass gates info out
    out = z._parse(jl, allow_info=True)
    assert len(out) == 1
    assert out[0].severity == Severity.info


def test_verify_helpers_offline():
    from app.verify import _is_sqli_candidate, _login_targets, _login_token, _with_param

    assert _with_param("http://h/s?q=x", "q", "y") == "http://h/s?q=y"
    assert _with_param("http://h/s", "q", "y") is None
    assert _login_token({"a": {"accessToken": "z"}}) == "z"
    assert _login_token({"x": 1}) is None
    sqli = _f(scanner="zap", title="SQL Injection", severity=Severity.high,
              raw={"pluginid": "40018"})
    assert _is_sqli_candidate(sqli) is True
    assert _is_sqli_candidate(_f(scanner="zap", title="X", raw={"pluginid": "10038"})) is False
    tagged = _f(title="Application Error Disclosure", location="http://h/api",
                raw={"affected_urls": ["http://h/api", "http://h/rest/user/login"]})
    assert _login_targets(tagged) == ["http://h/rest/user/login"]


def test_verify_findings_annotates_without_network(tmp_path, monkeypatch):
    from app import verify as vmod
    from app.verify import verify_findings

    monkeypatch.setattr(vmod, "confirm_sqli",
                        lambda f, auth=None: {"confirmed": True, "result": "error-confirmed", "note": "confirmed in test"})
    sqli = _f(scanner="zap", title="SQL Injection", severity=Severity.high,
              location="http://h/s?q=x", raw={"pluginid": "40018", "param": "q"})
    out = verify_findings([sqli])
    assert out[0].raw["sqli_confirmation"]["result"] == "error-confirmed"
    assert "error-confirmed" in out[0].description


def test_nikto_uncommon_header_is_info(tmp_path):
    from app.normalize import CONCEPT_SEVERITY, _canonical_severity, dedupe
    from app.scanners.nikto_scanner import NiktoScanner

    assert CONCEPT_SEVERITY["nikto-uncommon-header"] == Severity.info
    n = NiktoScanner("http://127.0.0.1:9/", tmp_path)
    n._root_fetched = True
    n._root_body = b"root"
    import httpx as _httpx

    class _R:
        status_code = 404
        content = b"not found"

    real_get = _httpx.get
    _httpx.get = lambda *a, **k: _R()
    try:
        out = n._build_findings([{
            "id": "999100", "method": "GET", "url": "/",
            "msg": "Uncommon header(s) 'x-recruiting' found, with contents: /#/jobs.",
        }])
    finally:
        _httpx.get = real_get
    assert len(out) == 1
    assert out[0].severity == Severity.low  # scanner default; canonicalized at merge
    merged = dedupe(out)
    assert merged[0].severity == Severity.info
    assert merged[0].raw.get("severity_normalized_from") == "low"


def test_csp_directive_merges_into_csp_missing():
    a = _f(title="Content Security Policy (CSP) Header Not Set", severity=Severity.medium,
           location="http://h/", raw={"pluginid": "10038"})
    b = _f(title="CSP: Failure to Define Directive with No Fallback", severity=Severity.medium,
           location="http://h/api-docs", raw={"pluginid": "10055"})
    out = dedupe([a, b])
    assert len(out) == 1
    assert out[0].location == "http://h/"
    assert out[0].severity == Severity.medium


def test_nikto_ftp_row_folds_into_listing():
    listing = _f(scanner="sensitive-files", title="Exposed directory listing: /ftp",
                 location="http://h/ftp", severity=Severity.medium)
    nikto_ftp = _f(scanner="nikto", title="Nikto 001675: This might be interesting.",
                   location="http://h/ftp/", severity=Severity.info)
    out = correlate([listing, nikto_ftp])
    assert [f.location for f in out] == ["http://h/ftp"]
    assert "http://h/ftp/" in (out[0].raw.get("folded_findings") or [])


def test_ftp_enrichment_flags_sensitive():
    from app.sensitive import _listing_files, _sensitive_names

    body = (b'<html><head><title>listing directory /ftp/</title></head><body>'
            b'<a href="legal.md">legal</a><a href="incident-support.kdbx">k</a>'
            b'<a href="app.js">a</a></body></html>')
    files = _listing_files(body)
    assert "legal.md" in files and "incident-support.kdbx" in files
    hits = _sensitive_names(files)
    assert "legal.md" in hits and "incident-support.kdbx" in hits
    assert "app.js" not in hits


def test_sqli_boolean_check_with_mocked_wire(tmp_path, monkeypatch):
    import httpx as _httpx
    from app.verify import confirm_sqli

    class _R:
        def __init__(self, status, body, headers=None):
            self.status_code = status
            self.content = body
            self.headers = headers or {}

    def _fake_get(url, **kw):
        if "ZapTest0" in url:
            return _R(200, b"[]")
        if "1%27%3D%271" in url or "%27+OR+%271" in url or "OR" in url:
            return _R(200, b"[" + b"x" * 2000 + b"]")
        return _R(500, b"error")

    monkeypatch.setattr(_httpx, "get", _fake_get)
    f = _f(scanner="zap", title="SQL Injection", severity=Severity.high,
           location="http://h/s?q=x", raw={"pluginid": "40018", "param": "q", "attack": "'\""})
    out = confirm_sqli(f)
    assert out["confirmed"] is True
    assert "boolean" in out["result"]
    assert out["stack"] == "generic"
