"""Scan-quality noise cuts (Juice Shop baseline 92e0a552, 1 Oct 2026).

- ZAP: cweid -1/0/"0" never becomes CWE--1/CWE-0; junk info signatures
  (Modern Web Application, User Agent Fuzzer) dropped, kept above info.
- testssl: non-HTTPS target returns [] (a skipped check is not a finding).
- nmap: the target's own port is skipped as expected-open, not reported.
"""

from __future__ import annotations

from app.models import Severity


def _zap(tmp_path):
    from app.scanners.zap_scanner import ZapScanner

    return ZapScanner("http://localhost:3000", tmp_path)


def _alert(title, risk="Informational", cweid="", url="http://localhost:3000/", param=None):
    return {
        "alert": title, "risk": risk, "cweid": cweid, "url": url,
        "pluginId": "99999", "param": param if param is not None else title,
        "description": title, "solution": "fix",
    }


def test_zap_cwe_invalid_never_emitted(tmp_path):
    z = _zap(tmp_path)
    out = z._parse([
        _alert("A", cweid="-1"), _alert("B", cweid="0"),
        _alert("C", cweid=0), _alert("D", cweid=""),
        _alert("SQL Injection", risk="High", cweid="89",
               url="http://localhost:3000/rest/products/search?q=x"),
    ])
    by_title = {f.title: f for f in out}
    for t in ("A", "B", "C", "D"):
        assert by_title[t].cwe == []
        assert by_title[t].cve is None
        assert by_title[t].owasp == []
    sqli = by_title["SQL Injection"]
    assert sqli.cwe == ["CWE-89"]
    assert sqli.cve is None  # weaknesses go in cwe, never fabricated CVEs
    assert sqli.owasp == ["A03:2021-Injection"]


def test_zap_junk_info_dropped_but_kept_when_real(tmp_path):
    z = _zap(tmp_path)
    out = z._parse([
        _alert("Modern Web Application"),
        _alert("User Agent Fuzzer", risk="1", url="http://localhost:3000/assets/public"),
        _alert("Modern Web Application", risk="High"),
        _alert("Content Security Policy (CSP) Header Not Set", risk="Medium", cweid="693"),
    ])
    titles = [f.title for f in out]
    assert titles.count("Modern Web Application") == 1  # only the High one
    assert "User Agent Fuzzer" not in titles
    assert "Content Security Policy (CSP) Header Not Set" in titles
    assert out[0].severity == Severity.high or any(
        f.title == "Modern Web Application" and f.severity == Severity.high for f in out
    )


def test_testssl_http_returns_no_findings(tmp_path):
    from app.scanners.testssl_scanner import TestsslScanner

    assert TestsslScanner("http://localhost:3000", tmp_path).run() == []


NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="{p1}"><state state="open"/>
<service name="http" product="" version="" method="table" conf="3" servicefp="HTTP/1.1 200"/></port>
<port protocol="tcp" portid="{p2}"><state state="open"/>
<service name="http-proxy" product="" version="" method="probed" conf="7"/></port>
</ports></host></nmaprun>"""


def _nmap(tmp_path, p1, p2):
    from app.scanners.nmap_scanner import NmapScanner

    xml = tmp_path / "nmap.xml"
    xml.write_text(NMAP_XML.format(p1=p1, p2=p2))
    return NmapScanner("http://localhost:3000", tmp_path), xml


def test_nmap_skips_target_own_port(tmp_path):
    nmap, xml = _nmap(tmp_path, "3000", "8080")
    out = nmap._parse(xml)
    assert [f.raw["port"] for f in out] == ["8080"]


def test_nmap_only_target_port_gives_expected_marker(tmp_path):
    from app.scanners.nmap_scanner import NmapScanner

    xml = tmp_path / "nmap.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><ports>'
        '<port protocol="tcp" portid="3000"><state state="open"/>'
        '<service name="http" method="table" conf="3"/></port>'
        "</ports></host></nmaprun>"
    )
    nmap = NmapScanner("http://localhost:3000", tmp_path)
    out = nmap._parse(xml)
    # No finding — the expected-open note lives in coverage, not counts.
    assert out == []
    assert nmap.coverage["status"] == "not-applicable"
    assert "expected" in nmap.coverage["reason"]


def test_nuclei_prometheus_metrics_stays_medium(tmp_path):
    import json

    from app.models import Severity
    from app.scanners.nuclei_scanner import NucleiScanner

    jl = tmp_path / "nuclei.jsonl"
    jl.write_text(json.dumps({
        "template-id": "prometheus-metrics",
        "info": {"name": "Prometheus Metrics - Detect", "severity": "medium"},
        "matched-at": "http://localhost:3000/metrics",
    }) + "\n")
    out = NucleiScanner("http://localhost:3000", tmp_path)._parse(jl)
    assert len(out) == 1
    # /metrics exposes internals — kept at medium, not tuned down.
    assert out[0].severity == Severity.medium
    assert out[0].raw.get("severity_tuned_from") is None
