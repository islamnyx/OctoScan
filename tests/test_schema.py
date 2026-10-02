"""Scan JSON shape regression (Oct 2026).

Catches branch mix-ups like Scan 3 (CWE ids in `cve`, empty taxonomy):
the persisted/exported shape is asserted key by key, including the
no-secret-leak invariant on exports.
"""

from __future__ import annotations

from app.models import SCHEMA_VERSION, Finding, ScanJob, Severity


def _finding(**kw):
    base = dict(scanner="zap", title="SQL Injection", severity=Severity.high,
                description="d", location="http://h/s?q=x", evidence="e",
                recommendation="r", request="http://h/s?q=x",
                response="HTTP 500", cwe=["CWE-89"],
                owasp=["A03:2021-Injection"], confidence=0.95, verified=True)
    base.update(kw)
    return Finding(**base)


def test_finding_shape_has_agent_fields():
    f = _finding().model_dump(mode="json")
    for key in ("id", "scanner", "title", "severity", "description", "evidence",
                "recommendation", "location", "cve", "cvss", "cwe", "owasp",
                "request", "response", "confidence", "verified", "raw"):
        assert key in f, f"missing Finding key: {key}"
    assert isinstance(f["id"], str) and len(f["id"]) == 12
    assert 0.0 <= f["confidence"] <= 1.0
    assert f["verified"] in (True, False, None)


def test_scan_job_shape_and_version():
    job = ScanJob(target_url="http://h/", findings=[_finding()],
                  scanners_run=["zap"], coverage={"zap": {"duration_s": 1.0}},
                  gate="FAILED", schema_version=SCHEMA_VERSION)
    d = job.model_dump(mode="json")
    for key in ("id", "target_url", "status", "schema_version", "scanners_run",
                "requested_scanners", "findings", "coverage", "gate", "gate_details"):
        assert key in d, f"missing ScanJob key: {key}"
    assert d["schema_version"] == SCHEMA_VERSION
    assert d["coverage"]["zap"]["duration_s"] == 1.0


def test_old_job_without_new_keys_still_loads():
    """Pre-version files (no schema_version, no req/resp/trust fields) load."""
    job = ScanJob.model_validate({
        "target_url": "http://h/",
        "findings": [{"scanner": "zap", "title": "t", "severity": "low", "description": "d"}],
    })
    assert job.schema_version == 1
    f = job.findings[0]
    assert f.request == "" and f.response == ""
    assert f.confidence == 0.0 and f.verified is None
    assert f.cwe == [] and f.owasp == []


def test_export_shape_auth_meta_without_secret(tmp_path, monkeypatch):
    from app.config import settings
    from app.main import _auth_export_meta
    from app.models import ScanAuth
    from app.store import load_job, save_job

    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    job = ScanJob(target_url="http://127.0.0.1:9/",
                  auth=ScanAuth(headers={"Authorization": "Bearer TOPSECRETXYZ"}),
                  schema_version=SCHEMA_VERSION)
    save_job(job)
    back = load_job(job.id)
    assert back is not None and back.schema_version == SCHEMA_VERSION
    data = back.model_dump(mode="json", exclude={"auth"})
    data["auth"] = _auth_export_meta(back)
    assert data["auth"] == {"used": True, "type": "bearer"}
    blob = __import__("json").dumps(data)
    assert "TOPSECRETXYZ" not in blob
    assert "auth" in data and set(data["auth"]) == {"used", "type"}


def test_stable_ids_survive_reprioritize():
    from app.normalize import prioritize

    # Same concept (CORS, no param) merges to ONE finding with ONE id —
    # and fresh runs hash identically, so agent verdicts survive rescans.
    a = _finding(location="http://h/a", raw={"pluginid": "10098"})
    b = _finding(location="http://h/b", raw={"pluginid": "10098"})
    first = prioritize([a, b])
    assert len(first) == 1
    assert first[0].location == "http://h/"  # sitewide root
    a2 = _finding(location="http://h/a", raw={"pluginid": "10098"})
    b2 = _finding(location="http://h/b", raw={"pluginid": "10098"})
    second = prioritize([a2, b2])
    assert second[0].id == first[0].id
    # Distinct params stay distinct issues with distinct stable ids.
    c = _finding(location="http://h/a", raw={"pluginid": "90022", "param": "p1"})
    d = _finding(location="http://h/a", raw={"pluginid": "90022", "param": "p2"})
    out = prioritize([c, d])
    assert len(out) == 2
    assert out[0].id != out[1].id
