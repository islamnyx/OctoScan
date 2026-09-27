"""Tests for the Phase 7 API/backend stage — traffic parsing, role diff,
redaction, ZAP + mitmproxy runners, API stage orchestration, API agent.

All external services are mocked (httpx.MockTransport, stub runners,
mock LLM). No live ZAP daemon, proxy, or network is touched.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
from urllib.parse import urlparse

import pytest

from scan_toolkit.agents.api_agent import APIBackendAgent, validate_api_output
from scan_toolkit.agents.redact import REDACTED, redact_dict, redact_text
from scan_toolkit.api_traffic import (
    compare_roles,
    load_role_captures,
    parse_har,
    passive_checks,
    access_matrix,
)
from scan_toolkit.intermediate import IRFinding, IRToolOutput, StageIR
from scan_toolkit.models import Finding, Severity, SourceAgent
from scan_toolkit.normalize import zap_findings
from scan_toolkit.tools.mitmproxy import MitmRunner
from scan_toolkit.tools.zap import ZAPRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(method, url, status=200, query=None, req_headers=None, resp_body="{}"):
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
            "queryString": [{"name": k, "value": v} for k, v in (query or {}).items()],
        },
        "response": {
            "status": status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"text": resp_body},
        },
    }


def _har(*entries):
    return {"log": {"entries": list(entries)}}


@pytest.fixture()
def api_env(tmp_path, monkeypatch):
    """Temp data dir (settings mutated in place, restored after)."""
    from scan_toolkit.config import get_settings
    s = get_settings()
    orig = s.data_dir
    s.data_dir = tmp_path / "data"
    yield tmp_path
    s.data_dir = orig
    get_settings.cache_clear()


def _engagement_with_creds(db_session, tmp_path, creds):
    from scan_toolkit import engagements
    from scan_toolkit.models import Platform

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk")
    creds_file = tmp_path / "creds.json"
    creds_file.write_text(json.dumps(creds))
    return engagements.create_engagement(
        db_session,
        client_name="Acme",
        app_platform=Platform.android,
        scope_agreement_confirmed=True,
        binary_source=apk,
        credentials_source=creds_file,
    )


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

class TestRedact:
    def test_bearer_header(self):
        out = redact_text("authorization: Bearer abcdef12345")
        assert "abcdef12345" not in out
        assert REDACTED in out
        assert "bearer" in out.lower()  # scheme label kept for triage

    def test_password_assignment(self):
        out = redact_text('{"password": "hunter2", "user": "bob"}')
        assert "hunter2" not in out
        assert '"bob"' in out  # non-secret values untouched

    def test_email(self):
        out = redact_text("login as alice@example.com failed")
        assert "alice@example.com" not in out
        assert REDACTED in out

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert redact_text(f"token {jwt}") == f"token {REDACTED}"

    def test_query_param(self):
        out = redact_text("GET /api/u?sessionid=abc123& verbose=1")
        assert "abc123" not in out
        assert "verbose=1" in out

    def test_clean_text_untouched(self):
        text = "GET /api/v1/users status=200 no secrets here"
        assert redact_text(text) == text

    def test_none_safe(self):
        assert redact_text(None) is None

    def test_redact_dict_deep(self):
        obj = {"a": {"b": "password=hunter2"}, "c": [{"d": "x@y.zz"}]}
        scrubbed = redact_dict(obj)
        assert "hunter2" not in json.dumps(scrubbed)
        assert "x@y.zz" not in json.dumps(scrubbed)
        # original untouched
        assert "hunter2" in obj["a"]["b"]


# ---------------------------------------------------------------------------
# HAR parsing
# ---------------------------------------------------------------------------

class TestParseHar:
    def test_basic(self):
        calls = parse_har(_har(
            _entry("GET", "https://api.example.com/v1/users?page=2",
                   query={"page": "2"},
                   req_headers={"Authorization": "Bearer tok"},
                   resp_body='{"users": []}'),
        ), role="user")
        assert len(calls) == 1
        c = calls[0]
        assert c.method == "GET"
        assert c.path == "/v1/users"
        assert c.query == {"page": "2"}
        assert c.req_headers["authorization"] == "Bearer tok"  # raw here; redacted later
        assert c.status == 200
        assert c.ok
        assert c.role == "user"
        assert c.endpoint_key == "GET /v1/users"

    def test_id_normalisation(self):
        calls = parse_har(_har(
            _entry("GET", "https://h/api/users/12345"),
            _entry("GET", "https://h/api/users/550e8400-e29b-41d4-a716-446655440000"),
        ))
        assert calls[0].endpoint_key == "GET /api/users/{id}"
        assert calls[1].endpoint_key == "GET /api/users/{id}"

    def test_bad_shape_raises(self):
        with pytest.raises(ValueError):
            parse_har({"no": "log"})
        with pytest.raises(ValueError):
            parse_har({"log": {"entries": "nope"}})

    def test_body_truncation(self):
        calls = parse_har(_har(_entry("POST", "https://h/x", resp_body="y" * 5000)))
        assert len(calls[0].resp_body) == 2000

    def test_load_role_captures(self, tmp_path):
        flows = tmp_path / "flows"
        flows.mkdir()
        (flows / "user.har").write_text(json.dumps(_har(
            _entry("GET", "https://h/api/me"))))
        (flows / "admin.har").write_text(json.dumps(_har(
            _entry("GET", "https://h/api/admin"))))
        captures = load_role_captures(flows)
        assert set(captures) == {"user", "admin"}
        assert captures["user"][0].role == "user"

    def test_load_missing_dir_empty(self, tmp_path):
        assert load_role_captures(tmp_path / "nope") == {}

    def test_load_bad_json_raises(self, tmp_path):
        flows = tmp_path / "flows"
        flows.mkdir()
        (flows / "user.har").write_text("{not json")
        with pytest.raises(ValueError, match="not valid JSON"):
            load_role_captures(flows)


# ---------------------------------------------------------------------------
# Passive checks
# ---------------------------------------------------------------------------

class TestPassiveChecks:
    def test_cleartext_flagged(self):
        calls = parse_har(_har(_entry("POST", "http://api.example.com/login")), role="user")
        findings = passive_checks(calls)
        assert len(findings) == 1
        assert findings[0].rule_id == "cleartext-http"
        assert findings[0].severity == "medium"
        assert findings[0].confidence == "high"

    def test_https_clean(self):
        calls = parse_har(_har(_entry("GET", "https://api.example.com/v1/ping")))
        assert passive_checks(calls) == []

    def test_secret_in_query(self):
        calls = parse_har(_har(_entry(
            "GET", "https://h/api/u?auth_token=sekret",
            query={"auth_token": "sekret"})), role="user")
        findings = passive_checks(calls)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "secret-in-query"
        assert f.severity == "high"
        assert f.cwe_id == "CWE-598"

    def test_dedupes_per_endpoint(self):
        calls = parse_har(_har(
            _entry("GET", "http://h/api/a"),
            _entry("GET", "http://h/api/a"),
        ))
        assert len(passive_checks(calls)) == 1


# ---------------------------------------------------------------------------
# Role diff
# ---------------------------------------------------------------------------

def _calls_for(role, *specs):
    """specs: (method, url, status, body)."""
    return parse_har(_har(*[
        _entry(m, u, status=s, resp_body=b) for m, u, s, b in specs
    ]), role=role)


class TestCompareRoles:
    def test_anonymous_access(self):
        captures = {
            "anonymous": _calls_for("anonymous",
                ("GET", "https://h/api/profile", 200, '{"name":"x"}')),
            "user": _calls_for("user",
                ("GET", "https://h/api/profile", 200, '{"name":"x"}')),
        }
        findings = compare_roles(captures)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "anonymous-access"
        assert f.severity == "medium"
        assert f.cwe_id == "CWE-862"

    def test_shared_object_endpoint(self):
        captures = {
            "user": _calls_for("user",
                ("GET", "https://h/api/orders/123", 200, '{"total": 5}')),
            "admin": _calls_for("admin",
                ("GET", "https://h/api/orders/123", 200, '{"total": 5}')),
        }
        findings = compare_roles(captures)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "shared-object-endpoint"
        assert f.confidence == "low"  # candidate, never confirmed by a diff
        assert "CANDIDATE" in f.description

    def test_no_shared_endpoints(self):
        captures = {
            "user": _calls_for("user", ("GET", "https://h/api/me", 200, "{}")),
            "admin": _calls_for("admin", ("GET", "https://h/api/admin", 200, "{}")),
        }
        assert compare_roles(captures) == []

    def test_empty(self):
        assert compare_roles({}) == []

    def test_access_matrix(self):
        captures = {
            "user": _calls_for("user", ("GET", "https://h/api/me", 200, "{}")),
        }
        assert access_matrix(captures) == {"GET /api/me": {"user": 1}}


# ---------------------------------------------------------------------------
# ZAP normalizer + runner
# ---------------------------------------------------------------------------

ZAP_ALERTS = [
    {
        "pluginId": "40012",
        "name": "Cross Site Scripting (Reflected)",
        "risk": "High",
        "confidence": "Medium",
        "description": "XSS desc",
        "solution": "Encode output",
        "cweid": 79,
        "url": "https://target/api/search?q=1",
        "evidence": "<script>",
        "otherinfo": "",
    },
    {
        "pluginId": "10021",
        "name": "X-Content-Type-Options Missing",
        "risk": "Informational",
        "confidence": "High",
        "description": "Header missing",
        "solution": "Add header",
        "cweid": 0,
        "url": "https://target/",
    },
]


class TestZapNormalize:
    def test_maps_fields(self):
        findings = zap_findings(ZAP_ALERTS)
        assert len(findings) == 2
        f = findings[0]
        assert f.tool == "zap"
        assert f.rule_id == "40012"
        assert f.severity == "high"
        assert f.cwe_id == "CWE-79"
        assert "Cross Site Scripting" in f.title
        assert "Encode output" in f.recommendation

    def test_informational_maps_to_info(self):
        findings = zap_findings(ZAP_ALERTS)
        assert findings[1].severity == "info"
        assert findings[1].cwe_id is None  # cweid=0 means none

    def test_empty(self):
        assert zap_findings([]) == []


def _zap_transport(alerts):
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path
        if path == "/JSON/core/view/version/":
            return httpx.Response(200, json={"version": "2.14.0"})
        if path in ("/JSON/spider/action/scan/", "/JSON/ascan/action/scan/"):
            return httpx.Response(200, json={"scan": "1"})
        if path in ("/JSON/spider/view/status/", "/JSON/ascan/view/status/"):
            return httpx.Response(200, json={"status": "100"})
        if path == "/JSON/core/view/alerts/":
            return httpx.Response(200, json={"alerts": alerts})
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


class TestZAPRunner:
    def test_full_scan_with_mock(self, tmp_path):
        runner = ZAPRunner(tmp_path, transport=_zap_transport(ZAP_ALERTS))
        assert runner.available() is True
        out = runner.run("https://target")
        assert out.errors == []
        assert len(out.findings) == 2
        assert out.version == "2.14.0"
        assert Path(out.raw_path).exists()

    def test_invalid_target(self, tmp_path):
        runner = ZAPRunner(tmp_path, transport=_zap_transport([]))
        out = runner.run("not-a-url")
        assert out.findings == []
        assert "invalid target" in out.errors[0]

    def test_unreachable_daemon(self, tmp_path):
        import httpx
        runner = ZAPRunner(
            tmp_path,
            transport=httpx.MockTransport(
                lambda request: (_ for _ in ()).throw(
                    httpx.ConnectError("refused"))
            ),
        )
        assert runner.available() is False
        out = runner.run("https://target")
        assert "zap request failed" in out.errors[0]


# ---------------------------------------------------------------------------
# MitmRunner
# ---------------------------------------------------------------------------

class TestMitmRunner:
    def test_run_single_har(self, tmp_path):
        har_path = tmp_path / "user.har"
        har_path.write_text(json.dumps(_har(
            _entry("POST", "http://h/api/login"))))
        runner = MitmRunner(tmp_path)
        out = runner.run(har_path)
        assert out.errors == []
        assert len(out.findings) == 1
        assert out.findings[0].tool == "mitmproxy"

    def test_run_missing_file(self, tmp_path):
        out = MitmRunner(tmp_path).run(tmp_path / "nope.har")
        assert "not found" in out.errors[0]

    def test_run_all(self, tmp_path):
        flows = tmp_path / "flows"
        flows.mkdir()
        (flows / "user.har").write_text(json.dumps(_har(
            _entry("GET", "https://h/api/me"))))
        out = MitmRunner(tmp_path).run_all(flows)
        assert out.errors == []

    def test_run_all_empty(self, tmp_path):
        flows = tmp_path / "flows"
        flows.mkdir()
        out = MitmRunner(tmp_path).run_all(flows)
        assert "no .har captures" in out.errors[0]


# ---------------------------------------------------------------------------
# Test accounts
# ---------------------------------------------------------------------------

class TestLoadAccounts:
    def test_object_shape(self, db_session, api_env, tmp_path):
        eng = _engagement_with_creds(db_session, tmp_path, {
            "accounts": [
                {"role": "user", "username": "u@example.com", "password": "pw1"},
                {"role": "admin", "username": "a", "password": "pw2",
                 "extra_field": "kept"},
            ]
        })
        from scan_toolkit.engagements import load_test_accounts
        accounts = load_test_accounts(eng)
        assert [a.role for a in accounts] == ["user", "admin"]
        assert accounts[0].password == "pw1"  # secret available to the stage
        assert accounts[1].extra == {"extra_field": "kept"}

    def test_bare_list_shape(self, db_session, api_env, tmp_path):
        eng = _engagement_with_creds(db_session, tmp_path, [
            {"role": "user", "token": "tok123"},
        ])
        from scan_toolkit.engagements import load_test_accounts
        accounts = load_test_accounts(eng)
        assert len(accounts) == 1 and accounts[0].token == "tok123"

    def test_no_credentials_empty(self, db_session, api_env, tmp_path):
        from scan_toolkit import engagements
        from scan_toolkit.models import Platform
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"apk")
        eng = engagements.create_engagement(
            db_session, client_name="Acme", app_platform=Platform.android,
            scope_agreement_confirmed=True, binary_source=apk)
        from scan_toolkit.engagements import load_test_accounts
        assert load_test_accounts(eng) == []

    def test_missing_role_raises(self, db_session, api_env, tmp_path):
        eng = _engagement_with_creds(db_session, tmp_path, {
            "accounts": [{"username": "nobody"}]})
        from scan_toolkit.engagements import load_test_accounts
        with pytest.raises(ValueError, match="role"):
            load_test_accounts(eng)

    def test_bad_json_raises(self, db_session, api_env, tmp_path):
        from scan_toolkit import engagements
        from scan_toolkit.models import Platform
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"apk")
        bad = tmp_path / "bad.json"
        bad.write_text("{nope")
        eng = engagements.create_engagement(
            db_session, client_name="Acme", app_platform=Platform.android,
            scope_agreement_confirmed=True, binary_source=apk,
            credentials_source=bad)
        from scan_toolkit.engagements import load_test_accounts
        with pytest.raises(ValueError, match="valid JSON"):
            load_test_accounts(eng)


# ---------------------------------------------------------------------------
# API stage
# ---------------------------------------------------------------------------

class TestAPIStage:
    def _target(self, eng):
        from scan_toolkit import artifacts
        target_file = artifacts.engagement_dir(eng.id) / "api_target.txt"
        target_file.write_text("https://api.example.com\n")
        return target_file

    def test_run_api_with_stubs(self, db_session, api_env, tmp_path):
        from scan_toolkit.stages import run_api

        eng = _engagement_with_creds(db_session, tmp_path, {
            "accounts": [{"role": "user", "username": "u", "password": "p"}]})
        self._target(eng)

        flows = tmp_path / "flows"
        flows.mkdir()
        (flows / "user.har").write_text(json.dumps(_har(
            _entry("GET", "http://h/api/me"))))
        (flows / "anonymous.har").write_text(json.dumps(_har(
            _entry("GET", "http://h/api/me"))))

        zap_stub = MagicMock()
        zap_stub.available.return_value = False

        result = run_api(db_session, eng, zap=zap_stub, flows_dir=flows)

        # mitmproxy passive + role_diff(anonymous-access) recorded
        tools = {t.tool for t in result.tools}
        assert {"mitmproxy", "role_diff"} <= tools
        zap_stub.run.assert_not_called()  # daemon down -> skipped with a note
        assert any("ZAP daemon not reachable" in n for n in result.notes)
        assert result.ir_path.exists()
        ir = json.loads(result.ir_path.read_text())
        assert ir["input"]["target"] == "https://api.example.com"
        assert ir["input"]["roles"] == ["user"]
        assert "anonymous" in ir["input"]["call_counts"]

    def test_run_api_zap_findings_flow(self, db_session, api_env, tmp_path):
        from scan_toolkit.stages import run_api

        eng = _engagement_with_creds(db_session, tmp_path, {"accounts": []})
        zap_output = IRToolOutput(
            tool="zap",
            findings=[IRFinding(tool="zap", rule_id="40012",
                                title="XSS", severity="high")],
        )
        zap_stub = MagicMock()
        zap_stub.available.return_value = True
        zap_stub.run.return_value = zap_output

        flows = tmp_path / "empty_flows"
        flows.mkdir()

        result = run_api(
            db_session, eng, zap=zap_stub,
            target_url="https://api.example.com", flows_dir=flows)

        assert result.status == "partial"  # no captures -> mitmproxy error noted
        assert sum(len(t.findings) for t in result.tools) == 1

    def test_run_api_no_target_raises(self, db_session, api_env, tmp_path):
        from scan_toolkit.stages import run_api

        eng = _engagement_with_creds(db_session, tmp_path, {"accounts": []})
        with pytest.raises(ValueError, match="no API target"):
            run_api(db_session, eng, target_url=None,
                    flows_dir=tmp_path / "flows")

    def test_run_stage_dispatches_api(self, db_session, api_env, tmp_path):
        from scan_toolkit.stages import run_stage

        eng = _engagement_with_creds(db_session, tmp_path, {"accounts": []})
        self._target(eng)
        flows = tmp_path / "flows"
        flows.mkdir()
        # Point the stage at an empty flows dir + no ZAP: real runners,
        # daemon absent -> partial/failed IR still stored, no network touched.
        import scan_toolkit.stages as stages_mod
        orig_flows = stages_mod.artifacts.engagement_dir(eng.id) / "flows"
        orig_flows.mkdir(parents=True, exist_ok=True)
        result = run_stage(db_session, eng.id, "api")
        assert result.stage == "api"
        assert result.ir_path.exists()


# ---------------------------------------------------------------------------
# API agent
# ---------------------------------------------------------------------------

VALID_API_FINDING = {
    "source_agent": "api",
    "category": "backend_vulnerability",
    "cwe_id": "CWE-79",
    "title": "Reflected XSS in /api/search",
    "description": "ZAP found reflected XSS on the search endpoint.",
    "evidence": "GET /api/search?q=<script> (role=user)",
    "severity": "high",
    "confidence": "medium",
    "affected_component": "https://api.example.com/api/search",
    "remediation_suggestion": "Context-encode all reflected input.",
    "status": "new",
    "related_finding_ids": [],
}


class TestAPIAgentValidation:
    def test_valid_output(self):
        validate_api_output({"findings": [VALID_API_FINDING]})

    def test_wrong_source_agent(self):
        bad = {**VALID_API_FINDING, "source_agent": "static"}
        with pytest.raises(ValueError, match="source_agent"):
            validate_api_output({"findings": [bad]})

    def test_empty_findings_valid(self):
        validate_api_output({"findings": [], "notes": "none"})


class TestAPIAgent:
    def _ir_with_secret(self, eng_id, tmp_path):
        ir = StageIR(
            engagement_id=eng_id,
            stage="api",
            input={"target": "https://api.example.com"},
            tools=[IRToolOutput(
                tool="mitmproxy",
                findings=[IRFinding(
                    tool="mitmproxy",
                    rule_id="secret-in-query",
                    title="Token in URL",
                    severity="high",
                    evidence="GET /api/u?auth_token=SUPERSEKRET (role=user)",
                    raw={"url": "https://h/api/u?auth_token=SUPERSEKRET"},
                )],
            )],
        )
        ir_path = tmp_path / "api_ir.json"
        ir_path.write_text(ir.model_dump_json())
        return ir_path

    def test_run_persists_redacted(self, db_session, tmp_path):
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()
        ir_path = self._ir_with_secret(eng.id, tmp_path)

        leaky = {**VALID_API_FINDING,
                 "evidence": "saw auth_token=SUPERSEKRET in URL, "
                             "auth via Bearer LEAKEDTOKEN123"}
        mock_llm = MagicMock()
        mock_llm.call.return_value = {"findings": [leaky], "notes": None}

        agent = APIBackendAgent(llm=mock_llm)
        findings = agent.run(db_session, eng.id, ir_path)

        assert len(findings) == 1
        assert findings[0].source_agent == SourceAgent.api
        assert findings[0].severity == Severity.high
        stored = findings[0].evidence
        assert "SUPERSEKRET" not in stored
        assert "LEAKEDTOKEN123" not in stored
        assert REDACTED in stored

    def test_prompt_redacted_before_llm(self, db_session, tmp_path):
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()
        ir_path = self._ir_with_secret(eng.id, tmp_path)

        mock_llm = MagicMock()
        mock_llm.call.return_value = {"findings": [], "notes": None}

        agent = APIBackendAgent(llm=mock_llm)
        agent.run(db_session, eng.id, ir_path)

        user_message = mock_llm.call.call_args.kwargs["user_message"]
        assert "SUPERSEKRET" not in user_message
        assert REDACTED in user_message

    def test_zero_findings_skips_llm(self, db_session, tmp_path):
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()

        ir = StageIR(engagement_id=eng.id, stage="api",
                     tools=[IRToolOutput(tool="zap")])
        ir_path = tmp_path / "api_ir.json"
        ir_path.write_text(ir.model_dump_json())

        mock_llm = MagicMock()
        agent = APIBackendAgent(llm=mock_llm)
        assert agent.run(db_session, eng.id, ir_path) == []
        mock_llm.call.assert_not_called()


# ---------------------------------------------------------------------------
# Queue: analyze flag runs the API agent after the stage
# ---------------------------------------------------------------------------

class TestQueueAnalyze:
    def test_execute_job_runs_api_agent(self, api_env, tmp_path, monkeypatch):
        from sqlalchemy.pool import StaticPool

        import scan_toolkit.models  # noqa: F401
        import scan_toolkit.queue as queue_mod
        from scan_toolkit import engagements
        from scan_toolkit.db import Base, create_engine, session_factory, session_scope
        from scan_toolkit.models import Platform
        from scan_toolkit.queue import JobQueue

        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)

        with session_scope(engine) as session:
            apk = tmp_path / "app.apk"
            apk.write_bytes(b"apk")
            eng = engagements.create_engagement(
                session, client_name="Acme", app_platform=Platform.android,
                scope_agreement_confirmed=True, binary_source=apk)
            from scan_toolkit import artifacts
            (artifacts.engagement_dir(eng.id) / "api_target.txt").write_text(
                "https://api.example.com")
            queue = JobQueue(engine)
            job = queue.submit(session, engagement_id=eng.id, stage="api",
                               analyze=True)
            job_id, eng_id = job.id, eng.id

        fake_agent = MagicMock()
        fake_agent.run.return_value = []
        # Patch the agent class where _execute_job imports it from.
        import scan_toolkit.agents as agents_pkg
        monkeypatch.setattr(agents_pkg, "APIBackendAgent",
                            lambda: fake_agent)
        # Real run_api would need ZAP/captures — stub run_stage instead.
        import scan_toolkit.queue as q
        real_run_stage = __import__("scan_toolkit.stages", fromlist=["run_stage"])
        monkeypatch.setattr(real_run_stage, "run_stage",
                            lambda session, eid, stage: MagicMock(
                                summary_line=lambda: "[api] fake",
                                ir_path=tmp_path / "api_ir.json"))

        q._execute_job(engine, job_id)

        fake_agent.run.assert_called_once()
        # _execute_job stores the summary; status flips to completed in the
        # _run_job/process_pending_sync wrappers around it.
        with session_scope(engine) as session:
            job = queue.get_job(session, job_id)
            assert "API agent" in (job.result_summary or "")
