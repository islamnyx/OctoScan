"""Tests for the SCA pipeline — dependency extraction, OSV, Grype, SCA agent.

All external services/tools are mocked.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scan_toolkit.intermediate import IRFinding, IRToolOutput, StageIR
from scan_toolkit.tools.deps import Dependency, extract_dependencies, _parse_gradle
from scan_toolkit.tools.osv import OsvRunner, _osv_to_findings, _osv_severity
from scan_toolkit.tools.grype import GrypeRunner, _grype_to_findings
from scan_toolkit.agents.sca import SCAAgent, validate_sca_output
from scan_toolkit.models import Finding, Severity, SourceAgent


# ---------------------------------------------------------------------------
# Dependency extractor
# ---------------------------------------------------------------------------


class TestDependencyExtractor:
    def test_parse_gradle_implementation(self, tmp_path):
        gradle = tmp_path / "build.gradle"
        gradle.write_text("""
        dependencies {
            implementation 'com.squareup.okhttp3:okhttp:4.12.0'
            api "com.google.code.gson:gson:2.10.1"
            testImplementation 'junit:junit:4.13.2'
        }
        """)
        deps = _parse_gradle(gradle)
        assert len(deps) == 3
        names = {d.name for d in deps}
        assert "com.squareup.okhttp3:okhttp" in names
        assert "com.google.code.gson:gson" in names
        assert deps[0].version == "4.12.0"

    def test_parse_gradle_kts(self, tmp_path):
        gradle = tmp_path / "build.gradle.kts"
        gradle.write_text("""
        dependencies {
            implementation("com.squareup.retrofit2:retrofit:2.9.0")
            api("org.jetbrains.kotlin:kotlin-stdlib:1.9.0")
        }
        """)
        deps = _parse_gradle(gradle)
        assert len(deps) == 2
        assert deps[0].name == "com.squareup.retrofit2:retrofit"
        assert deps[0].version == "2.9.0"

    def test_extract_from_pom_properties(self, tmp_path):
        pom_dir = tmp_path / "META-INF" / "maven" / "com.example" / "mylib"
        pom_dir.mkdir(parents=True)
        (pom_dir / "pom.properties").write_text(
            "groupId=com.example\nartifactId=mylib\nversion=1.0.0\n"
        )
        deps = extract_dependencies(tmp_path)
        assert len(deps) == 1
        assert deps[0].name == "com.example:mylib"
        assert deps[0].version == "1.0.0"

    def test_extract_deduplicates(self, tmp_path):
        # Same dep in gradle + pom.properties
        gradle = tmp_path / "build.gradle"
        gradle.write_text("implementation 'com.example:mylib:1.0.0'")
        pom_dir = tmp_path / "META-INF" / "maven" / "com.example" / "mylib"
        pom_dir.mkdir(parents=True)
        (pom_dir / "pom.properties").write_text(
            "groupId=com.example\nartifactId=mylib\nversion=1.0.0\n"
        )
        deps = extract_dependencies(tmp_path)
        assert len(deps) == 1

    def test_extract_empty_dir(self, tmp_path):
        assert extract_dependencies(tmp_path) == []


# ---------------------------------------------------------------------------
# OSV runner
# ---------------------------------------------------------------------------

OSV_BATCH_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "summary": "RCE in okhttp via malformed headers",
                    "aliases": ["CVE-2024-12345"],
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    "database_specific": {"cwe_ids": ["CWE-94"], "severity": "CRITICAL"},
                    "affected": [
                        {
                            "ranges": [
                                {"events": [{"introduced": "0"}, {"fixed": "4.12.1"}]}
                            ]
                        }
                    ],
                }
            ]
        },
        {"vulns": []},  # second dep has no vulns
    ]
}


class TestOsvRunner:
    def test_osv_to_findings_maps_fields(self):
        deps = [
            Dependency(name="com.squareup.okhttp3:okhttp", version="4.12.0"),
            Dependency(name="com.google.code.gson:gson", version="2.10.1"),
        ]
        findings = _osv_to_findings(deps, OSV_BATCH_RESPONSE["results"])
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "osv"
        assert f.rule_id == "GHSA-xxxx-yyyy-zzzz"
        assert f.severity == "critical"
        assert f.cwe_id == "CWE-94"
        assert "okhttp" in f.title
        assert "4.12.1" in f.recommendation

    def test_osv_runner_no_deps(self, tmp_path):
        runner = OsvRunner(tmp_path)
        out = runner.run(dependencies=[])
        assert out.errors == ["no dependencies to scan"]
        assert out.findings == []

    def test_osv_severity_parsing(self):
        assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": "9.8"}]}) == "critical"
        assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": "7.5"}]}) == "high"
        assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": "4.0"}]}) == "medium"
        assert _osv_severity({"severity": [{"type": "CVSS_V3", "score": "2.0"}]}) == "low"
        assert _osv_severity({}) == "medium"  # default

    def test_osv_runner_with_mock_transport(self, tmp_path):
        """OSV runner with a mock HTTP transport."""
        import httpx

        mock_transport = httpx.MockTransport(
            lambda request: httpx.Response(200, json=OSV_BATCH_RESPONSE)
        )
        runner = OsvRunner(tmp_path, transport=mock_transport)
        deps = [
            Dependency(name="com.squareup.okhttp3:okhttp", version="4.12.0"),
            Dependency(name="com.google.code.gson:gson", version="2.10.1"),
        ]
        out = runner.run(dependencies=deps)
        assert len(out.findings) == 1
        assert out.errors == []
        assert Path(out.raw_path).exists()


# ---------------------------------------------------------------------------
# Grype runner
# ---------------------------------------------------------------------------

GRYPE_OUTPUT = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2024-99999",
                "severity": "High",
                "description": "Buffer overflow in libpng",
                "fix": {"versions": [{"version": "1.6.40"}]},
            },
            "artifact": {
                "name": "libpng",
                "version": "1.6.37",
                "type": "java-archive",
            },
            "relatedVulnerabilities": [
                {"id": "CVE-2024-99999", "cwes": ["787"]}
            ],
        }
    ],
    "descriptor": {"version": "0.73.0"},
}


class TestGrypeRunner:
    def test_grype_to_findings(self):
        findings = _grype_to_findings(GRYPE_OUTPUT)
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "grype"
        assert f.rule_id == "CVE-2024-99999"
        assert f.severity == "high"
        assert f.cwe_id == "CWE-787"
        assert "libpng" in f.title
        assert "1.6.40" in f.recommendation

    def test_grype_not_available(self, tmp_path):
        runner = GrypeRunner(tmp_path)
        out = runner.run(target_dir=tmp_path)
        assert "not available" in out.errors[0]

    def test_grype_empty_matches(self):
        findings = _grype_to_findings({"matches": []})
        assert findings == []


# ---------------------------------------------------------------------------
# SCA stage orchestration
# ---------------------------------------------------------------------------


class TestSCAStage:
    @pytest.fixture()
    def env(self, tmp_path, monkeypatch):
        from scan_toolkit.config import get_settings
        s = get_settings()
        orig = s.data_dir
        s.data_dir = tmp_path / "data"
        yield tmp_path
        s.data_dir = orig
        get_settings.cache_clear()

    def _complete_engagement(self, db_session, tmp_path):
        from scan_toolkit import engagements
        from scan_toolkit.models import Platform

        apk = tmp_path / "app.apk"
        apk.write_bytes(b"apk")
        return engagements.create_engagement(
            db_session,
            client_name="Acme",
            app_platform=Platform.android,
            scope_agreement_confirmed=True,
            binary_source=apk,
        )

    def test_run_sca_with_stubs(self, db_session, env, tmp_path):
        from scan_toolkit.stages import run_sca

        eng = self._complete_engagement(db_session, tmp_path)
        deps = [Dependency(name="com.example:lib", version="1.0.0")]

        osv_output = IRToolOutput(
            tool="osv",
            findings=[IRFinding(
                tool="osv",
                rule_id="GHSA-test",
                title="Test vuln",
                severity="high",
                confidence="high",
            )],
        )
        osv_stub = MagicMock()
        osv_stub.run.return_value = osv_output

        grype_stub = MagicMock()
        grype_stub.available.return_value = False

        result = run_sca(
            db_session, eng,
            osv=osv_stub, grype=grype_stub, deps_override=deps,
        )

        assert result.status == "completed"
        assert result.stage == "sca"
        assert sum(len(t.findings) for t in result.tools) == 1
        assert result.ir_path.exists()

    def test_run_sca_no_deps(self, db_session, env, tmp_path):
        from scan_toolkit.stages import run_sca

        eng = self._complete_engagement(db_session, tmp_path)

        osv_stub = MagicMock()
        grype_stub = MagicMock()
        grype_stub.available.return_value = False

        result = run_sca(
            db_session, eng,
            osv=osv_stub, grype=grype_stub, deps_override=[],
        )

        assert any("no dependencies" in n for n in result.notes)
        osv_stub.run.assert_not_called()


# ---------------------------------------------------------------------------
# SCA Agent validation
# ---------------------------------------------------------------------------

VALID_SCA_FINDING = {
    "source_agent": "sca",
    "category": "dependency_vulnerability",
    "cwe_id": "CWE-94",
    "title": "CVE-2024-12345: RCE in okhttp",
    "description": "Remote code execution via malformed headers in okhttp 4.12.0.",
    "evidence": "CVE-2024-12345 / GHSA-xxxx-yyyy-zzzz affecting okhttp 4.12.0",
    "severity": "critical",
    "confidence": "high",
    "affected_component": "com.squareup.okhttp3:okhttp:4.12.0",
    "remediation_suggestion": "Upgrade okhttp to 4.12.1 or later.",
    "status": "new",
    "related_finding_ids": [],
}


class TestSCAAgentValidation:
    def test_valid_output(self):
        validate_sca_output({"findings": [VALID_SCA_FINDING]})

    def test_wrong_source_agent(self):
        bad = {**VALID_SCA_FINDING, "source_agent": "static"}
        with pytest.raises(ValueError, match="source_agent"):
            validate_sca_output({"findings": [bad]})

    def test_empty_findings_valid(self):
        validate_sca_output({"findings": [], "notes": "none"})


class TestSCAAgent:
    def test_run_produces_finding_rows(self, db_session, tmp_path):
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()

        ir = StageIR(
            engagement_id=eng.id,
            stage="sca",
            tools=[IRToolOutput(
                tool="osv",
                findings=[IRFinding(
                    tool="osv", rule_id="GHSA-test",
                    title="Test vuln", severity="high", confidence="high",
                )],
            )],
        )
        ir_path = tmp_path / "sca_ir.json"
        ir_path.write_text(ir.model_dump_json())

        mock_llm = MagicMock()
        mock_llm.call.return_value = {"findings": [VALID_SCA_FINDING], "notes": None}

        agent = SCAAgent(llm=mock_llm)
        findings = agent.run(db_session, eng.id, ir_path)

        assert len(findings) == 1
        assert findings[0].source_agent == SourceAgent.sca
        assert findings[0].severity == Severity.critical

    def test_zero_findings_skips_llm(self, db_session, tmp_path):
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()

        ir = StageIR(
            engagement_id=eng.id,
            stage="sca",
            tools=[IRToolOutput(tool="osv")],
        )
        ir_path = tmp_path / "sca_ir.json"
        ir_path.write_text(ir.model_dump_json())

        mock_llm = MagicMock()
        agent = SCAAgent(llm=mock_llm)
        findings = agent.run(db_session, eng.id, ir_path)

        assert findings == []
        mock_llm.call.assert_not_called()
