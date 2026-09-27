"""Tests for the Phase 8 dynamic stage — Frida scripts, runners, emulator
observations, dynamic stage orchestration, dynamic agent.

No emulator, ADB, or Frida exists in CI — live-device paths are tested via
stubs and fake binaries; the degradation paths (binaries missing) are
tested for real.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scan_toolkit.agents.dynamic import DynamicAnalysisAgent, validate_dynamic_output
from scan_toolkit.agents.redact import REDACTED
from scan_toolkit.intermediate import IRFinding, IRToolOutput, StageIR
from scan_toolkit.models import Finding, Severity, SourceAgent
from scan_toolkit.normalize import (
    frida_findings,
    logcat_findings,
    manifest_exported_findings,
)
from scan_toolkit.tools.emulator import (
    EmulatorRunner,
    extract_exported_components,
    scan_logcat_text,
)
from scan_toolkit.tools.frida import FridaRunner, _parse_frida_stdout


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def dyn_env(tmp_path, monkeypatch):
    """Temp data dir (settings mutated in place, restored after)."""
    from scan_toolkit.config import get_settings
    s = get_settings()
    orig = s.data_dir
    s.data_dir = tmp_path / "data"
    yield tmp_path
    s.data_dir = orig
    get_settings.cache_clear()


def _engagement(db_session, tmp_path):
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


MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
  <application>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter>
    </activity>
    <activity android:name=".SecretActivity" android:exported="false" />
    <service android:name=".SyncService" android:exported="true"
        android:permission="com.example.app.SYNC" />
    <receiver android:name=".BootReceiver">
      <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED" /></intent-filter>
    </receiver>
    <provider android:name=".DataProvider" android:exported="false"
        android:authorities="com.example.app.data" />
  </application>
</manifest>
"""


# ---------------------------------------------------------------------------
# Bundled Frida scripts
# ---------------------------------------------------------------------------

EXPECTED_SCRIPTS = [
    "insecure-storage.js",
    "weak-crypto.js",
    "ssl-validation.js",
    "anti-debug-root.js",
]


class TestFridaScripts:
    def test_all_present(self):
        from scan_toolkit.config import get_settings
        scripts_dir = get_settings().frida_scripts_dir
        for name in EXPECTED_SCRIPTS:
            assert (scripts_dir / name).exists(), f"missing {name}"

    def test_scripts_use_send_json(self):
        from scan_toolkit.config import get_settings
        scripts_dir = get_settings().frida_scripts_dir
        for name in EXPECTED_SCRIPTS:
            text = (scripts_dir / name).read_text()
            assert "send(JSON.stringify" in text, f"{name} emits non-JSON?"
            assert "Java.perform" in text, f"{name} has no Java.perform?"

    def test_expected_hooks(self):
        from scan_toolkit.config import get_settings
        d = get_settings().frida_scripts_dir
        assert "SharedPreferences$Editor" in (d / "insecure-storage.js").read_text()
        assert "MessageDigest" in (d / "weak-crypto.js").read_text()
        assert "X509TrustManager" in (d / "ssl-validation.js").read_text()
        assert "isDebuggerConnected" in (d / "anti-debug-root.js").read_text()


# ---------------------------------------------------------------------------
# Frida stdout parsing
# ---------------------------------------------------------------------------

class TestParseFridaStdout:
    def test_new_style_bare_json(self):
        events, errs = _parse_frida_stdout(
            '{"script": "weak-crypto", "event": "weak-cipher"}\n')
        assert len(events) == 1 and errs == []

    def test_old_style_wrapped_dict(self):
        events, _ = _parse_frida_stdout(
            '{"type": "send", "payload": {"script": "x", "event": "weak-hash"}}')
        assert events[0]["event"] == "weak-hash"

    def test_old_style_wrapped_string(self):
        inner = json.dumps({"script": "x", "event": "weak-hash"})
        events, _ = _parse_frida_stdout(
            json.dumps({"type": "send", "payload": inner}))
        assert events[0]["event"] == "weak-hash"

    def test_chatter_ignored(self):
        events, errs = _parse_frida_stdout(
            "Frida 16.x blabla\nSpan  blah\n[object Object]\n")
        assert events == [] and errs == []

    def test_hook_error_split(self):
        events, errs = _parse_frida_stdout(
            '{"script": "x", "event": "hook-error", "hook": "Cipher", "error": "boom"}')
        assert events == [] and len(errs) == 1 and "Cipher" in errs[0]


# ---------------------------------------------------------------------------
# Frida normalizer
# ---------------------------------------------------------------------------

class TestFridaFindings:
    def test_weak_cipher_high(self):
        (f,) = frida_findings([{"script": "s", "event": "weak-cipher",
                                "transformation": "DES/ECB/PKCS5Padding"}])
        assert f.severity == "high" and f.cwe_id == "CWE-327"
        assert f.confidence == "high"  # observed, not inferred

    def test_weak_hash_medium(self):
        (f,) = frida_findings([{"script": "s", "event": "weak-hash",
                                "algorithm": "MD5"}])
        assert f.severity == "medium"

    def test_sensitive_pref_high(self):
        (f,) = frida_findings([{"script": "s", "event": "shared-prefs-write",
                                "key": "auth_token"}])
        assert f.severity == "high" and f.cwe_id == "CWE-312"

    def test_plain_pref_low(self):
        (f,) = frida_findings([{"script": "s", "event": "shared-prefs-write",
                                "key": "ui_theme"}])
        assert f.severity == "low"

    def test_webview_proceed_high(self):
        (f,) = frida_findings([{"script": "s", "event": "webview-ssl-proceed"}])
        assert f.severity == "high" and f.cwe_id == "CWE-297"

    def test_test_keys_low(self):
        (f,) = frida_findings([{"script": "s", "event": "build-tags",
                                "tags": "test-keys"}])
        assert f.severity == "low"

    def test_release_build_no_finding(self):
        assert frida_findings([{"script": "s", "event": "build-tags",
                                "tags": "release-keys"}]) == []

    def test_hostname_reject_no_finding(self):
        assert frida_findings([{"script": "s", "event": "hostname-verify",
                                "result": False}]) == []

    def test_unknown_event_skipped(self):
        assert frida_findings([{"script": "s", "event": "hash-use",
                                "algorithm": "SHA-256"}]) == []


# ---------------------------------------------------------------------------
# Manifest extraction + mapping
# ---------------------------------------------------------------------------

class TestManifest:
    def test_extract(self, tmp_path):
        manifest = tmp_path / "AndroidManifest.xml"
        manifest.write_text(MANIFEST_XML)
        comps = extract_exported_components(manifest)
        by_name = {c["name"]: c for c in comps}
        assert by_name[".MainActivity"]["exported"] is True
        assert by_name[".SecretActivity"]["exported"] is False
        assert by_name[".SyncService"]["permission"] == "com.example.app.SYNC"
        # No android:exported + intent-filter => exported (pre-12 rule).
        assert by_name[".BootReceiver"]["exported"] is True
        assert by_name[".DataProvider"]["exported"] is False

    def test_bad_xml_raises(self, tmp_path):
        manifest = tmp_path / "AndroidManifest.xml"
        manifest.write_text("<manifest><unclosed>")
        with pytest.raises(ValueError, match="not valid XML"):
            extract_exported_components(manifest)

    def test_mapping(self, tmp_path):
        manifest = tmp_path / "AndroidManifest.xml"
        manifest.write_text(MANIFEST_XML)
        findings = manifest_exported_findings(extract_exported_components(manifest))
        by_title = {f.title: f for f in findings}
        assert any("without permission" in t and f.severity == "medium"
                   for t, f in by_title.items())
        assert any("permission-guarded" in t and f.severity == "info"
                   for t, f in by_title.items())
        assert all(f.cwe_id == "CWE-926" for f in findings)
        # .SecretActivity / .DataProvider produce nothing.
        assert not any("SecretActivity" in t for t in by_title)


# ---------------------------------------------------------------------------
# Logcat scan + mapping
# ---------------------------------------------------------------------------

LOGCAT = """01-01 10:00:00.000  1234  app I Fetching http://api.example.com/v1/feed
01-01 10:00:01.000  1234  app D login password=s3cr3t for user bob
01-01 10:00:02.000  1234  app D proxy 127.0.0.1:8080 http://localhost/x ok
"""


class TestLogcat:
    def test_scan(self):
        hits = scan_logcat_text(LOGCAT)
        kinds = {h["kind"] for h in hits}
        assert kinds == {"cleartext-url", "credential-in-log"}

    def test_loopback_skipped(self):
        hits = scan_logcat_text("01-01 1 2 x I GET http://localhost/health")
        assert hits == []

    def test_mapping(self):
        findings = logcat_findings(scan_logcat_text(LOGCAT))
        assert {f.severity for f in findings} == {"medium", "high"}
        assert any(f.cwe_id == "CWE-532" for f in findings)


# ---------------------------------------------------------------------------
# FridaRunner
# ---------------------------------------------------------------------------

def _fake_frida_script(tmp_path: Path) -> Path:
    script = tmp_path / "fake-frida"
    script.write_text(
        "#!/bin/sh\n"
        "echo 'frida banner chatter (ignored)'\n"
        "echo '{\"script\": \"weak-crypto\", \"event\": \"weak-cipher\", "
        "\"transformation\": \"DES/ECB/PKCS5Padding\"}'\n"
        "echo '{\"script\": \"x\", \"event\": \"hook-error\", "
        "\"hook\": \"Cipher\", \"error\": \"boom\"}'\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


class TestFridaRunner:
    def test_unavailable(self, tmp_path, monkeypatch):
        from scan_toolkit.config import get_settings
        monkeypatch.setattr(get_settings(), "frida_bin", "/nonexistent/frida")
        runner = FridaRunner(tmp_path)
        assert runner.available() is False
        out = runner.run("com.example.app")
        assert any("frida-tools" in e for e in out.errors)

    def test_run_with_fake_binary(self, tmp_path, monkeypatch):
        from scan_toolkit.config import get_settings
        fake = _fake_frida_script(tmp_path)
        monkeypatch.setattr(get_settings(), "frida_bin", str(fake))
        probe = tmp_path / "probe.js"
        probe.write_text("// probe")
        runner = FridaRunner(tmp_path / "work")
        out = runner.run("com.example.app", device="emulator-5554",
                         scripts=[probe])
        assert len(out.findings) == 1
        assert out.findings[0].rule_id == "weak-cipher"
        assert any("Cipher" in e for e in out.errors)  # hook-error surfaced
        assert Path(out.raw_path).exists()

    def test_no_package(self, tmp_path, monkeypatch):
        from scan_toolkit.config import get_settings
        monkeypatch.setattr(get_settings(), "frida_bin", str(_fake_frida_script(tmp_path)))
        out = FridaRunner(tmp_path).run("  ")
        assert "package" in out.errors[0]


# ---------------------------------------------------------------------------
# EmulatorRunner (no device here — degradation paths only)
# ---------------------------------------------------------------------------

class TestEmulatorRunner:
    def test_missing_binaries_reported(self, tmp_path, monkeypatch):
        from scan_toolkit.config import get_settings
        monkeypatch.setattr(get_settings(), "emulator_bin", "/nonexistent/emulator")
        monkeypatch.setattr(get_settings(), "adb_bin", "/nonexistent/adb")
        runner = EmulatorRunner(tmp_path)
        assert runner.available() is False
        assert len(runner.missing_binaries()) == 2
        out = runner.run(tmp_path / "app.apk", "com.example.app")
        assert any("Install the Android SDK" in e for e in out.errors)
        assert out.findings == []

    def test_boot_raises_helpfully(self, tmp_path, monkeypatch):
        from scan_toolkit.config import get_settings
        monkeypatch.setattr(get_settings(), "emulator_bin", "/nonexistent/emulator")
        with pytest.raises(RuntimeError, match="emulator/ADB unavailable"):
            EmulatorRunner(tmp_path).boot()


# ---------------------------------------------------------------------------
# Dynamic stage
# ---------------------------------------------------------------------------

class TestDynamicStage:
    def test_run_with_stubs(self, db_session, dyn_env, tmp_path):
        from scan_toolkit.stages import run_dynamic

        eng = _engagement(db_session, tmp_path)

        emu_stub = MagicMock()
        emu_stub.boot.return_value = "emulator-5554"
        emu_stub.observe.return_value = IRToolOutput(
            tool="emulator",
            findings=[IRFinding(tool="emulator", rule_id="exported-no-permission",
                                title="Exported activity", severity="medium")],
        )
        frida_stub = MagicMock()
        frida_stub.run.return_value = IRToolOutput(
            tool="frida",
            findings=[IRFinding(tool="frida", rule_id="weak-cipher",
                                title="DES", severity="high")],
        )
        frida_stub.scripts.return_value = [Path("weak-crypto.js")]
        frida_stub.available.return_value = True

        result = run_dynamic(db_session, eng, emulator=emu_stub,
                             frida=frida_stub, package_name="com.example.app")

        assert result.status == "completed"
        assert sum(len(t.findings) for t in result.tools) == 2
        frida_stub.run.assert_called_once_with("com.example.app",
                                               device="emulator-5554")
        emu_stub.teardown.assert_called_once()
        ir = json.loads(result.ir_path.read_text())
        assert ir["input"]["package"] == "com.example.app"

    def test_package_from_static_manifest(self, db_session, dyn_env, tmp_path):
        from scan_toolkit import artifacts
        from scan_toolkit.stages import run_dynamic

        eng = _engagement(db_session, tmp_path)
        manifest_dir = (artifacts.engagement_dir(eng.id) / "stages" / "static"
                        / "tools" / "apktool" / "decoded")
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "AndroidManifest.xml").write_text(MANIFEST_XML)

        emu_stub = MagicMock()
        emu_stub.boot.return_value = "emulator-5554"
        emu_stub.observe.return_value = IRToolOutput(tool="emulator")
        frida_stub = MagicMock()
        frida_stub.run.return_value = IRToolOutput(tool="frida")
        frida_stub.scripts.return_value = []
        frida_stub.available.return_value = True

        result = run_dynamic(db_session, eng, emulator=emu_stub,
                             frida=frida_stub)
        frida_stub.run.assert_called_once_with("com.example.app",
                                               device="emulator-5554")
        assert result.status == "completed"

    def test_no_emulator_degrades(self, db_session, dyn_env, tmp_path):
        from scan_toolkit.stages import run_dynamic

        eng = _engagement(db_session, tmp_path)

        emu_stub = MagicMock()
        emu_stub.boot.side_effect = RuntimeError("emulator/ADB unavailable: missing adb")
        frida_stub = MagicMock()
        frida_stub.available.return_value = False

        result = run_dynamic(db_session, eng, emulator=emu_stub,
                             frida=frida_stub, package_name="com.example.app")

        assert result.status in ("partial", "failed")
        assert any("emulator" in e.lower() for e in result.errors)
        frida_stub.run.assert_not_called()
        assert result.ir_path.exists()

    def test_run_stage_dispatches_dynamic(self, db_session, dyn_env, tmp_path):
        from scan_toolkit.stages import run_stage

        eng = _engagement(db_session, tmp_path)
        # Real runners, no SDK here -> informative failure, no crash.
        result = run_stage(db_session, eng.id, "dynamic")
        assert result.stage == "dynamic"
        assert result.ir_path.exists()


# ---------------------------------------------------------------------------
# Dynamic agent
# ---------------------------------------------------------------------------

VALID_DYNAMIC_FINDING = {
    "source_agent": "dynamic",
    "category": "weak_cryptography",
    "cwe_id": "CWE-327",
    "title": "DES/ECB observed at runtime",
    "description": "Cipher.getInstance(DES/ECB...) was called while instrumented.",
    "evidence": "Cipher.getInstance(DES/ECB/PKCS5Padding) observed",
    "severity": "high",
    "confidence": "high",
    "affected_component": "javax.crypto.Cipher",
    "remediation_suggestion": "Use AES/GCM.",
    "status": "new",
    "related_finding_ids": [],
}


class TestDynamicAgentValidation:
    def test_valid_output(self):
        validate_dynamic_output({"findings": [VALID_DYNAMIC_FINDING]})

    def test_wrong_source_agent(self):
        bad = {**VALID_DYNAMIC_FINDING, "source_agent": "static"}
        with pytest.raises(ValueError, match="source_agent"):
            validate_dynamic_output({"findings": [bad]})

    def test_empty_findings_valid(self):
        validate_dynamic_output({"findings": [], "notes": "none"})


class TestDynamicAgent:
    def _ir(self, eng_id, tmp_path, evidence):
        ir = StageIR(
            engagement_id=eng_id,
            stage="dynamic",
            input={"package": "com.example.app"},
            tools=[IRToolOutput(
                tool="frida",
                findings=[IRFinding(
                    tool="frida", rule_id="sqlite-write",
                    title="DB write", severity="info", evidence=evidence,
                )],
            )],
        )
        ir_path = tmp_path / "dynamic_ir.json"
        ir_path.write_text(ir.model_dump_json())
        return ir_path

    def test_run_persists_and_redacts(self, db_session, tmp_path):
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()
        ir_path = self._ir(eng.id, tmp_path, "line: password=s3cr3t tag=app")

        leaky = {**VALID_DYNAMIC_FINDING,
                 "evidence": "logcat: password=s3cr3t, user user@example.com"}
        mock_llm = MagicMock()
        mock_llm.call.return_value = {"findings": [leaky], "notes": None}

        agent = DynamicAnalysisAgent(llm=mock_llm)
        findings = agent.run(db_session, eng.id, ir_path)

        assert len(findings) == 1
        assert findings[0].source_agent == SourceAgent.dynamic
        assert findings[0].severity == Severity.high
        # confidence preserved as high (observed) — agent must not downgrade.
        assert findings[0].confidence.value == "high"
        assert "s3cr3t" not in findings[0].evidence
        assert "user@example.com" not in findings[0].evidence
        assert REDACTED in findings[0].evidence

    def test_prompt_redacted_before_llm(self, db_session, tmp_path):
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()
        ir_path = self._ir(eng.id, tmp_path, "line: password=s3cr3t tag=app")

        mock_llm = MagicMock()
        mock_llm.call.return_value = {"findings": [], "notes": None}
        DynamicAnalysisAgent(llm=mock_llm).run(db_session, eng.id, ir_path)

        user_message = mock_llm.call.call_args.kwargs["user_message"]
        assert "s3cr3t" not in user_message

    def test_zero_findings_skips_llm(self, db_session, tmp_path):
        from scan_toolkit.models import Engagement, Platform

        eng = Engagement(client_name="Test", app_platform=Platform.android)
        db_session.add(eng)
        db_session.flush()

        ir = StageIR(engagement_id=eng.id, stage="dynamic",
                     tools=[IRToolOutput(tool="frida")])
        ir_path = tmp_path / "dynamic_ir.json"
        ir_path.write_text(ir.model_dump_json())

        mock_llm = MagicMock()
        assert DynamicAnalysisAgent(llm=mock_llm).run(
            db_session, eng.id, ir_path) == []
        mock_llm.call.assert_not_called()


# ---------------------------------------------------------------------------
# Queue: analyze flag runs the dynamic agent after the stage
# ---------------------------------------------------------------------------

class TestQueueAnalyzeDynamic:
    def test_execute_job_runs_dynamic_agent(self, dyn_env, tmp_path, monkeypatch):
        from sqlalchemy.pool import StaticPool

        import scan_toolkit.models  # noqa: F401
        from scan_toolkit import engagements
        from scan_toolkit.db import Base, create_engine, session_factory, session_scope
        from scan_toolkit.models import Platform
        from scan_toolkit.queue import JobQueue
        import scan_toolkit.queue as q

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
            queue = JobQueue(engine)
            job = queue.submit(session, engagement_id=eng.id,
                               stage="dynamic", analyze=True)
            job_id = job.id

        fake_agent = MagicMock()
        fake_agent.run.return_value = []
        fake_result = MagicMock(
            summary_line=lambda: "[dynamic] fake",
            ir_path=tmp_path / "dynamic_ir.json",
        )
        import scan_toolkit.agents as agents_pkg
        import scan_toolkit.stages as stages_mod
        monkeypatch.setattr(agents_pkg, "DynamicAnalysisAgent",
                            lambda: fake_agent)
        monkeypatch.setattr(stages_mod, "run_stage",
                            lambda session, eid, stage: fake_result)

        q._execute_job(engine, job_id)

        fake_agent.run.assert_called_once()
        with session_scope(engine) as session:
            job = queue.get_job(session, job_id)
            assert "Dynamic agent" in (job.result_summary or "")
