"""Tests for scan_toolkit.normalize -- raw Semgrep/MobSF JSON -> IRFinding."""

from scan_toolkit.normalize import mobsf_findings, semgrep_findings

SEMGREP_FIXTURE = {
    "version": "1.90.0",
    "results": [
        {
            "check_id": "java.lang.security.audit.broken-crypto-android.double-ratchet-bugs.message-digest-weak",
            "path": "sources/com/acme/app/CryptoUtil.java",
            "start": {"line": 42, "col": 8},
            "end": {"line": 42, "col": 45},
            "extra": {
                "message": "Weak message digest \"MD5\" used. ...",
                "severity": "ERROR",
                "lines": '        MessageDigest.getInstance("MD5")',
                "metadata": {"cwe": ["CWE-327"]},
            },
        },
        {
            "check_id": "android-hardcoded-secret-token",
            "path": "sources/com/acme/app/Api.java",
            "start": {"line": 7, "col": 4},
            "end": {"line": 7, "col": 30},
            "extra": {
                "message": "A token-like literal is assigned in source.",
                "severity": "WARNING",
                "lines": '    String TOKEN = "sk-1234567890abcdef";',
                "metadata": {"cwe": ["CWE-798"]},
            },
        },
    ],
}

MOBSF_FIXTURE = {
    "app_name": "AcmeApp",
    "package_name": "com.acme.app",
    "code_analysis": [
        {
            "title": "Insecure SharedPreferences",
            "level": "high",
            "description": "Sensitive data stored in plaintext SharedPreferences.",
            "file_path": "com/acme/app/Prefs.java",
            "code": "editor.putString(\"token\", t);",
            "cwe": "CWE-312",
            "cvss": 7.5,
            "owasp": "M7",
        },
        {
            "title": "Exported Activity",
            "level": "warning",
            "description": "Activity is exported without protection.",
            "file_path": "AndroidManifest.xml",
            "cwe": "CWE-926",
        },
    ],
}


def test_semgrep_findings_maps_fields():
    ir = semgrep_findings(SEMGREP_FIXTURE)
    assert len(ir) == 2

    weak = ir[0]
    assert weak.tool == "semgrep"
    assert weak.rule_id.endswith("message-digest-weak")
    assert weak.severity == "error"
    assert weak.cwe_id == "CWE-327"
    assert weak.file.endswith("CryptoUtil.java")
    assert weak.line == 42
    assert weak.evidence == 'MessageDigest.getInstance("MD5")'
    assert weak.title.startswith("Weak message digest")
    assert weak.raw["severity_raw"] == "ERROR"


def test_semgrep_findings_empty_results():
    assert semgrep_findings({"results": []}) == []


def test_semgrep_findings_handles_missing_metadata():
    ir = semgrep_findings({"results": [{"check_id": "x", "path": "p", "start": {}, "end": {},
                                        "extra": {"severity": "INFO"}}]})
    assert ir[0].cwe_id is None
    assert ir[0].title is None


def test_mobsf_findings_maps_categories_and_severity():
    ir = mobsf_findings(MOBSF_FIXTURE)
    assert len(ir) == 2

    prefs = ir[0]
    assert prefs.tool == "mobsf"
    assert prefs.category == "code_analysis"
    assert prefs.severity == "high"
    assert prefs.cwe_id == "CWE-312"
    assert prefs.file == "com/acme/app/Prefs.java"
    assert prefs.evidence == 'editor.putString("token", t);'
    assert prefs.raw.get("owasp") == "M7"


def test_mobsf_level_warning_maps_low():
    ir = mobsf_findings(MOBSF_FIXTURE)
    exported = next(f for f in ir if f.title == "Exported Activity")
    assert exported.severity == "low"  # 'warning' -> 'low'


def test_mobsf_findings_handles_non_list_categories():
    assert mobsf_findings({"code_analysis": "not-a-list"}) == []
