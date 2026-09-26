"""Ruleset regression test — bundled Semgrep rules against a fixture file.

Runs the REAL semgrep binary when present (validates rule syntax AND
matching); skips cleanly on machines without the toolchain.  This guards
the starter ruleset that the UnCrackable pilot proved too narrow.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURE_JAVA = """\
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Vuln {
    byte[] key = new byte[16];

    void demo() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        SecretKeySpec eks = new SecretKeySpec(key, "AES/ECB/PKCS7Padding");
        Cipher c1 = Cipher.getInstance("AES");
        Cipher c2 = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
"""

EXPECTED_RULES = {
    "android-weak-message-digest",
    "android-ecb-secret-key",
    "android-aes-default-mode",
    "android-weak-cipher-transformation",
}

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep binary not installed")


@needs_semgrep
def test_bundled_rules_fire_on_fixture(tmp_path: Path):
    from scan_toolkit.tools.semgrep import SemgrepRunner

    target = tmp_path / "src"
    target.mkdir()
    (target / "Vuln.java").write_text(FIXTURE_JAVA)

    out = SemgrepRunner(tmp_path / "work").run(target_dir=target)
    assert out.errors == [], f"semgrep errors: {out.errors}"
    rule_ids = {f.rule_id.split(".")[-1] for f in out.findings}
    assert EXPECTED_RULES <= rule_ids, f"missing: {EXPECTED_RULES - rule_ids}"
