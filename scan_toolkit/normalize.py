"""Normalizers — raw tool output -> common intermediate JSON shape.

Each function is pure and unit-testable with fixture JSON. The LLM agents in
later phases consume this normalized shape, never the raw tool dumps.
"""

from __future__ import annotations

import re
from typing import Any

from scan_toolkit.intermediate import IRFinding


# ---------------------------------------------------------------------------
# Shared secret-key hint (storage keys that suggest sensitive content)
# ---------------------------------------------------------------------------

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(token|secret|password|passwd|auth|session|credential|pin|ssn|card)"
)


# ---------------------------------------------------------------------------
# Semgrep (--json output)
# ---------------------------------------------------------------------------


def semgrep_findings(raw: dict[str, Any]) -> list[IRFinding]:
    """Map ``semgrep --json`` output results to IRFinding entries."""
    out: list[IRFinding] = []
    for res in raw.get("results") or []:
        extra = res.get("extra") or {}
        metadata = extra.get("metadata") or {}
        cwes = metadata.get("cwe") or []
        cwe = str(cwes[0]) if cwes else None
        start = res.get("start") or {}
        end = res.get("end") or {}
        severity = str(extra.get("severity") or "").upper()
        msg = (extra.get("message") or "").strip()
        first_line = msg.splitlines() if msg else []
        out.append(
            IRFinding(
                tool="semgrep",
                rule_id=res.get("check_id"),
                category=None,
                title=first_line[0][:200] if first_line else None,
                severity=severity.lower() or None,
                confidence=None,
                cwe_id=cwe,
                file=res.get("path"),
                line=start.get("line"),
                end_line=end.get("line"),
                description=extra.get("message"),
                evidence=(extra.get("lines") or "").strip() or None,
                recommendation=None,
                raw={
                    "check_id": res.get("check_id"),
                    "severity_raw": severity,
                    "start_col": start.get("col"),
                    "end_col": end.get("col"),
                },
            )
        )
    return out


# ---------------------------------------------------------------------------
# ZAP (alerts JSON from /JSON/core/view/alerts/)
# ---------------------------------------------------------------------------

_ZAP_RISK_TO_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def zap_findings(alerts: list[dict[str, Any]]) -> list[IRFinding]:
    """Map ZAP alert dicts to IRFinding entries.

    ZAP alert fields used: name/risk/confidence/description/solution/cweid/
    url/evidence/otherinfo. ``cweid`` is numeric — prefixed to ``CWE-N``.
    Unknown risk levels fall back to ``medium`` (conservative, not alarming).
    """
    out: list[IRFinding] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        risk = str(alert.get("risk") or "").lower()
        cweid = alert.get("cweid")
        cwe = None
        if cweid not in (None, "", 0, "0", -1, "-1"):
            cwe = f"CWE-{cweid}" if not str(cweid).startswith("CWE-") else str(cweid)
        name = str(alert.get("name") or "ZAP alert").strip()[:200]
        url = str(alert.get("url") or "")
        out.append(
            IRFinding(
                tool="zap",
                rule_id=str(alert.get("pluginId") or alert.get("pluginid") or "")
                or None,
                category="backend_vulnerability",
                title=name or None,
                severity=_ZAP_RISK_TO_SEVERITY.get(risk, "medium"),
                confidence=str(alert.get("confidence") or "").lower() or None,
                cwe_id=cwe,
                file=url or None,
                description=str(alert.get("description") or "") or None,
                evidence=str(alert.get("evidence") or url or "")[:2000] or None,
                recommendation=str(alert.get("solution") or "") or None,
                raw={
                    "risk": alert.get("risk"),
                    "confidence_raw": alert.get("confidence"),
                    "otherinfo": alert.get("otherinfo"),
                },
            )
        )
    return out


# ---------------------------------------------------------------------------
# Frida runtime events (dicts emitted by scan_toolkit/frida_scripts/*.js)
# ---------------------------------------------------------------------------

def frida_findings(events: list[dict[str, Any]]) -> list[IRFinding]:
    """Map Frida script events to IRFinding entries.

    Dynamic findings carry high confidence — the behaviour was OBSERVED at
    runtime, not pattern-matched.  ``hook-error`` events are NOT findings;
    the Frida runner surfaces those as tool errors.
    """
    out: list[IRFinding] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        kind = ev.get("event")
        handler = _FRIDA_HANDLERS.get(kind)
        if handler is None:
            continue  # unknown/observation-only event (hash-use, file-write...)
        finding = handler(ev)
        if finding is not None:
            out.append(finding)
    return out


def _frida_base(ev: dict, *, rule_id: str, category: str) -> dict:
    return {
        "tool": "frida",
        "rule_id": rule_id,
        "category": category,
        "confidence": "high",  # observed at runtime
        "raw": {"script": ev.get("script"), "event": ev.get("event")},
    }


def _ev_shared_prefs(ev: dict) -> IRFinding | None:
    key = str(ev.get("key", ""))
    sensitive = bool(_SENSITIVE_KEY_RE.search(key))
    return IRFinding(
        **_frida_base(ev, rule_id="plaintext-shared-prefs",
                      category="insecure_storage"),
        title=(
            f"Sensitive value in plaintext SharedPreferences: {key[:80]}"
            if sensitive else
            f"Plaintext SharedPreferences write: {key[:80]} (review contents)"
        ),
        severity="high" if sensitive else "low",
        cwe_id="CWE-312",
        description=(
            f"The app wrote key {key!r} to SharedPreferences without "
            "encryption (observed at runtime). "
            + ("The key name suggests sensitive content — verify what is "
               "stored and move it to EncryptedSharedPreferences. "
               if sensitive else
               "Confirm the stored value is non-sensitive; otherwise move "
               "it to EncryptedSharedPreferences. ")
        ),
        evidence=f"SharedPreferences.Editor.putString({key!r}, …) observed",
        recommendation="Use EncryptedSharedPreferences for any sensitive values.",
    )


def _ev_world_file(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="world-accessible-file",
                      category="insecure_storage"),
        title=f"World-accessible file created: {ev.get('name')}",
        severity="high",
        cwe_id="CWE-276",
        description=(
            f"openFileOutput({ev.get('name')!r}, mode={ev.get('mode')}) — "
            "MODE_WORLD_READABLE/WRITEABLE exposes the file to other apps."
        ),
        evidence=f"openFileOutput name={ev.get('name')} mode={ev.get('mode')}",
        recommendation="Use MODE_PRIVATE (or scoped storage) for app files.",
    )


def _ev_sqlite(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="sqlite-write", category="insecure_storage"),
        title="SQLite database write observed (verify encryption)",
        severity="info",
        description=(
            "The app wrote to a local SQLite database during the "
            "instrumented run. Confirm sensitive tables use SQLCipher (or "
            "equivalent) — statement shape only is recorded, not row data."
        ),
        evidence=f"SQLiteDatabase.execSQL({str(ev.get('sql', ''))[:200]})",
        recommendation="Encrypt databases holding sensitive data (SQLCipher).",
    )


def _ev_weak_hash(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="weak-hash", category="weak_cryptography"),
        title=f"Weak hash in use at runtime: {ev.get('algorithm')}",
        severity="medium",
        cwe_id="CWE-327",
        description=(
            f"MessageDigest.getInstance({ev.get('algorithm')!r}) was called. "
            "MD5/SHA-1 are broken for integrity/password purposes."
        ),
        evidence=f"MessageDigest.getInstance({ev.get('algorithm')}) observed",
        recommendation="Use SHA-256+ (or bcrypt/argon2 for passwords).",
    )


def _ev_weak_cipher(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="weak-cipher", category="weak_cryptography"),
        title=f"Weak cipher transformation: {ev.get('transformation')}",
        severity="high",
        cwe_id="CWE-327",
        description=(
            f"Cipher.getInstance({ev.get('transformation')!r}) — DES or ECB "
            "mode observed at runtime. ECB leaks plaintext patterns; DES is "
            "brute-forceable."
        ),
        evidence=f"Cipher.getInstance({ev.get('transformation')}) observed",
        recommendation="Use AES/GCM (or ChaCha20-Poly1305) with a random IV.",
    )


def _ev_securerandom_seed(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="securerandom-seed",
                      category="weak_cryptography"),
        title="Manual SecureRandom.setSeed(byte[]) call observed",
        severity="low",
        cwe_id="CWE-330",
        description=(
            "The app overrode SecureRandom's seed at runtime. A static seed "
            "makes output predictable — verify the seed is itself random "
            "(or remove the call; the OS seeds SecureRandom adequately)."
        ),
        evidence="SecureRandom.setSeed(byte[]) observed",
        recommendation="Do not call setSeed with static bytes.",
    )


def _ev_trustmanager(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="custom-trustmanager",
                      category="insecure_transport"),
        title=f"Custom X509TrustManager in use: {ev.get('impl')}",
        severity="low",
        cwe_id="CWE-297",
        description=(
            f"TLS validation ran through {ev.get('impl')}. A custom "
            "TrustManager is where trust-all bypasses hide — cross-check "
            "the static findings for an empty checkServerTrusted, and "
            "confirm the production build pins or properly validates."
        ),
        evidence=f"checkServerTrusted via {ev.get('impl')} observed",
        recommendation="Validate the TrustManager impl; prefer pinning.",
    )


def _ev_hostname_verify(ev: dict) -> IRFinding | None:
    if ev.get("result") is not True:
        return None
    return IRFinding(
        **_frida_base(ev, rule_id="hostname-verify-true",
                      category="insecure_transport"),
        title=f"HostnameVerifier accepted: {ev.get('hostname')}",
        severity="low",
        cwe_id="CWE-297",
        description=(
            f"{ev.get('impl')} returned true for {ev.get('hostname')!r}. "
            "Accepts are normal for valid hosts — flag only if the impl is "
            "custom/permissive (compare with static analysis)."
        ),
        evidence=f"HostnameVerifier.verify({ev.get('hostname')}) -> true",
        recommendation="Ensure the verifier is the default strict one.",
    )


def _ev_webview_ssl(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="webview-ssl-proceed",
                      category="insecure_transport"),
        title="WebView tapped through a TLS error (SslErrorHandler.proceed)",
        severity="high",
        cwe_id="CWE-297",
        description=(
            "The app called SslErrorHandler.proceed() — it continues loading "
            "a page after a certificate error, defeating TLS for WebView "
            "content (MITM-able)."
        ),
        evidence="SslErrorHandler.proceed() observed at runtime",
        recommendation="Call cancel() on SSL errors, never proceed().",
    )


def _ev_cleartext_url(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="cleartext-url",
                      category="insecure_transport"),
        title=f"Cleartext HTTP request at runtime: {str(ev.get('url', ''))[:100]}",
        severity="medium",
        description=(
            "The app opened a plaintext http:// URL while instrumented. "
            "Observed on the wire path — stronger than a static manifest "
            "flag."
        ),
        evidence=f"java.net.URL({str(ev.get('url', ''))[:200]})",
        recommendation="Move the endpoint to HTTPS; forbid cleartext.",
    )


def _ev_debugger(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="debugger-connected",
                      category="insufficient_protection"),
        title="Debugger attachment observed (expected under instrumentation)",
        severity="info",
        description=(
            "Debug.isDebuggerConnected() returned true — normal for a "
            "Frida-instrumented run. Relevant only if the app is supposed "
            "to refuse debuggable sessions in release builds."
        ),
        evidence="Debug.isDebuggerConnected() -> true",
        recommendation="Ensure release builds set android:debuggable=false.",
    )


def _ev_sensitive_exec(ev: dict) -> IRFinding:
    return IRFinding(
        **_frida_base(ev, rule_id="sensitive-exec",
                      category="insufficient_protection"),
        title=f"App executed shell command: {' '.join(map(str, ev.get('argv', [])))[:100]}",
        severity="info",
        description=(
            "Runtime.exec with su/busybox/mount/getprop-style argv — "
            "typically the app's own root/environment checks firing. "
            "Context for the root-detection-bypass test (which check to "
            "patch and re-run)."
        ),
        evidence=f"Runtime.exec({ev.get('argv')}) observed",
        recommendation="Map each check before attempting bypass.",
    )


def _ev_build_tags(ev: dict) -> IRFinding | None:
    if "test-keys" not in str(ev.get("tags", "")):
        return None
    return IRFinding(
        **_frida_base(ev, rule_id="test-keys-build",
                      category="insufficient_protection"),
        title="App running on a test-keys (debug/emulator) build",
        severity="low",
        description=(
            "Build.TAGS contains test-keys — the instrumented environment "
            "is not a production-signed build. Findings about missing "
            "root/debug defences must be re-verified on a release build."
        ),
        evidence=f"Build.TAGS={ev.get('tags')}",
        recommendation="Re-run critical dynamic checks on a release build.",
    )


_FRIDA_HANDLERS = {
    "shared-prefs-write": _ev_shared_prefs,
    "shared-prefs-write-set": _ev_shared_prefs,
    "world-accessible-file": _ev_world_file,
    "sqlite-exec": _ev_sqlite,
    "weak-hash": _ev_weak_hash,
    "weak-cipher": _ev_weak_cipher,
    "securerandom-seed": _ev_securerandom_seed,
    "trustmanager-check": _ev_trustmanager,
    "hostname-verify": _ev_hostname_verify,
    "webview-ssl-proceed": _ev_webview_ssl,
    "cleartext-url": _ev_cleartext_url,
    "debugger-connected": _ev_debugger,
    "sensitive-exec": _ev_sensitive_exec,
    "build-tags": _ev_build_tags,
    # Observation-only events (no finding): hash-use, cipher-use, file-write.
}


# ---------------------------------------------------------------------------
# Exported components (parsed from the apktool-decoded AndroidManifest.xml)
# ---------------------------------------------------------------------------

def manifest_exported_findings(components: list[dict[str, Any]]) -> list[IRFinding]:
    """Map parsed manifest components to IRFinding entries.

    ``components``: {kind, name, exported: bool, permission: str|None}.
    Exported + no permission guard = runtime-attackable surface (medium);
    exported WITH a permission = recorded as info for the LLM/reviewer.
    Unexported components are skipped (no finding).
    """
    out: list[IRFinding] = []
    for comp in components:
        if not comp.get("exported"):
            continue
        name = str(comp.get("name", "?"))
        kind = str(comp.get("kind", "component"))
        permission = comp.get("permission")
        if permission:
            out.append(IRFinding(
                tool="emulator",
                rule_id="exported-with-permission",
                category="exposed_component",
                title=f"Exported {kind} (permission-guarded): {name[:120]}",
                severity="info",
                confidence="high",  # read from the shipped manifest
                cwe_id="CWE-926",
                file="AndroidManifest.xml",
                description=(
                    f"{kind} {name!r} is exported but guarded by permission "
                    f"{permission!r}. Verify the permission's protectionLevel "
                    "is signature-level for sensitive components."
                ),
                evidence=f"<{kind} android:name={name!r} permission={permission!r}>",
                recommendation="Prefer signature-level permissions; unexport if unused.",
                raw={"kind": kind, "permission": permission},
            ))
        else:
            out.append(IRFinding(
                tool="emulator",
                rule_id="exported-no-permission",
                category="exposed_component",
                title=f"Exported {kind} without permission: {name[:120]}",
                severity="medium",
                confidence="high",
                cwe_id="CWE-926",
                file="AndroidManifest.xml",
                description=(
                    f"{kind} {name!r} is exported with no permission guard — "
                    "any app on the device can invoke it. CANDIDATE for "
                    "runtime exercising: send it crafted intents during the "
                    "instrumented run and watch for crashes/data leaks."
                ),
                evidence=f"<{kind} android:name={name!r} exported=true, no permission>",
                recommendation="Set exported=false or add a permission guard.",
                raw={"kind": kind},
            ))
    return out


# ---------------------------------------------------------------------------
# Logcat observations (structured hits from tools/emulator.scan_logcat_text)
# ---------------------------------------------------------------------------

def logcat_findings(hits: list[dict[str, Any]]) -> list[IRFinding]:
    """Map logcat scan hits ({kind, tag, line}) to IRFinding entries."""
    out: list[IRFinding] = []
    for hit in hits:
        kind = hit.get("kind")
        line = str(hit.get("line", ""))[:300]
        if kind == "cleartext-url":
            out.append(IRFinding(
                tool="emulator",
                rule_id="logcat-cleartext-url",
                category="insecure_transport",
                title="Cleartext URL in logcat output",
                severity="medium",
                confidence="high",
                description=(
                    "A plaintext http:// URL appeared in logcat during the "
                    "instrumented run — corroborates runtime cleartext traffic."
                ),
                evidence=line,
                recommendation="Move the endpoint to HTTPS.",
                raw={"tag": hit.get("tag")},
            ))
        elif kind == "credential-in-log":
            out.append(IRFinding(
                tool="emulator",
                rule_id="credential-in-log",
                category="sensitive_data_exposure",
                title="Possible credential/secret written to logcat",
                severity="high",
                confidence="medium",  # label-matched, verify the value
                cwe_id="CWE-532",
                description=(
                    "A logcat line pairs a secret label (password/token/...) "
                    "with a value. Logcat is readable by other apps with "
                    "READ_LOGS on older platforms and leaks into bug reports."
                ),
                evidence=line,
                recommendation="Strip secrets from all log output.",
                raw={"tag": hit.get("tag")},
            ))
    return out
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# MobSF (report JSON)
# ---------------------------------------------------------------------------

# MobSF v3 groups findings under category keys in its report JSON. The exact
# set varies across versions; collect from every candidate key defensively.
_MOBSF_CATEGORY_KEYS = [
    "manifest_analysis",
    "binary_analysis",
    "network_analysis",
    "code_analysis",
    "malware_analysis",
    "exported_activities",
    "exported_services",
    "exported_receivers",
    "exported_providers",
]

_LEVEL_TO_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "warning": "low",
    "low": "low",
    "info": "info",
}


def _severity(level: Any) -> str | None:
    if level is None:
        return None
    return _LEVEL_TO_SEVERITY.get(str(level).lower(), str(level).lower())


def mobsf_findings(report: dict[str, Any]) -> list[IRFinding]:
    """Map a MobSF report dict to IRFinding entries.

    MobSF report entries are plain dicts keyed roughly by title/level/description/
    file_path/code/cwe/owasp — normalise only what's present, keep the rest in raw.
    """
    out: list[IRFinding] = []
    for key in _MOBSF_CATEGORY_KEYS:
        entries = report.get(key)
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            raw_extra = {k: item[k] for k in ("owasp", "cvss", "cwe", "level") if item.get(k) is not None}
            out.append(
                IRFinding(
                    tool="mobsf",
                    rule_id=str(item.get("rule") or item.get("rule_id"))
                        if (item.get("rule") or item.get("rule_id"))
                        else None,
                    category=key,
                    title=str(item.get("title") or "").strip()[:200] or None,
                    severity=_severity(item.get("level")),
                    confidence=None,
                    cwe_id=str(item.get("cwe")) if item.get("cwe") else None,
                    file=item.get("file_path") or item.get("file"),
                    line=None,
                    end_line=None,
                    description=str(item.get("description") or "") or None,
                    evidence=str(item.get("code") or "")[:2000] or None,
                    recommendation=str(item.get("recommendation") or "") or None,
                    raw=raw_extra,
                )
            )
    return out