"""Quality gate per integrating-dast-with-owasp-zap-in-pipeline (Step 4).

Maps ZAP rule (pluginId) → gate action, mirroring .zap/rules.tsv:

  40012  FAIL  Cross Site Scripting (Reflected)
  40014  FAIL  Cross Site Scripting (Persistent)
  40018  FAIL  SQL Injection
  40019  FAIL  SQL Injection (MySQL)
  40032  FAIL  .htaccess Information Leak
  90033  FAIL  Loosely Scoped Cookie

Header/misconfig plugins (10015/10021/10035/10038) are WARN — real but
not deployment blockers. Anything unlisted falls back to severity:
critical/high from an active scanner (zap/nuclei) FAILs the gate,
everything else passes through as WARN/INFO without blocking.
"""

from app.models import Finding, Severity

FAIL_PLUGINS = frozenset({"40012", "40014", "40018", "40019", "40032", "90033"})
WARN_PLUGINS = frozenset({"10015", "10021", "10035", "10038"})

# Non-ZAP scanners have no pluginId; a high/critical from an active
# scanner (zap/nuclei) with concrete evidence blocks, info/low never does.
FAIL_SCANNERS = frozenset({"zap", "nuclei"})
FAIL_SEVERITIES = frozenset({Severity.critical, Severity.high})


def gate_action(finding: Finding) -> str:
    """Return FAIL, WARN, or PASS for a single finding."""
    plugin = str((finding.raw or {}).get("pluginid") or "")
    if plugin in FAIL_PLUGINS:
        return "FAIL"
    if plugin in WARN_PLUGINS:
        return "WARN"
    if finding.scanner in FAIL_SCANNERS and finding.severity in FAIL_SEVERITIES:
        return "FAIL"
    if finding.severity in (Severity.medium, Severity.low):
        return "WARN"
    return "PASS"


def evaluate_gate(
    findings: list[Finding], coverage: dict | None = None
) -> tuple[str, list[str]]:
    """Return (verdict, details). Verdict is FAILED, INCOMPLETE, or PASSED.

    Coverage honesty (2026-09-16): a PASSED verdict on 4/20 ascan targets
    misled on Juice Shop. FAILED still wins (a real vuln is a real vuln);
    otherwise partial active-scan coverage downgrades to INCOMPLETE so the
    verdict reflects how much was actually tested.
    """
    failing = [f"{f.scanner}:{f.title}" for f in findings if gate_action(f) == "FAIL"]
    if failing:
        return ("FAILED", failing)
    note = _coverage_note(coverage)
    if note:
        return ("INCOMPLETE", [note])
    return ("PASSED", [])


# Active scan below this fraction of planned targets = partial verdict.
ASCAN_COVERAGE_MIN_RATIO = 0.75


def _coverage_note(coverage: dict | None) -> str | None:
    if not isinstance(coverage, dict):
        return None
    zap = coverage.get("zap")
    if not isinstance(zap, dict):
        return None
    targets = zap.get("ascan_targets") or 0
    scanned = zap.get("ascan_scanned") or 0
    if targets <= 0:
        skipped = zap.get("ascan_skipped")
        if skipped and zap.get("classic_spider"):
            return f"active scan did not run ({skipped}); verdict covers passive/spider findings only"
        return None
    if scanned / targets < ASCAN_COVERAGE_MIN_RATIO:
        reason = zap.get("ascan_skipped") or f"active scan covered {scanned}/{targets} targets"
        return f"active scan partial ({scanned}/{targets} targets): {reason}"
    return None
