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


def evaluate_gate(findings: list[Finding]) -> tuple[str, list[str]]:
    """Return (verdict, failing_titles). Verdict is PASSED or FAILED."""
    failing = [f"{f.scanner}:{f.title}" for f in findings if gate_action(f) == "FAIL"]
    return ("FAILED" if failing else "PASSED", failing)
