"""Normalizers — raw tool output -> common intermediate JSON shape.

Each function is pure and unit-testable with fixture JSON. The LLM agents in
later phases consume this normalized shape, never the raw tool dumps.
"""

from __future__ import annotations

from typing import Any

from scan_toolkit.intermediate import IRFinding


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