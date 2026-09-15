"""CVSS v3.x base-score calculator (for OSV severity vectors).

OSV ships vectors (`CVSS:3.1/AV:N/...`), not numeric scores. Implementation
follows FIRST CVSS v3.1 §2; validated against known vectors:
Heartbleed 7.5, Log4Shell 10.0, Spectre (CVE-2017-5753) 5.6,
stored-XSS shape 6.1, adm-zip file-write shape 5.5.
"""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PRC = {"N": 0.85, "L": 0.68, "H": 0.5}  # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    if x <= 0:
        return 0.0
    return math.ceil(x * 10) / 10


def cvss_v3_score(vector: str) -> float | None:
    """Base score 0.0-10.0 for a CVSS v3.x vector string, else None."""
    try:
        text = (vector or "").strip()
        if not text.upper().startswith("CVSS:3."):
            return None
        m = dict(part.split(":") for part in text.split("/")[1:])
        iss = 1 - math.prod(1 - _CIA[m[k]] for k in ("C", "I", "A"))
        changed = m.get("S") == "C"
        if not changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.029) ** 15)
        if impact <= 0:
            return 0.0
        pr = (_PRC if changed else _PR)[m["PR"]]
        exploit = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
        if not changed:
            return _roundup(min(impact + exploit, 10))
        return _roundup(min(1.08 * (impact + exploit), 10))
    except Exception:
        return None


def max_cvss(severities: object) -> float | None:
    """Best numeric score from an OSV `severity` list (CVSS_V3 preferred)."""
    best: float | None = None
    items = severities if isinstance(severities, list) else []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") not in ("CVSS_V3", "CVSS_V31", "CVSS_V3_1"):
            continue
        score = cvss_v3_score(str(entry.get("score") or ""))
        if score is not None and (best is None or score > best):
            best = score
    return best
