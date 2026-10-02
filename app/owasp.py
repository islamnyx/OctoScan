"""One OWASP Top 10 (2021) mapping for every scanner.

Two keys, one answer:
- CWE id  -> category (precise; preferred)
- finding class -> category (for scanners that emit no CWE:
  Nikto/Nuclei/headers/sensitive-files/testssl)

Never invented: unknown CWE/class yields []. Scanners set
raw["finding_class"]; normalize fills empty owasp centrally so ZAP,
Nuclei, Nikto and headers report the same category for the same
weakness (e.g. CWE-497 is A01 on Private IP Disclosure AND on
Timestamp Disclosure).
"""

from __future__ import annotations

A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"
A03 = "A03:2021-Injection"
A04 = "A04:2021-Insecure Design"
A05 = "A05:2021-Security Misconfiguration"
A06 = "A06:2021-Vulnerable and Outdated Components"
A07 = "A07:2021-Identification and Authentication Failures"

# CWE id (bare number, no "CWE-" prefix) -> OWASP category.
CWE_OWASP: dict[str, str] = {
    # Injection
    "78": A03, "79": A03, "89": A03, "90": A03, "91": A03,
    # Broken access control / exposure
    "200": A01, "201": A01, "359": A01, "352": A01, "639": A01,
    "306": A01, "862": A01, "829": A01,
    # CWE-497 Exposure of Sensitive System Information: A01 everywhere
    # (Private IP Disclosure AND Timestamp Disclosure alike).
    "497": A01,
    # Session identifier in URL: capability leak via logs/referers.
    "598": A01,
    # Security misconfiguration
    "550": A05, "693": A05, "1004": A05, "1021": A05, "614": A05,
    # Vulnerable third-party components (e.g. old JS bundles).
    "1395": A06,
    # Cryptographic failures
    "319": A02, "320": A02, "321": A02, "322": A02, "323": A02,
    "324": A02, "325": A02, "326": A02, "327": A02, "328": A02,
    # Identification / authentication failures
    "287": A07, "307": A07, "308": A07, "798": A07, "916": A07,
}

# Finding class (raw["finding_class"], set by each scanner) -> category.
CLASS_OWASP: dict[str, str] = {
    "missing-security-header": A05,
    "cors": A01,
    "cookie-flags": A05,
    "error-disclosure": A05,
    "sqli": A03,
    "nosql-injection": A03,
    "xss": A03,
    "sensitive-file": A01,
    "directory-listing": A01,
    "server-status": A01,
    "private-ip": A01,
    "timestamp-disclosure": A01,
    "vulnerable-library": A06,
    "session-in-url": A01,
    "metrics-exposure": A01,
    "tls-weakness": A02,
}

# Title-keyword fallback when neither CWE nor class is set.
_TITLE_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("sql injection", A03), ("nosql", A03), ("cross-site scripting", A03),
    ("xss", A03), ("cors", A01), ("cross-domain", A01),
    ("private ip", A01), ("timestamp", A01), ("directory listing", A01),
    ("directory index", A01), ("sensitive", A01), ("exposed", A01),
    ("metrics", A01), ("session id in url", A01),
    ("vulnerable js library", A06), ("outdated", A06),
    ("missing", A05), ("header not set", A05), ("header is not set", A05),
    ("misconfiguration", A05),
    ("error disclosure", A05), ("stack trace", A05),
    ("tls", A02), ("ssl", A02), ("hsts", A05),
)


def _norm_cwe(value: object) -> str:
    s = str(value or "").strip()
    if s.lower().startswith("cwe-"):
        s = s[4:]
    return s if s.isdigit() and int(s) > 0 else ""


def owasp_for(
    cwe: object = None,
    finding_class: str | None = None,
    title: str = "",
    cwes: list | None = None,
) -> list[str]:
    """OWASP categories, [] when unknown. Never guessed beyond the tables."""
    for candidate in ([cwe] if cwe is not None else []) + list(cwes or []):
        num = _norm_cwe(candidate)
        if num and num in CWE_OWASP:
            return [CWE_OWASP[num]]
    if finding_class and finding_class in CLASS_OWASP:
        return [CLASS_OWASP[finding_class]]
    low = (title or "").lower()
    for keyword, category in _TITLE_KEYWORDS:
        if keyword in low:
            return [category]
    return []
