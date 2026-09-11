from app.models import Finding, Severity

SEVERITY_RANK = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.info: 1,
}

ZAP_RISK_MAP = {
    "4": Severity.critical,
    "3": Severity.high,
    "2": Severity.medium,
    "1": Severity.low,
    "0": Severity.info,
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "informational": Severity.info,
    "info": Severity.info,
}

TESTSSL_MAP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "WARN": Severity.low,
    "INFO": Severity.info,
    "OK": Severity.info,
}


def from_zap_risk(risk: str | int | None) -> Severity:
    return ZAP_RISK_MAP.get(str(risk or "0").strip().lower(), Severity.info)


def from_testssl(severity: str | None) -> Severity:
    return TESTSSL_MAP.get((severity or "INFO").upper(), Severity.info)


def nmap_port_severity(state: str, service: str) -> Severity:
    risky = {"ftp", "telnet", "rlogin", "vnc", "smb", "microsoft-ds", "netbios-ssn"}
    if state != "open":
        return Severity.info
    if service.lower() in risky:
        return Severity.high
    if service.lower() in {"http", "https", "ssh", "rdp", "ms-wbt-server"}:
        return Severity.medium
    return Severity.low


def prioritize(findings: list[Finding]) -> list[Finding]:
    findings = dedupe(findings)
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.cvss or 0),
        reverse=True,
    )


# Cross-scanner dupes: headers / ZAP / Nikto all report the same
# site-wide config issues (CORS *, missing CSP/HSTS/frame-options/...).
# Without merging, one root cause shows up 10+ times (e.g. ZAP 10098
# per-URL + Nikto 999986). Group by concept per target host; keep the
# strongest finding, record merged sources + affected URLs.
def _concept(f: Finding) -> str | None:
    title = (f.title or "").lower()
    desc = (f.description or "").lower()
    text = f"{title} {desc}"
    raw = f.raw or {}
    header = str(raw.get("header") or "").lower()
    plugin = str(raw.get("pluginid") or "")
    nikto_id = str(raw.get("nikto_id") or "")

    if plugin == "10098" or nikto_id == "999986" or "access-control-allow-origin" in text or "cross-domain misconfiguration" in text:
        return "cors-star"
    if header == "content-security-policy" or plugin == "10038" or (nikto_id == "013587" and "content-security-policy" in text):
        return "csp-missing"
    if header == "strict-transport-security" or plugin == "10035" or (nikto_id == "013587" and "strict-transport-security" in text):
        return "hsts-missing"
    if header == "x-frame-options" or plugin == "10020" or (nikto_id == "013587" and "x-frame-options" in text):
        return "frame-options-missing"
    if header == "x-content-type-options" or plugin == "10021" or nikto_id == "007352" or (nikto_id == "013587" and "x-content-type-options" in text):
        return "content-type-options-missing"
    if header == "referrer-policy" or (nikto_id == "013587" and "referrer-policy" in text):
        return "referrer-policy-missing"
    if header == "permissions-policy" or (nikto_id == "013587" and "permissions-policy" in text):
        return "permissions-policy-missing"
    return None


def dedupe(findings: list[Finding]) -> list[Finding]:
    grouped: dict[str, list[Finding]] = {}
    passthrough: list[Finding] = []
    for f in findings:
        concept = _concept(f)
        if concept is None:
            passthrough.append(f)
            continue
        grouped.setdefault(concept, []).append(f)

    merged: list[Finding] = []
    for concept, items in grouped.items():
        if len(items) == 1:
            merged.append(items[0])
            continue
        # Winner: highest severity, then longest description (usually ZAP/headers).
        winner = sorted(items, key=lambda f: (SEVERITY_RANK[f.severity], len(f.description or "")), reverse=True)[0]
        sources = sorted({f.scanner for f in items})
        urls = sorted({f.location for f in items if f.location})
        data = dict(winner.raw or {})
        data["merged_from"] = [f.model_dump(mode="json") for f in items if f.id != winner.id]
        data["merged_concept"] = concept
        data["merged_count"] = len(items)
        data["affected_urls"] = urls
        extra = f" Also reported by {', '.join(sources)} ({len(items)}x, {len(urls)} URL(s))."
        if extra not in (winner.description or ""):
            winner = winner.model_copy(
                update={
                    "description": (winner.description or "") + extra,
                    "raw": data,
                }
            )
        else:
            winner = winner.model_copy(update={"raw": data})
        merged.append(winner)
    return passthrough + merged
