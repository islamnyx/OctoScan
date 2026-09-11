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
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.cvss or 0),
        reverse=True,
    )
