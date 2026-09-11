import json

import httpx

from app.models import Finding, Severity
from app.scanners.base import BaseScanner


CHECKS = (
    {
        "header": "strict-transport-security",
        "title": "Missing HSTS header",
        "severity_https": Severity.medium,
        "description": "Strict-Transport-Security not set. Clients may accept plaintext HTTP on first visit.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
        "header": "content-security-policy",
        "title": "Missing Content-Security-Policy header",
        "severity_https": Severity.medium,
        "description": "No CSP header. XSS impact is harder to contain.",
        "recommendation": "Add a restrictive Content-Security-Policy (start with default-src 'self').",
    },
    {
        "header": "x-frame-options",
        "title": "Missing X-Frame-Options header",
        "severity_https": Severity.medium,
        "description": "Page can be embedded in iframes (clickjacking risk).",
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN) or use frame-ancestors in CSP.",
    },
    {
        "header": "x-content-type-options",
        "title": "Missing X-Content-Type-Options header",
        "severity_https": Severity.low,
        "description": "MIME sniffing not disabled.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header": "referrer-policy",
        "title": "Missing Referrer-Policy header",
        "severity_https": Severity.low,
        "description": "Referrer leakage policy not defined.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    },
    {
        "header": "permissions-policy",
        "title": "Missing Permissions-Policy header",
        "severity_https": Severity.info,
        "description": "Browser feature permissions not restricted.",
        "recommendation": "Add Permissions-Policy to disable unused features (camera, microphone, geolocation).",
    },
)


class HeadersScanner(BaseScanner):
    name = "headers"

    def run(self) -> list[Finding]:
        try:
            r = httpx.get(self.target_url, follow_redirects=True, timeout=15.0)
            headers = dict(r.headers)
            status = r.status_code
        except Exception as exc:
            raise RuntimeError(f"header check failed: {exc}")
        (self.workdir / "headers.json").write_text(
            json.dumps({"url": self.target_url, "status": status, "headers": headers}, indent=2)
        )
        return self._parse(headers, status)

    def _parse(self, headers: dict, status: int) -> list[Finding]:
        lowered = {k.lower(): v for k, v in headers.items()}
        findings: list[Finding] = []

        for check in CHECKS:
            h = check["header"]
            if h not in lowered or not lowered[h]:
                # HSTS only matters on HTTPS; skip on plain HTTP to avoid noise
                # (testssl/ZAP cover transport separately).
                if h == "strict-transport-security" and self.scheme != "https":
                    continue
                findings.append(
                    Finding(
                        scanner=self.name,
                        title=check["title"],
                        severity=check["severity_https"],
                        description=check["description"],
                        evidence=f"HTTP {status}, header '{h}' absent",
                        location=self.target_url,
                        recommendation=check["recommendation"],
                        raw={"header": h, "status": status},
                    )
                )

        # Cookie flags: fast high-value check that ZAP may miss on spider-only runs.
        set_cookie = lowered.get("set-cookie", "")
        if set_cookie:
            missing: list[str] = []
            lc = set_cookie.lower()
            if "httponly" not in lc:
                missing.append("HttpOnly")
            if "samesite" not in lc:
                missing.append("SameSite")
            if self.scheme == "https" and "secure" not in lc:
                missing.append("Secure")
            if missing:
                findings.append(
                    Finding(
                        scanner=self.name,
                        title=f"Weak Set-Cookie flags: {', '.join(missing)} missing",
                        severity=Severity.medium,
                        description="Session cookies without Secure/HttpOnly/SameSite are easier to steal via XSS or leak over HTTP.",
                        evidence=set_cookie[:300],
                        location=self.target_url,
                        recommendation="Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict).",
                        raw={"header": "set-cookie", "missing": missing},
                    )
                )

        # Server version disclosure (info only, never fails a build).
        server = lowered.get("server", "")
        if server:
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Server banner disclosed: {server[:60]}",
                    severity=Severity.info,
                    description="Server header reveals software/version. Useful for targeted attacks.",
                    evidence=server,
                    location=self.target_url,
                    recommendation="Minimize Server header (e.g. server_tokens off; or strip via proxy).",
                    raw={"header": "server", "value": server},
                )
            )

        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    title="Security headers present",
                    severity=Severity.info,
                    description="All checked security headers present, no cookie flag or banner issues.",
                    location=self.target_url,
                )
            )
        return findings
