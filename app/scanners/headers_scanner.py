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
        # Authenticated scans (v1): session injection on both requests.
        extra = self.auth_headers()
        jar = dict(self.auth.cookies) if self.auth else {}
        try:
            r = httpx.get(
                self.target_url,
                headers=extra or None,
                cookies=jar or None,
                follow_redirects=True,
                timeout=15.0,
            )
            headers = dict(r.headers)
            status = r.status_code
        except Exception as exc:
            raise RuntimeError(f"header check failed: {exc}")
        # CORS probe (testing-cors-misconfiguration skill): a plain GET rarely
        # shows ACAO; re-request with an evil Origin to expose wildcard /
        # reflected-origin misconfigurations. Fail-open: never fails the scan.
        cors_headers: dict = {}
        try:
            rc = httpx.get(
                self.target_url,
                headers={"Origin": "https://evil.example", **extra},
                cookies=jar or None,
                follow_redirects=True,
                timeout=15.0,
            )
            cors_headers = dict(rc.headers)
        except Exception:
            cors_headers = {}
        (self.workdir / "headers.json").write_text(
            json.dumps(
                {"url": self.target_url, "status": status, "headers": headers,
                 "cors_probe": cors_headers},
                indent=2,
            )
        )
        return self._parse(headers, status, cors_headers)

    def _parse(self, headers: dict, status: int, cors_headers: dict | None = None) -> list[Finding]:
        lowered = {k.lower(): v for k, v in headers.items()}
        findings: list[Finding] = []
        request_line = f"GET {self.target_url}"
        present = sorted(lowered.keys())[:20]

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
                        request=request_line,
                        response=f"HTTP {status}; present: {', '.join(present)}",
                        raw={"header": h, "status": status, "finding_class": "missing-security-header",
                             "live_verified": True},
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
                        request=request_line,
                        response=f"HTTP {status}; Set-Cookie without: {', '.join(missing)}",
                        raw={"header": "set-cookie", "missing": missing, "finding_class": "cookie-flags",
                             "live_verified": True},
                    )
                )

        # CORS misconfiguration (OWASP testing-cors-misconfiguration): wildcard
        # or reflected evil origin + credentials = any site reads responses.
        probed = {k.lower(): v for k, v in (cors_headers or {}).items()}
        acao = (probed.get("access-control-allow-origin") or "").strip()
        acac = (probed.get("access-control-allow-credentials") or "").strip().lower()
        if acao == "*" or acao.lower() == "https://evil.example":
            creds = acac == "true"
            findings.append(
                Finding(
                    scanner=self.name,
                    title="Permissive CORS policy (evil Origin accepted)",
                    severity=Severity.high if creds else Severity.medium,
                    description=(
                        "Server returned Access-Control-Allow-Origin reflecting an "
                        f"untrusted Origin ('{acao[:80]}')"
                        + (" with Access-Control-Allow-Credentials: true — any site can read credentialed responses." if creds else ".")
                    ),
                    evidence=f"Origin: https://evil.example -> ACAO: {acao[:120]}",
                    location=self.target_url,
                    recommendation="Never reflect arbitrary Origins. Allow-list trusted origins server-side; avoid ACAO:* with credentials.",
                    request="GET " + self.target_url + " (Origin: https://evil.example)",
                    response=f"ACAO: {acao[:120]}" + ("; ACAC: true" if creds else ""),
                    raw={"header": "access-control-allow-origin", "value": acao, "finding_class": "cors",
                         "live_verified": True},
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
                        request=request_line,
                        response=f"HTTP {status}; Server: {server[:80]}",
                        raw={"header": "server", "value": server, "live_verified": True},
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
