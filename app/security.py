"""Central security controls (WSTG / SSRF / BAC / headers skills).

Single place for: SSRF guard, scan_id validation, rate limiting,
and security-headers middleware.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from collections import defaultdict
from urllib.parse import urlparse

from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

SCAN_ID_RE = re.compile(r"^[a-fA-F0-9]{8,64}$")

# Cloud metadata + link-local — never valid scan targets.
BLOCKED_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure metadata
    ipaddress.ip_address("169.254.169.253"),
    ipaddress.ip_address("0.0.0.0"),
}

BLOCKED_CIDRS = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / metadata
]


def is_blocked_ip(ip_str: str, allow_private: bool = False) -> str | None:
    """Return reason if IP must be rejected, else None. Raises ValueError for non-IP."""
    ip = ipaddress.ip_address(ip_str)  # ValueError -> caller takes DNS path
    if ip in BLOCKED_IPS:
        return "cloud metadata / link-local address blocked"
    for cidr in BLOCKED_CIDRS:
        if ip in cidr:
            return "link-local range blocked"
    if not allow_private and (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    ):
        # is_reserved covers 240/4 + 0/8; keep message generic to avoid oracle.
        return "internal / non-public address blocked (set ALLOW_PRIVATE_TARGETS=true for lab scans)"
    return None


def validate_target_url(target_url: str, allow_private: bool = False) -> str:
    """SSRF guard per performing-ssrf-vulnerability-exploitation skill.

    - http/https only, no credentials, no non-default weird ports abuse
    - host resolves via DNS and every A/AAAA record is checked
    - fail-closed on DNS errors
    """
    if not target_url or len(target_url) > 2048:
        raise HTTPException(400, "target_url must be 1-2048 chars")
    try:
        p = urlparse(target_url)
    except Exception:
        raise HTTPException(400, "unparsable target_url")
    if p.scheme not in ("http", "https"):
        raise HTTPException(400, "only http/https targets allowed")
    if p.username or p.password or "@" in (p.netloc or ""):
        raise HTTPException(400, "credentials in URL not allowed")
    host = (p.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise HTTPException(400, "target_url needs a hostname")
    if len(host) > 253:
        raise HTTPException(400, "hostname too long")
    # Fast path: literal IP
    try:
        reason = is_blocked_ip(host, allow_private)
        if reason is not None:
            raise HTTPException(403, f"target blocked: {reason}")
        return target_url
    except HTTPException:
        raise
    except ValueError:
        pass
    # DNS path: resolve and check every record (anti DNS-rebind baseline).
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise HTTPException(400, "hostname does not resolve")
    ips = {info[4][0] for info in infos}
    if not ips:
        raise HTTPException(400, "hostname does not resolve")
    for ip in ips:
        reason = is_blocked_ip(ip, allow_private)
        if reason is not None:
            raise HTTPException(403, f"target blocked: {reason}")
    return target_url


def validate_scan_id(scan_id: str) -> str:
    if not SCAN_ID_RE.match(scan_id or "") or ".." in scan_id or "/" in scan_id:
        raise HTTPException(400, "invalid scan id")
    return scan_id


class SimpleRateLimiter:
    """In-memory fixed-window limiter for POST /api/scans (anti scan-DoS)."""

    def __init__(self, max_hits: int = 10, window_s: int = 60):
        self.max_hits = max_hits
        self.window_s = window_s
        self._hits: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str):
        now = time.time()
        bucket = [t for t in self._hits[key] if now - t < self.window_s]
        self._hits[key] = bucket
        if len(bucket) >= self.max_hits:
            raise HTTPException(429, "rate limited: too many scans, retry later")
        bucket.append(now)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Per performing-security-headers-audit skill."""

    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        # HSTS only makes sense over TLS; harmless on http, keep for preload readiness.
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Dashboard is same-origin vanilla JS — tight CSP, no inline relaxation beyond what we ship.
        # index.html uses inline <style>/<script>; allow 'unsafe-inline' for style only,
        # scripts are inline in the single file so we must allow them deliberately.
        # API responses are JSON — CSP doesn't hurt.
        if request.url.path in ("/", "/static/index.html"):
            resp.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
            )
        else:
            resp.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            )
        return resp
