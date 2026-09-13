"""Sensitive file exposure check.

Scanners (ZAP spider, Nikto, …) discover URLs across the target but only
report what their own checks cover. A KeePass database sitting in /ftp/
shows up merely as one URL among 50 in a merged "missing CSP header"
finding — nobody flags the password database itself.

This module re-examines every already-discovered, same-host URL for
suspicious extensions and filenames (.bak, .kdbx, .env, .pyc, .sql,
.pem, …) and surfaces each hit as its own HIGH-severity finding.
Pattern matches are live-verified: the URL is fetched and byte-compared
against the scan root, so SPA catch-all shells (HTTP 200 + index.html for
unknown paths) collapse into one INFO instead of false HIGHs. Only a
handful of verification GETs; fail-open (finding kept) on fetch errors.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from app.models import Finding, Severity

# (compiled regex against the URL path, human label, why-it-matters)
HIGH_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\.kdbx$", re.I), "KeePass password database",
     "A KeePass vault was exposed over HTTP. Vaults hold credentials for other systems; even encrypted, offline brute-force applies."),
    (re.compile(r"\.(pem|key|p12|pfx|jks|keystore|asc)$", re.I), "Private key / keystore",
     "Private cryptographic material exposed. Enables impersonation, decryption, and code signing as the victim."),
    (re.compile(r"(\.env$|(^|/)\.env\.)", re.I), "Environment file",
     ".env files routinely contain production secrets: DB passwords, API keys, session salts."),
    (re.compile(r"\.(sql|dump|bak|old|backup|back|orig|save)$", re.I), "Backup / database dump",
     "Backup and dump files bypass access controls and often contain live data or credentials."),
    (re.compile(r"~$", re.I), "Editor backup file",
     "Trailing-~ editor backups expose source that the live file hides."),
    (re.compile(r"(^|/)\.(git|svn|hg|bzr)(/|$)", re.I), "Version-control metadata",
     "Exposed .git/.svn allows full source reconstruction, including secrets in history."),
    (re.compile(r"(^|/)\.htpasswd$", re.I), "Password file (.htpasswd)",
     "Hashed credentials exposed; offline cracking yields valid logins."),
    (re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?$", re.I), "SSH private key",
     "SSH private key exposed. Direct server access if passphraseless or crackable."),
    (re.compile(r"\.(sqlite|sqlite3?|db|mdb|frm|kdb)$", re.I), "Database file",
     "A raw database file served over HTTP — full table contents without authentication."),
    (re.compile(r"\.(sh_history|bash_history|bashhistory|history)$", re.I), "Shell history",
     "Shell histories frequently contain typed passwords, tokens, and connection strings."),
    (re.compile(r"\.(pyc|pyo|class|phps)$", re.I), "Compiled / disclosed source",
     "Compiled or source-disclosing files leak application logic, and often embedded secrets and crypto."),
]

# Basename keywords for otherwise-ambiguous extensions
# (yml/yaml/json/xml/txt/md/cfg/conf/ini/properties). Catches
# suspicious_errors.yml while leaving legal.md / acquisitions.md alone.
AMBIGUOUS_EXTENSIONS = (
    ".yml", ".yaml", ".json", ".xml", ".txt", ".md",
    ".cfg", ".conf", ".ini", ".properties",
)
KEYWORD_RE = re.compile(
    r"(passw|passwd|secret|credential|private|suspicious|incident|confidential|shadow|token|backup|internal)",
    re.I,
)
ENCRYPT_RE = re.compile(r"encrypt", re.I)

MEDIUM_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\.log$", re.I), "Log file",
     "Log files can leak paths, usernames, session tokens, and stack traces useful for targeting."),
]


def _path(url: str) -> str:
    try:
        return urlparse(url).path or ""
    except Exception:
        return ""


def _classify(url: str) -> tuple[Severity, str, str] | None:
    path = _path(url)
    if not path or path == "/":
        return None
    for rx, label, why in HIGH_PATTERNS:
        if rx.search(path):
            return Severity.high, label, why
    basename = path.rsplit("/", 1)[-1]
    lower = basename.lower()
    if any(lower.endswith(ext) for ext in AMBIGUOUS_EXTENSIONS):
        stem = lower.rsplit(".", 1)[0]
        if KEYWORD_RE.search(stem):
            return (Severity.high, "Sensitive-named data file",
                    f"'{basename}' matches a sensitive filename pattern ({KEYWORD_RE.search(stem).group(0)}). "
                    "Oddly-named data files in public dirs are frequently backups, incident artifacts, or exports.")
        if ENCRYPT_RE.search(stem):
            return (Severity.medium, "Possibly encrypted sensitive content",
                    f"'{basename}' suggests encrypted content served over HTTP. Review what it protects and why it is public.")
    for rx, label, why in MEDIUM_PATTERNS:
        if rx.search(path):
            return Severity.medium, label, why
    return None


def _fetch_status_body(url: str) -> tuple[int | None, bytes | None]:
    """Best-effort GET. Returns (status_code, body); (None, None) on any error.

    Fail-open lives with the caller: network errors (None) keep the HIGH,
    definitive non-200 (403/404/…) demotes to INFO — verified 2026-09-13:
    Juice Shop 403s /ftp/*.bak|*.pyc|*.yml while .kdbx returns 200.
    """
    try:
        import httpx

        r = httpx.get(url, follow_redirects=True, timeout=10.0)
        return r.status_code, r.content
    except Exception:
        return None, None


def _fetch_body(url: str) -> bytes | None:
    """Back-compat wrapper: body only when HTTP 200, else None."""
    status, body = _fetch_status_body(url)
    return body if status == 200 else None


def flag_sensitive_files(target_url: str, findings: list[Finding]) -> list[Finding]:
    """Build one finding per exposed sensitive file found in discovered URLs."""
    try:
        target_host = (urlparse(target_url).hostname or "").lower()
    except Exception:
        target_host = ""
    # url -> scanners that referenced it
    seen: dict[str, set[str]] = {}
    for f in findings:
        raw = f.raw or {}
        candidates = [f.location, raw.get("url"), raw.get("matched_at")]
        for key in ("affected_urls", "urls"):
            val = raw.get(key)
            if isinstance(val, list):
                candidates.extend(val)
        for u in candidates:
            if not isinstance(u, str) or not u.startswith(("http://", "https://")):
                continue
            try:
                host = (urlparse(u).hostname or "").lower()
            except Exception:
                continue
            if target_host and host != target_host:
                continue
            seen.setdefault(u.split("#")[0], set()).add(f.scanner)

    out: list[Finding] = []
    unverifiable: list[str] = []
    catchall_skipped: list[str] = []
    # SPA catch-all check (same technique as NiktoScanner._is_spa_catchall):
    # servers like Juice Shop answer unknown paths with HTTP 200 + index.html,
    # so a patterned URL alone proves nothing. Byte-compare against the root;
    # identical bodies are the app shell, not a leaked file. Fail-open (keep
    # the finding) when either fetch errors.
    root_body: bytes | None = None
    root_fetched = False
    for url in sorted(seen):
        classified = _classify(url)
        if classified is None:
            continue
        if not root_fetched:
            root_body = _fetch_body(target_url)
            root_fetched = True
        if root_body is not None:
            status, body = _fetch_status_body(url)
            if status is not None and status != 200:
                # Definitive negative: pattern matched but server refuses
                # (Juice Shop: 403 on *.bak/*.pyc/*.yml, 200 on .kdbx).
                # Demote to INFO instead of a false HIGH.
                severity, label, why = classified
                basename = _path(url).rsplit("/", 1)[-1]
                out.append(
                    Finding(
                        scanner="sensitive-files",
                        title=f"Sensitive-named URL not retrievable (HTTP {status}): {basename} ({label})",
                        severity=Severity.info,
                        description=(
                            f"{why} Pattern matched at {url}, but live fetch returned "
                            f"HTTP {status} — file not exposed right now. Kept as INFO "
                            "in case the block is temporary or path-dependent."
                        ),
                        evidence=f"GET {url} -> HTTP {status}",
                        location=url,
                        recommendation="No immediate action; re-check if server config changes. Keep the deny rule that returns this status.",
                        raw={
                            "url": url,
                            "pattern": label,
                            "discovered_by": sorted(seen[url]),
                            "http_status": status,
                            "catch_all_verified": False,
                        },
                    )
                )
                unverifiable.append(f"{url} (HTTP {status})")
                continue
            if body is not None and body == root_body:
                catchall_skipped.append(url)
                continue
        severity, label, why = classified
        basename = _path(url).rsplit("/", 1)[-1]
        discoverers = sorted(seen[url])
        out.append(
            Finding(
                scanner="sensitive-files",
                title=f"Exposed sensitive file: {basename} ({label})",
                severity=severity,
                description=f"{why} Discovered at {url} (seen by: {', '.join(discoverers)}). "
                "Confirm by fetching the URL, then remove it from the public tree and rotate any exposed credentials.",
                evidence=url,
                location=url,
                recommendation="Remove the file from the public web root (or deny by server config), audit access logs for downloads, and rotate any credentials it may have contained.",
                raw={
                    "url": url,
                    "pattern": label,
                    "discovered_by": discoverers,
                    "catch_all_verified": False,
                },
            )
        )
    if catchall_skipped:
        out.append(
            Finding(
                scanner="sensitive-files",
                title=f"{len(catchall_skipped)} sensitive-named URL(s) return the app shell (SPA catch-all, not leaked files)",
                severity=Severity.info,
                description=(
                    "These URLs matched sensitive-file patterns but return content "
                    "byte-identical to /. The server serves its SPA shell for unknown "
                    "paths, so no such file was actually fingerprinted: "
                    + ", ".join(sorted(catchall_skipped))
                ),
                evidence="GET " + ", ".join(sorted(catchall_skipped)),
                location=target_url,
                recommendation="No action needed if bodies match /. Spot-check one path by diffing against / before acting.",
                raw={"catchall_urls": sorted(catchall_skipped)},
            )
        )
    return out
