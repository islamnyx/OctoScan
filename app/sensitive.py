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


def _listing_files(body: bytes) -> list[str]:
    """File names linked from a directory-index page (href basenames)."""
    try:
        import re as _re

        text = body.decode("utf-8", "ignore")
        names: list[str] = []
        for href in _re.findall(r'''href=["']([^"']+)["']''', text):
            name = href.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
            if name and name not in (".", "..") and name not in names:
                names.append(name)
        return names[:50]
    except Exception:
        return []


# Extensions/keywords that make a listed file sensitive on sight.
SENSITIVE_EXTENSIONS = frozenset({
    ".bak", ".old", ".orig", ".save", ".sql", ".dump", ".db", ".sqlite",
    ".pem", ".key", ".p12", ".pfx", ".kdbx", ".env", ".md", ".log",
    ".txt", ".yml", ".yaml", ".json", ".xml", ".cfg", ".conf", ".ini",
    ".pyc", ".pyo", ".zip", ".tar", ".gz",
})
SENSITIVE_NAME_KEYWORDS = (
    "passw", "passwd", "secret", "credential", "token", "private",
    "backup", "shadow", "encrypt", "coupon", "incident", "suspicious",
    "key", "config",
)


def _sensitive_names(files: list[str]) -> list[str]:
    """Listed files that look sensitive by extension or name."""
    hits: list[str] = []
    for name in files:
        lower = name.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if ext in SENSITIVE_EXTENSIONS or any(k in lower for k in SENSITIVE_NAME_KEYWORDS):
            hits.append(name)
    return hits


def verify_listed_files(target_url: str, dir_url: str, files: list[str], auth: Auth = None,
                        cap: int = 10) -> tuple[list[dict], list[dict]]:
    """Fetch each sensitive-looking listed file; record status + size.

    Returns (downloads, blocked): downloads have HTTP 200 with a body
    that is NOT the site-root SPA shell; blocked keep their status. For
    blocked files one null-byte variant (`<url>%00.md`) is tried and
    recorded — bypass lead, never claimed without a 200.
    Bounded: cap files × 2 GETs max. Fail-open (empty lists on error).
    """
    downloads: list[dict] = []
    blocked: list[dict] = []
    try:
        from urllib.parse import urlparse as _up

        p = _up(target_url)
        root = f"{p.scheme}://{p.hostname}{(':' + str(p.port)) if p.port else ''}/"
        root_body = _fetch_body(root, auth)
    except Exception:
        root_body = None
    for name in files[:cap]:
        url = dir_url.rstrip("/") + "/" + name
        try:
            status, body = _fetch_status_body(url, auth)
            size = len(body) if body else 0
            real = status == 200 and body is not None and body != root_body and size > 0
            entry: dict = {"name": name, "url": url, "status": status, "bytes": size}
            if real:
                downloads.append(entry)
                continue
            # One bypass probe per blocked file; record, never claim.
            try:
                bstatus, bbody = _fetch_status_body(url + "%00.md", auth)
                entry["bypass_status"] = bstatus
                entry["bypass_bytes"] = len(bbody) if bbody else 0
                if bstatus == 200 and bbody and bbody != root_body:
                    entry["status"] = bstatus
                    entry["bytes"] = len(bbody)
                    entry["bypass"] = "null-byte variant downloaded"
                    downloads.append(entry)
                    continue
            except Exception:
                pass
            blocked.append(entry)
        except Exception:
            continue
    return downloads, blocked


def _looks_dir_like(url: str) -> bool:
    """True for directory-shaped URLs: trailing slash or extensionless.

    ZAP strips trailing slashes when normalizing, so /ftp/ arrives as
    /ftp — an endswith('/') check alone misses every real listing.
    Basenames with a dot (.js, .png, /login) are files/routes, not dirs.
    """
    path = _path(url)
    if not path or path == "/":
        return False
    if path.endswith("/"):
        return True
    return "." not in path.rsplit("/", 1)[-1]


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


Auth = tuple[dict[str, str], dict[str, str]] | None
"""Session injection passthrough: (headers, cookies) or None (anonymous)."""


def _get(url: str, auth: Auth = None) -> tuple[int | None, bytes | None, str]:
    """Single GET primitive: (status, body, final-url); (None, None, url) on error."""
    try:
        import httpx

        headers, cookies = auth or ({}, {})
        r = httpx.get(
            url, headers=headers or None, cookies=cookies or None,
            follow_redirects=True, timeout=10.0,
        )
        return r.status_code, r.content, str(r.url)
    except Exception:
        return None, None, url


def _fetch_status_body(url: str, auth: Auth = None) -> tuple[int | None, bytes | None]:
    """Best-effort GET. Returns (status_code, body); (None, None) on any error.

    Fail-open lives with the caller: network errors (None) keep the HIGH,
    definitive non-200 (403/404/…) demotes to INFO — verified 2026-09-13:
    Juice Shop 403s /ftp/*.bak|*.pyc|*.yml while .kdbx returns 200.
    """
    status, body, _ = _get(url, auth)
    return status, body


def _fetch_body(url: str, auth: Auth = None) -> bytes | None:
    """Back-compat wrapper: body only when HTTP 200, else None."""
    status, body = _fetch_status_body(url, auth)
    return body if status == 200 else None


def _fetch(url: str, auth: Auth = None) -> tuple[bytes | None, str]:
    """Best-effort GET for probes. Returns (body-or-None-on-non-200/error, final-url)."""
    status, body, final = _get(url, auth)
    if status != 200:
        return None, final
    return body, final


def _looks_like_html(body: bytes) -> bool:
    head = body[:300].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def _is_git_head(body: bytes) -> bool:
    if _looks_like_html(body) or len(body) > 200:
        return False
    text = body.decode("utf-8", "ignore").strip()
    return bool(
        re.match(r"ref:\s*refs/", text)
        or re.match(r"[0-9a-f]{40}\s*$", text)  # detached HEAD
    )


def _is_git_config(body: bytes) -> bool:
    if _looks_like_html(body) or len(body) > 20000:
        return False
    text = body.decode("utf-8", "ignore")
    return "[core]" in text and "repositoryformatversion" in text


def _is_env_file(body: bytes) -> bool:
    if _looks_like_html(body) or not (20 < len(body) < 100000):
        return False
    text = body.decode("utf-8", "ignore")
    if "=" not in text:
        return False
    upper = text.upper()
    return any(k in upper for k in ("KEY=", "SECRET", "PASSWORD", "DATABASE", "API_KEY", "TOKEN="))


def _is_ds_store(body: bytes) -> bool:
    return body.startswith(b"\x00\x00\x00\x01Bud1")


def _is_listing(body: bytes) -> bool:
    """True when the body looks like a server-generated directory index
    (Apache/NGINX autoindex, Express serve-index) or an SPA view
    rendering one (Juice Shop /ftp/, whose title is literally
    'listing directory /ftp/') — rather than app content."""
    if not body or len(body) > 500000:
        return False
    try:
        text = body.decode("utf-8", "ignore").lower()
    except Exception:
        return False
    if "index of /" in text and ("<a href" in text or "<tr>" in text):
        return True
    head = body[:4000].lower()
    if any(m in head for m in LISTING_MARKERS):
        return True
    title = re.search(r"<title>(.*?)</title>", text, re.S)
    if title and "listing director" in title.group(1) and text.count("href") >= 3:
        return True
    return False


# Auto-index pages share unmistakable markers across servers
# (Apache/Nginx/lighttpd/Express `serve-index`).
LISTING_MARKERS = (
    b"<title>index of /",
    b"<h1>index of /",
    b"directory listing for /",
    b"<title>directory listing",
    b"[parent directory]",
    b"[to parent directory]",
)


def _is_server_status(body: bytes) -> bool:
    # NOTE: no _looks_like_html guard — mod_status output IS an HTML page;
    # the marker strings below are specific enough on their own.
    if not body or len(body) > 200000:
        return False
    text = body.decode("utf-8", "ignore")
    return "Apache Status" in text and ("requests currently being processed" in text or "Server Version" in text)


def _is_server_info(body: bytes) -> bool:
    if not body or len(body) > 200000:
        return False
    text = body.decode("utf-8", "ignore")
    return "Apache Server Information" in text and "Server Version" in text


def _is_svn_entries(body: bytes) -> bool:
    if _looks_like_html(body) or len(body) > 20000:
        return False
    text = body.decode("utf-8", "ignore")
    return text.startswith("8\ndir\n") or "has-props\n" in text[:200] or "svn:this_dir" in text[:500]


def _is_web_config(body: bytes) -> bool:
    if len(body) > 100000:
        return False
    text = body.decode("utf-8", "ignore").lower()
    return "<configuration" in text and ("appsettings" in text or "connectionstrings" in text)


def _is_composer_json(body: bytes) -> bool:
    if _looks_like_html(body) or len(body) > 100000:
        return False
    try:
        import json as _json

        doc = _json.loads(body.decode("utf-8", "ignore"))
        return isinstance(doc, dict) and ("require" in doc or "name" in doc)
    except Exception:
        return False


# Direct probes: high-value paths no crawler reliably discovers.
# Unlike flag_sensitive_files (which re-examines already-seen URLs),
# these are fetched outright — a handful of GETs, signature-verified,
# catch-all-compared. (path, label, severity, check, why)
WELLKNOWN_PROBES: list[tuple[str, str, Severity, object, str]] = [
    ("/.git/HEAD", "Exposed Git metadata (.git/HEAD)", Severity.high, _is_git_head,
     "The Git HEAD reference is public. Attackers can reconstruct the full "
     "repository (including secrets in history) via /.git/ objects."),
    ("/.git/config", "Exposed Git metadata (.git/config)", Severity.high, _is_git_config,
     "The Git config is public, confirming a browsable .git directory. "
     "Full source reconstruction — including secrets in history — applies."),
    ("/.env", "Exposed environment file (.env)", Severity.high, _is_env_file,
     ".env files routinely contain production secrets: DB passwords, API keys, session salts."),
    ("/.DS_Store", "Exposed .DS_Store file", Severity.medium, _is_ds_store,
     ".DS_Store leaks directory listings and filenames, aiding targeted attacks."),
    ("/server-status", "Exposed Apache server-status page", Severity.high, _is_server_status,
     "mod_status reveals live requests, client IPs and server internals to anyone. Restrict to localhost."),
    ("/server-info", "Exposed Apache server-info page", Severity.medium, _is_server_status,
     "mod_info discloses loaded modules and configuration. Restrict to localhost."),
    ("/.svn/entries", "Exposed SVN metadata (.svn/entries)", Severity.high, _is_svn_entries,
     "Subversion metadata leaks repository paths and enables source reconstruction. Remove .svn from the web root."),
    ("/web.config", "Exposed IIS web.config", Severity.medium, _is_web_config,
     "web.config routinely carries connection strings and secrets. Never serve it from the web root."),
    ("/composer.json", "Exposed composer.json", Severity.low, _is_composer_json,
     "Dependency manifests disclose exact package versions for targeted CVE exploitation. Remove from the web root."),
    ("/ftp/", "Exposed directory listing (/ftp/)", Severity.medium, _is_listing,
     "Public upload/download directories frequently contain backups, "
     "incident artifacts, and files with sensitive names."),
]


def _probe_class(label: str) -> str:
    """Finding class for the central OWASP table (app/owasp.py)."""
    low = (label or "").lower()
    if "directory listing" in low:
        return "directory-listing"
    if "server-status" in low or "server-info" in low:
        return "server-status"
    return "sensitive-file"


def probe_wellknown(target_url: str, auth: Auth = None) -> list[Finding]:
    """Fetch a handful of high-value paths and verify their content.

    Pure active check — runs even when no other scanner discovered any
    URL (e.g. headers-only scans). Same-host only: cross-host redirects
    are never flagged. Fail-open per probe.
    """
    out: list[Finding] = []
    try:
        target_host = (urlparse(target_url).hostname or "").lower()
    except Exception:
        return out
    if not target_host:
        return out
    base = target_url.rstrip("/")
    root_body = _fetch_body(target_url, auth)
    for path, label, severity, check, why in WELLKNOWN_PROBES:
        url = base + path
        try:
            body, final = _fetch(url, auth)
            if body is None:
                continue
            try:
                if (urlparse(final).hostname or "").lower() != target_host:
                    continue  # redirected elsewhere — not our finding
            except Exception:
                continue
            if root_body is not None and body == root_body:
                continue  # catch-all shell, not a real file
            if not check(body):
                continue
            ev = body[:120]
            try:
                evidence = ev.decode("utf-8", "ignore")
                if not evidence.isprintable() and "DS_Store" not in label:
                    evidence = ev.hex()[:120]
            except Exception:
                evidence = ""
            is_listing = _probe_class(label) == "directory-listing"
            files = _listing_files(body) if is_listing else []
            sensitive_hits = _sensitive_names(files) if is_listing else []
            downloads, blocked = ([], [])
            if sensitive_hits:
                downloads, blocked = verify_listed_files(target_url, url, sensitive_hits, auth)
            probe_sev = Severity.high if downloads else severity
            probe_desc_extra = ""
            if is_listing and files:
                probe_desc_extra = f" Listed files ({len(files)}): {', '.join(files[:20])}."
                if downloads:
                    probe_desc_extra += " HIGH: downloads verified: " + ", ".join(
                        f"{d['name']} (HTTP {d['status']}, {d['bytes']} B)" for d in downloads[:10]) + "."
                elif sensitive_hits:
                    probe_desc_extra += " Sensitive names present but none download; kept below high."
            out.append(
                Finding(
                    scanner="sensitive-files",
                    title=f"{label} at {path}",
                    severity=probe_sev,
                    description=f"{why} Verified live at {url} (HTTP 200, content signature matched). "
                    "Remove it from the public tree and rotate any exposed credentials."
                    + probe_desc_extra,
                    evidence=(evidence[:200] + (
                        f" files={','.join(_listing_files(body)[:10])}"
                        if is_listing else ""
                    ))[:300],
                    location=url,
                    recommendation="Deny dotfiles in server config (e.g. `location ~ /\\. { deny all; }`), "
                    "remove the file from the public web root, and audit access logs for downloads.",
                    raw={"url": url, "pattern": label, "probed": True, "catch_all_verified": False,
                         "finding_class": _probe_class(label),
                         "directory_listing": is_listing,
                         "listed_files": files if is_listing else [],
                         "sensitive_files": sensitive_hits if is_listing else [],
                         "file_checks": downloads + blocked,
                         "live_verified": True},
                )
            )
        except Exception:
            continue
    return out


def dedupe_listings(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate directory-listing rows (/ftp vs /ftp/).

    flag_sensitive_files (discovered URLs) and probe_wellknown (direct
    probes) can each report the same directory with different trailing
    slashes. Keep the first, record the merge.
    """
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        if f.scanner == "sensitive-files" and (f.raw or {}).get("directory_listing"):
            key = _path(f.location or "").rstrip("/") or "/"
            if key in seen:
                continue
            seen.add(key)
        out.append(f)
    return out


def flag_sensitive_files(
    target_url: str, findings: list[Finding], auth: Auth = None
) -> tuple[list[Finding], dict]:
    """Build one finding per exposed sensitive file found in discovered URLs.

    Returns (findings, meta): SPA-shell catch-all matches are scan
    metadata (meta["catchall_skipped"]), not findings — same rule as
    nmap/testssl skips.
    """
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
    emitted_listings: set[str] = set()
    meta: dict = {}
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
            # Unclassified but directory-shaped: a browsable index is a
            # finding in its own right (e.g. Juice Shop /ftp/ advertised
            # by robots.txt — ZAP normalizes it to /ftp, no trailing
            # slash). 200 + index markers + not the app shell. One URL,
            # one finding: /ftp and /ftp/ are the same directory.
            if _looks_dir_like(url):
                norm_path = _path(url).rstrip("/") or "/"
                if norm_path in emitted_listings:
                    continue
                if not root_fetched:
                    root_body = _fetch_body(target_url, auth)
                    root_fetched = True
                status, body = _fetch_status_body(url, auth)
                if (status == 200 and body and _is_listing(body)
                        and body != root_body):
                    emitted_listings.add(norm_path)
                    discoverers = sorted(seen[url])
                    files = _listing_files(body)
                    sensitive_hits = _sensitive_names(files)
                    # Verify before calling it high: file names alone are
                    # not exposure. Downloads keep HIGH; pure-403 listings
                    # stay medium with bypass leads noted.
                    downloads, blocked = ([], [])
                    if sensitive_hits:
                        downloads, blocked = verify_listed_files(target_url, url, sensitive_hits, auth)
                    severity = Severity.high if downloads else Severity.medium
                    desc_extra = ""
                    if files:
                        desc_extra = f" Listed files ({len(files)}): {', '.join(files[:20])}."
                        if len(files) > 20:
                            desc_extra += f" (+{len(files) - 20} more)"
                    if downloads:
                        desc_extra += (
                            f" HIGH: {len(downloads)} file(s) actually download: "
                            + ", ".join(f"{d['name']} (HTTP {d['status']}, {d['bytes']} B)" for d in downloads[:10])
                            + "."
                        )
                    elif sensitive_hits:
                        blocked_txt = ", ".join(
                            "%s HTTP %s" % (b["name"], b["status"]) for b in blocked[:10]
                        )
                        desc_extra += (
                            " Sensitive names present but none download "
                            f"({blocked_txt}); kept at medium. Null-byte bypass "
                            "variants tried per file, none fetched."
                        )
                    out.append(
                        Finding(
                            scanner="sensitive-files",
                            title=f"Exposed directory listing: {_path(url)}",
                            severity=severity,
                            description=(
                                "The server renders a browsable directory index at "
                                f"{url} (seen by: {', '.join(discoverers)}), exposing file "
                                "names and structure. Disable auto-indexing or restrict access."
                                + desc_extra
                            ),
                            evidence=f"GET {url} -> HTTP 200 directory index ({len(files)} files)"
                            + (f"; downloads: {', '.join(d['name'] for d in downloads[:10])}" if downloads else ""),
                            location=url,
                            recommendation="Disable directory auto-indexing (e.g. `autoindex off`, "
                            "`Options -Indexes`), or require authentication for the directory."
                            + (" Fetch and audit every downloaded file above; rotate exposed credentials." if downloads else ""),
                            raw={
                                "url": url,
                                "discovered_by": discoverers,
                                "directory_listing": True,
                                "catch_all_verified": False,
                                "finding_class": "directory-listing",
                                "listed_files": files,
                                "sensitive_files": sensitive_hits,
                                "file_checks": downloads + blocked,
                                "live_verified": True,
                            },
                        )
                    )
            continue
        if not root_fetched:
            root_body = _fetch_body(target_url, auth)
            root_fetched = True
        if root_body is not None:
            status, body = _fetch_status_body(url, auth)
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
                        "finding_class": "sensitive-file",
                        "live_verified": True,
                    },
                )
            )
    if catchall_skipped:
        meta = {
            "status": "not-applicable",
            "reason": (
                f"{len(catchall_skipped)} sensitive-named URL(s) return content byte-identical "
                "to / (SPA shell served for unknown paths, not leaked files)"
            ),
            "catchall_urls": sorted(catchall_skipped),
            "count": len(catchall_skipped),
        }
    return out, meta
