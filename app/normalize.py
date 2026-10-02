from app.cvss import estimated_cvss
from app.models import Finding, Severity
from app.owasp import owasp_for

import re

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


# Site-wide config concepts: one root cause per host, so the
# representative URL is ALWAYS the origin root (deterministic across
# scans) with the per-URL spread kept in affected_urls. Without this,
# merged CSP/CORS findings jump root -> /rest/user -> /rest/user/login
# between crawls and Compare diffs churn.
SITEWIDE_CONCEPTS = frozenset({
    "cors-star", "csp-missing", "hsts-missing", "frame-options-missing",
    "content-type-options-missing", "referrer-policy-missing",
    "permissions-policy-missing",
})


def _origin_root(location: str) -> str | None:
    """scheme://host/ for an absolute http(s) URL, else None."""
    try:
        from urllib.parse import urlparse

        p = urlparse(location or "")
        if p.scheme in ("http", "https") and p.hostname:
            port = f":{p.port}" if p.port else ""
            return f"{p.scheme}://{p.hostname}{port}/"
    except Exception:
        pass
    return None


def fill_owasp(f: Finding) -> Finding:
    """Fill empty owasp from the central table (CWE, then finding class,
    then title keywords). Scanner-provided values are never overwritten."""
    if f.owasp:
        return f
    raw = f.raw or {}
    owasp = owasp_for(
        cwes=list(f.cwe or []),
        finding_class=str(raw.get("finding_class") or "") or None,
        title=f"{f.title or ''} {f.description or ''}",
    )
    if not owasp:
        return f
    return f.model_copy(update={"owasp": owasp})


# One severity table for every scanner (headers, ZAP, Nikto, Nuclei):
# the same root cause reports one severity no matter who found it.
# Applied at merge time; the original severity is kept in
# raw["severity_normalized_from"] when it changes.
CONCEPT_SEVERITY = {
    "cors-star": Severity.medium,
    "csp-missing": Severity.medium,
    "hsts-missing": Severity.low,
    "frame-options-missing": Severity.low,
    "content-type-options-missing": Severity.low,
    "referrer-policy-missing": Severity.low,
    "permissions-policy-missing": Severity.info,
    # Nikto noise classes: speculative guesses and "uncommon header"
    # banners (e.g. x-recruiting) are recon chatter, not findings.
    "nikto-speculative-paths": Severity.info,
    "nikto-uncommon-header": Severity.info,
}


def _canonical_severity(concept: str) -> Severity | None:
    if concept in CONCEPT_SEVERITY:
        return CONCEPT_SEVERITY[concept]
    # ZAP Timestamp Disclosure (plugin 10096, any param): recon noise.
    if concept.startswith("zap-10096-"):
        return Severity.info
    return None


def clean_cwe(value: object) -> str | None:
    """Normalize a CWE id, treating ZAP's -1/0/"0" ("no CWE") as none.
    Accepts 89, "89", "CWE-89"; returns "CWE-89" or None."""
    s = str(value or "").strip()
    if s.lower().startswith("cwe-"):
        s = s[4:]
    return f"CWE-{int(s)}" if s.lstrip("-").isdigit() and int(s) > 0 else None


def prioritize(findings: list[Finding]) -> list[Finding]:
    findings = correlate(escalate_auth_errors(dedupe(findings)))
    scored: list[Finding] = []
    for f in findings:
        if f.cvss is None:
            data = dict(f.raw or {})
            data["cvss_estimated"] = True
            f = f.model_copy(update={"cvss": estimated_cvss(f.severity.value), "raw": data})
        scored.append(assign_trust(f))
    return sorted(
        scored,
        key=lambda f: (SEVERITY_RANK[f.severity], f.cvss or 0),
        reverse=True,
    )


# Error-disclosure on authentication endpoints: a 500 on
# /rest/user/login is not a generic low — error text on a login sink is
# how SQLi footholds start. Escalate to medium and tag for review;
# when a SQLi finding already exists on the same host, say so explicitly
# so the triage reader connects the two. (Merged from scan-quality-v2.)
AUTH_PATH_RE = re.compile(
    r"/(login|logon|signin|sign-in|signup|sign-up|register|auth|token|"
    r"session|password|account|user)",
    re.I,
)
# Narrow login pattern: the actual sign-in sink (rep-URL first choice).
LOGIN_PATH_RE = re.compile(r"/(login|logon|signin|sign-in)(/|$|\?)", re.I)
ERROR_DISCLOSURE_TITLES = (
    "application error disclosure",
    "error message",
    "stack trace",
    "debug error",
)


def stable_id(scanner: str, key: str) -> str:
    """Deterministic finding ID: sha1(scanner|key), 12 hex chars (same
    shape as the legacy random IDs). Agent verdicts keyed by ID survive
    rescans because the same underlying issue hashes identically."""
    import hashlib

    return hashlib.sha1(f"{scanner}|{key}".encode()).hexdigest()[:12]


def assign_trust(f: Finding) -> Finding:
    """Confidence (0.0-1.0, always set) + verified flag for every finding.

    Rubric (basis recorded in raw["confidence_basis"]):
    - 0.95 / True  — live-confirmed (SQLi differential, login token)
    - 0.90 / True  — live-fetch verified (sensitive content signature,
      Nuclei match, observed headers)
    - 0.85 / None  — measured identifiers (CVE id or real CVSS score)
    - 0.70 / None  — scanner-observed with evidence
    - 0.50 / None  — severity-bucket estimates / heuristics
    - 0.30 / None  — info / no evidence
    """
    raw = dict(f.raw or {})
    conf: float
    ver: bool | None
    if raw.get("sqli_confirmation", {}).get("confirmed") or any(
        p.get("token") for p in (raw.get("login_probes") or []) if isinstance(p, dict)
    ):
        conf, ver, basis = 0.95, True, "live-confirmation"
    elif raw.get("live_verified"):
        conf, ver, basis = 0.90, True, "live-fetch-verified"
    elif f.cve or (f.cvss is not None and not raw.get("cvss_estimated")):
        conf, ver, basis = 0.85, None, "measured"
    elif f.severity == Severity.info or not (f.evidence or f.response):
        conf, ver, basis = 0.30, None, "low-signal"
    elif raw.get("cvss_estimated"):
        conf, ver, basis = 0.50, None, "estimated"
    else:
        conf, ver, basis = 0.70, None, "scanner-observed"
    raw["confidence_basis"] = basis
    return f.model_copy(update={"confidence": conf, "verified": ver, "raw": raw})


def _host_of(location: str) -> str:
    try:
        return (location or "").split("://", 1)[1].split("/", 1)[0].lower()
    except IndexError:
        return ""


def escalate_auth_errors(findings: list[Finding]) -> list[Finding]:
    """Bump error-disclosure findings on auth paths to medium + review tag."""
    hosts_with_sqli = set()
    for f in findings:
        text = f"{f.title or ''} {f.description or ''}".lower()
        if "sql" in text and f.severity in (Severity.critical, Severity.high):
            host = _host_of(f.location or "")
            if host:
                hosts_with_sqli.add(host)
    out: list[Finding] = []
    for f in findings:
        title = (f.title or "").lower()
        # Merged groups bury the login URL in affected_urls while the
        # representative shows /api — check merged URLs too.
        urls_to_check = [f.location or ""]
        raw = f.raw or {}
        affected = raw.get("affected_urls")
        if isinstance(affected, list):
            urls_to_check += [u for u in affected if isinstance(u, str)]
        on_auth = any(AUTH_PATH_RE.search(u or "") for u in urls_to_check)
        if (
            f.scanner in ("zap", "nikto", "nuclei", "sensitive-files")
            and f.severity == Severity.low
            and any(t in title for t in ERROR_DISCLOSURE_TITLES)
            and on_auth
        ):
            host = _host_of(f.location or "")
            note = (
                " Escalated low->medium: error output on an authentication "
                "endpoint deserves manual review (login sinks are prime "
                "injection targets)."
            )
            if host in hosts_with_sqli:
                note += (
                    " A SQL injection finding already exists on this host — "
                    "check whether this error path is the same sink."
                )
            data = dict(raw)
            tags = list(data.get("review_tags") or [])
            if "auth-error-needs-review" not in tags:
                tags.append("auth-error-needs-review")
            data["review_tags"] = tags
            data["escalated_from"] = "low"
            out.append(
                f.model_copy(
                    update={
                        "severity": Severity.medium,
                        "description": (f.description or "") + note,
                        "raw": data,
                    }
                )
            )
            continue
        out.append(f)
    return out


# Cross-scanner dupes: headers / ZAP / Nikto all report the same
# site-wide config issues (CORS *, missing CSP/HSTS/frame-options/...).
# Without merging, one root cause shows up 10+ times (e.g. ZAP 10098
# per-URL + Nikto 999986). Group by concept per target host; keep the
# strongest finding, record merged sources + affected URLs.
SOURCE_SCANNERS = {"gitleaks", "semgrep", "builtin-secrets", "osv", "ai-code-review", "ai"}


def _source_type(text: str, check: str = "", rule: str = "") -> str | None:
    """Coarse finding-type slug so the same underlying issue reported by
    two source scanners merges (e.g. server.key flagged by both semgrep
    and gitleaks). Unknown types return None = never merge."""
    if "private-key" in text or "private key" in text:
        return "private-key"
    if any(k in text for k in ("api-key", "api key", "secret", "token", "password", "passwd", "aws_", "akia", "bcrypt", "hash")):
        return "secret"
    if "sql" in text:
        return "sqli"
    if "xss" in text or "cross-site" in text or "innerhtml" in text:
        return "xss"
    if "command injection" in text or "shell" in text or "exec" in text:
        return "cmdi"
    if "lfi" in text or "rfi" in text or "file inclusion" in text or "path traversal" in text or "traversal" in text:
        return "pathtraversal"
    if "redirect" in text:
        return "redirect"
    if "deserial" in text:
        return "deser"
    if "ssrf" in text:
        return "ssrf"
    if "nosql" in text or "$where" in text:
        return "nosqli"
    if "idor" in text or "broken object" in text or "broken function" in text:
        return "idor"
    if "cve-" in text or text.startswith("cve"):
        return "cve"
    # Fallback: same rule/check on the same file+line merges even when no
    # keyword matches (e.g. a registry rule reported 6x identical). The
    # check/rule slug keeps distinct rules on one line distinct.
    slug = re.sub(r"[^a-z0-9]+", "-", f"{check} {rule}".strip().lower()).strip("-")[:80]
    return f"rule-{slug}" if slug else None


def _source_concept(f: Finding) -> str | None:
    """Same file + same line + same finding-type from any source scanners
    (gitleaks/semgrep/osv/...) is one issue, not N findings. Findings
    without a numeric line number never merge (avoids collapsing distinct
    issues that merely share a file)."""
    if f.scanner not in SOURCE_SCANNERS:
        return None
    loc = f.location or ""
    frag = loc.split("#", 1)[1] if "#" in loc else ""
    rel, _, line = frag.rpartition(":")
    if not rel or not line.strip().isdigit():
        return None
    raw = f.raw or {}
    text = " ".join([
        f.title or "", f.description or "",
        str(raw.get("check") or ""), str(raw.get("rule") or ""),
    ]).lower()
    kind = _source_type(text, str(raw.get("check") or ""), str(raw.get("rule") or ""))
    if kind is None:
        return None
    return f"src-{rel.strip().lower()}-{line.strip()}-{kind}"


def _concept(f: Finding) -> str | None:
    src = _source_concept(f)
    if src is not None:
        return src
    title = (f.title or "").lower()
    desc = (f.description or "").lower()
    text = f"{title} {desc}"
    raw = f.raw or {}
    header = str(raw.get("header") or "").lower()
    plugin = str(raw.get("pluginid") or "")
    nikto_id = str(raw.get("nikto_id") or "")

    if plugin == "10098" or nikto_id == "999986" or "access-control-allow-origin" in text or "cross-domain misconfiguration" in text:
        return "cors-star"
    if header == "content-security-policy" or plugin in ("10038", "10055") or (nikto_id == "013587" and "content-security-policy" in text):
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
    # Generic fallback: the same ZAP rule (plugin+param) firing on N URLs
    # is one root cause, not N findings (e.g. Timestamp Disclosure on every
    # crawled page). Group by rule so each reports once with affected_urls.
    # Param is included so distinct injection points stay distinct.
    if f.scanner == "zap" and plugin:
        param = str(raw.get("param") or "")
        return f"zap-{plugin}-{param}"
    # Nikto "Uncommon header" banners (999100, e.g. x-recruiting): recon
    # chatter about exotic-but-harmless headers. One info row per host.
    if f.scanner == "nikto" and nikto_id == "999100":
        return "nikto-uncommon-header"
    # Nikto speculative guesses ("This might be interesting" for
    # /userdata.json, /login.json, ...) are one noise class, not N rows.
    # The scanner already collapses catch-all-confirmed ones live; this is
    # the safety net for old scans and fail-open network checks. Titles are
    # prefixed ("Nikto 007203: This might be interesting."), so endswith.
    if f.scanner == "nikto" and title.strip().rstrip(".").endswith("this might be interesting"):
        return "nikto-speculative-paths"
    return None


def dedupe(findings: list[Finding]) -> list[Finding]:
    grouped: dict[str, list[Finding]] = {}
    passthrough: list[Finding] = []
    for f in findings:
        concept = _concept(f)
        if concept is None:
            # No shared concept: identity is scanner+title+location so
            # re-runs hash identically (verdicts survive rescans).
            passthrough.append(f.model_copy(update={
                "id": stable_id(f.scanner, f"single:{f.title}|{f.location}")}))
            continue
        grouped.setdefault(concept, []).append(f)

    merged: list[Finding] = []
    for concept, items in grouped.items():
        if len(items) == 1:
            solo = items[0]
            canonical = _canonical_severity(concept)
            if canonical is not None and canonical != solo.severity:
                data = dict(solo.raw or {})
                data["severity_normalized_from"] = solo.severity.value
                solo = solo.model_copy(update={"severity": canonical, "raw": data})
            merged.append(solo.model_copy(update={"id": stable_id(solo.scanner, f"concept:{concept}")}))
            continue
        if concept == "nikto-speculative-paths":
            # Rewrite: winner title would otherwise be a single random
            # path ("Nikto 007203: This might be interesting.") hiding the
            # N-to-1 collapse. State the collapse explicitly.
            winner = sorted(items, key=lambda f: (SEVERITY_RANK[f.severity], len(f.description or "")), reverse=True)[0]
            urls = sorted({f.location for f in items if f.location})
            paths = sorted({str((f.raw or {}).get("url") or f.location) for f in items})
            ids = sorted({str((f.raw or {}).get("nikto_id") or "") for f in items if (f.raw or {}).get("nikto_id")})
            n = len(items)
            data = dict(winner.raw or {})
            data["merged_from"] = [f.model_dump(mode="json") for f in items if f.id != winner.id]
            data["merged_concept"] = concept
            data["merged_count"] = n
            data["merged_sources"] = sorted({f.scanner for f in items})
            data["affected_urls"] = urls
            data["nikto_ids"] = ids
            data["urls"] = paths
            merged.append(
                winner.model_copy(
                    update={
                        "title": f"Nikto: {n} speculative paths returned non-404 responses (likely SPA catch-all)",
                        "severity": Severity.info,
                        "location": min(urls, key=len) if urls else winner.location,
                        "description": (
                            f"{n} guessed paths returned non-404 responses ('This might be "
                            "interesting'). On SPA servers these are typically the app shell "
                            "served for unknown paths, not real files. Review list: "
                            + ", ".join(paths)
                        ),
                        "evidence": "GET " + ", ".join(paths),
                        "recommendation": (
                            "Likely SPA catch-all noise — spot-check one path by diffing "
                            "against / before acting. No action needed if bodies match."
                        ),
                        "raw": data,
                    }
                )
            )
            continue
        # Winner: highest severity, then longest description (usually ZAP/headers).
        winner = sorted(items, key=lambda f: (SEVERITY_RANK[f.severity], len(f.description or "")), reverse=True)[0]
        sources = sorted({f.scanner for f in items})
        urls = sorted({f.location for f in items if f.location})
        # Representative URL (deterministic across crawls):
        # - site-wide config (CSP/CORS/headers): the origin root. No more
        #   root -> /rest/user -> /rest/user/login jumping; the per-URL
        #   spread stays in affected_urls.
        # - auth-relevant groups: the exact login sink when present, else
        #   any auth URL (so /rest/user/login is never buried under /api).
        # - everything else: the shortest URL.
        origin = _origin_root(winner.location)
        login_urls = [u for u in urls if LOGIN_PATH_RE.search(u or "")]
        auth_urls = [u for u in urls if AUTH_PATH_RE.search(u or "")]
        if concept in SITEWIDE_CONCEPTS and origin:
            rep_url = origin
        elif login_urls:
            rep_url = min(login_urls, key=len)
        elif auth_urls:
            rep_url = min(auth_urls, key=len)
        else:
            rep_url = min(urls, key=len) if urls else winner.location
        data = dict(winner.raw or {})
        data["merged_from"] = [f.model_dump(mode="json") for f in items if f.id != winner.id]
        data["merged_concept"] = concept
        data["merged_count"] = len(items)
        data["merged_sources"] = sources
        data["affected_urls"] = urls
        if rep_url != winner.location:
            data["location_normalized_from"] = winner.location
        canonical = _canonical_severity(concept)
        new_sev = canonical if canonical is not None else winner.severity
        if new_sev != winner.severity:
            data["severity_normalized_from"] = winner.severity.value
        extra = f" Also reported by {', '.join(sources)} ({len(items)}x, {len(urls)} URL(s))."
        update: dict = {"location": rep_url, "severity": new_sev, "raw": data,
                          "id": stable_id(winner.scanner, f"concept:{concept}")}
        if extra not in (winner.description or ""):
            update["description"] = (winner.description or "") + extra
        merged.append(winner.model_copy(update=update))
    # Central OWASP backfill: same weakness, same category, every scanner.
    return [fill_owasp(f) for f in passthrough] + [fill_owasp(f) for f in merged]


def correlate(findings: list[Finding]) -> list[Finding]:
    """Cross-finding attack chains (same scan, no model needed).

    - robots.txt → /ftp → directory listing: folded into ONE listing
      finding carrying the chain (the standalone robots row added
      nothing once the listing is confirmed).
    - login HTTP 500 → SQLi candidate: the SQLi finding points at the
      login URL for auth-bypass testing.
    No matches = findings untouched.
    """
    def _path(loc: str) -> str:
        try:
            from urllib.parse import urlparse

            return (urlparse(loc or "").path or "/").rstrip("/") or "/"
        except Exception:
            return "/"

    locs = [(f, _path(f.location or "")) for f in findings]
    # Robots + directory listing chain: match the robots finding by path
    # OR title (Nikto titles vary), and listings on the same host.
    def _all_urls(f: Finding) -> list[str]:
        urls = [f.location or ""]
        affected = (f.raw or {}).get("affected_urls")
        if isinstance(affected, list):
            urls += [u for u in affected if isinstance(u, str)]
        return urls

    robots_findings = [
        f for f in findings
        if any(_path(u).lower() == "/robots.txt" for u in _all_urls(f))
        or "robots.txt" in (f.title or "").lower()
    ]
    has_robots = bool(robots_findings)
    ftp_locs = sorted({f.location for f, p in locs if p.lower().rstrip("/") == "/ftp"})
    listings = [f for f in findings if "directory listing" in (f.title or "").lower()
                or "directory index" in (f.title or "").lower()]
    logins_500 = [
        f for f in findings
        # Merged groups bury the login URL in affected_urls while the
        # representative shows /api — check every merged URL too.
        if any("login" in u.lower() for u in _all_urls(f))
        and ("500" in (f.evidence or "") or "error disclosure" in (f.title or "").lower())
    ]
    sqlis = [f for f in findings if "sql injection" in (f.title or "").lower()]

    # Fold into the confirmed listing (one finding, not N unlinked ones):
    # (a) low/info robots rows when robots advertises the listed path;
    # (b) Nikto rows sitting exactly on a confirmed listing path (its
    # "/ftp/ might be interesting" adds nothing next to the verified
    # index). Medium+ rows never fold.
    listing_paths = {_path(x.location or "").lower().rstrip("/") or "/" for x in listings}
    fold_robots = {
        id(f) for f in robots_findings
        if f.severity in (Severity.low, Severity.info)
    } if (has_robots and ftp_locs and listings) else set()
    fold_nikto = {
        id(f) for f in findings
        if f.scanner == "nikto" and f.severity in (Severity.low, Severity.info)
        and f not in listings
        and _path(f.location or "").lower().rstrip("/") in listing_paths
    } if listings else set()
    foldable = fold_robots | fold_nikto

    out: list[Finding] = []
    for f in findings:
        if id(f) in foldable:
            continue
        data = dict(f.raw or {})
        desc = f.description or ""
        changed = False
        if f in listings:
            folded_here = sorted({
                str(r.location) for r in findings
                if id(r) in foldable and str(r.location) != str(f.location)
            })
            if folded_here:
                data["folded_findings"] = folded_here
                changed = True
        if f in listings and has_robots and ftp_locs:
            chain = ["robots.txt"] + ftp_locs + [f.location]
            data["attack_chain"] = chain
            if any(id(r) in fold_robots for r in findings):
                data["robots_folded"] = sorted({str(r.location) for r in robots_findings})
            add = (" Attack chain: robots.txt is fetchable and advertises a path "
                   "that renders a browsable directory index — crawl advertised "
                   "paths instead of ignoring robots output.")
            if add not in desc:
                desc += add
                changed = True
        if f in sqlis and logins_500:
            data["login_500_candidate"] = sorted({str(x.location) for x in logins_500})
            add = (" The login endpoint also returns HTTP 500 — test authentication "
                   "bypass payloads there (e.g. `' OR 1=1' --`).")
            if add not in desc:
                desc += add
                changed = True
        out.append(f.model_copy(update={"description": desc, "raw": data}) if changed else f)
    return out
