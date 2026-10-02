"""Live verification probes: confirm scanner claims with differential tests.

Two probes, both read-only and bounded (never brute-force, never mutate):

- confirm_sqli: re-issues the flagged GET parameter twice — once benign,
  once with a single quote — and compares. benign normal + quote 500 =
  confirmed; anything else = unconfirmed (kept, flagged as such).
- probe_login: follows an auth-error-needs-review tag with a targeted
  injection check on the login endpoint: baseline invalid credentials vs
  classic bypass payloads. Outcomes: bypass-indicated (token/session
  returned), error-signal (500), or no-difference.

Results land in finding raw (sqli_confirmation / login_probe) and in the
description. Probe failures are silent (finding kept as-is) — verification
is advisory, never load-bearing.
"""

from __future__ import annotations

import re
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.models import Finding, ScanAuth, Severity

MAX_SQLI_CONFIRMS = 3
MAX_LOGIN_PROBES = 2
TIMEOUT_S = 10.0


def _session(auth: ScanAuth | None):
    import httpx

    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    if auth:
        for k, v in (auth.headers or {}).items():
            if k.lower() != "cookie":
                headers[k] = v
        for k, v in (auth.cookies or {}).items():
            cookies[k] = v
        for k, v in (auth.headers or {}).items():
            if k.lower() == "cookie" and "=" in v:
                for pair in v.split(";"):
                    if "=" in pair:
                        kk, vv = pair.split("=", 1)
                        cookies.setdefault(kk.strip(), vv.strip())
    return headers, cookies


def _with_param(location: str, param: str, value: str) -> str | None:
    try:
        parts = urlsplit(location)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        if param not in query:
            return None
        query[param] = value
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    except Exception:
        return None


def confirm_sqli(finding: Finding, auth: ScanAuth | None = None) -> dict:
    """Two-stage differential check for a ZAP SQLi finding. Never raises.

    Stage 1 (error-based): benign input vs ZAP's recorded attack payload.
    200-normal vs 500 = "error-confirmed".
    Stage 2 (boolean-based): benign vs tautology `' OR '1'='1`. Same 200
    but a much larger result set = "boolean-indicated".
    Either runs at most 3 read-only GETs total. Unconfirmed findings are
    kept as-is — verification annotates, never removes.
    """
    result: dict = {"confirmed": False, "result": "unconfirmed", "method": "differential-get"}
    try:
        import httpx

        raw = finding.raw or {}
        param = str(raw.get("param") or "")
        if not param:
            result["note"] = "no injectable param recorded; skipped"
            return result
        # Replay ZAP's own recorded attack payload first (it produced the
        # 500); fall back to a lone quote. Benign baseline for contrast.
        attack = str(raw.get("attack") or "'")[:50]
        benign = _with_param(finding.location or "", param, "ZapTest0")
        payload = _with_param(finding.location or "", param, attack)
        tautology = _with_param(finding.location or "", param, "' OR '1'='1")
        if not benign or not payload:
            result["note"] = "param not in URL query; skipped"
            return result
        headers, cookies = _session(auth)
        rb = httpx.get(benign, headers=headers or None, cookies=cookies or None,
                       follow_redirects=True, timeout=TIMEOUT_S)
        rp = httpx.get(payload, headers=headers or None, cookies=cookies or None,
                       follow_redirects=True, timeout=TIMEOUT_S)
        stack = _stack_hint(dict(rb.headers or {}))
        result.update({
            "param": param,
            "attack_replayed": attack,
            "benign_status": rb.status_code,
            "payload_status": rp.status_code,
            "benign_bytes": len(rb.content),
            "payload_bytes": len(rp.content),
            "stack": stack,
        })
        error_hit = 200 <= rb.status_code < 500 and rp.status_code == 500
        bool_hit = False
        if tautology:
            rt = httpx.get(tautology, headers=headers or None, cookies=cookies or None,
                           follow_redirects=True, timeout=TIMEOUT_S)
            result.update({"tautology_status": rt.status_code, "tautology_bytes": len(rt.content)})
            bool_hit = (
                rt.status_code == 200 and rb.status_code == 200
                and len(rt.content) > max(500, len(rb.content) * 3)
            )
        if error_hit and bool_hit:
            result.update(result="error-confirmed+boolean-indicated", confirmed=True)
            result["note"] = (
                f"benign -> HTTP {rb.status_code} ({len(rb.content)} B); attack replay -> "
                f"HTTP 500 (backend error on unescaped input); tautology -> HTTP 200 "
                f"({len(rt.content)} B, full result set): error-based AND boolean-based SQLi"
            )
        elif error_hit:
            result.update(result="error-confirmed", confirmed=True)
            result["note"] = (
                f"benign input -> HTTP {rb.status_code}, attack replay -> HTTP 500: "
                "backend error on unescaped input, SQLi error-confirmed"
            )
        elif bool_hit:
            result.update(result="boolean-indicated", confirmed=True)
            result["note"] = (
                f"benign -> HTTP {rb.status_code} ({len(rb.content)} B), tautology -> "
                f"HTTP 200 ({len(rt.content)} B): result-set superset without error, "
                "boolean-based SQLi indicated"
            )
        else:
            result["note"] = (
                f"benign -> HTTP {rb.status_code}, attack -> HTTP {rp.status_code}: "
                "no error or boolean differential, unconfirmed (ZAP alert kept as-is)"
            )
    except Exception as exc:
        result["note"] = f"probe failed ({str(exc)[:120]}); kept as-is"
    return result


def _stack_hint(headers: dict) -> str:
    """Stack guess from response headers for stack-specific remediation."""
    blob = " ".join(str(v) for v in (headers or {}).values()).lower()
    if "express" in blob:
        return "node-express"
    if "django" in blob or "wsgiserver" in blob:
        return "python-django"
    if "php" in blob or "laravel" in blob:
        return "php"
    if "spring" in blob or "tomcat" in blob or "jboss" in blob:
        return "java"
    if "asp.net" in blob or "iis" in blob or "kestrel" in blob:
        return "dotnet"
    return "generic"


STACK_SQLI_FIX = {
    "node-express": (
        "Node/Express + Sequelize: never concatenate input into SQL — use replacements "
        "(`sequelize.query('... WHERE name = :q', { replacements: { q } })`) or bound "
        "model parameters (`{ where: { name: q } }`). Validate + allow-list input server-side."
    ),
    "python-django": (
        "Django: use ORM filters (`Model.objects.filter(name=q)`) or parameterized "
        "raw SQL (`cursor.execute('... WHERE name = %s', [q])`) — never %/f-string "
        "interpolation into queries."
    ),
    "php": (
        "PHP: use PDO prepared statements (`$pdo->prepare('... WHERE name = ?')` + "
        "`execute([$q])`) — never interpolate $_GET/$_POST into SQL."
    ),
    "java": (
        "Java: use PreparedStatement with ? placeholders and setString() — never "
        "string-concatenate request parameters into SQL."
    ),
    "dotnet": (
        ".NET: use parameterized SqlCommand (`@q` + Parameters.AddWithValue) or an ORM "
        "with bound parameters — never interpolate input into SQL text."
    ),
    "generic": (
        "Use parameterized queries / prepared statements so user input is never "
        "concatenated into SQL. Validate + type-check input server-side, run the DB "
        "user with least privilege, and treat WAF rules as defense-in-depth only."
    ),
}


def _login_token(payload: object) -> str | None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(key, str) and key.lower().replace("-", "").replace("_", "") in (
                    "token", "accesstoken", "access_token", "jwt", "authtoken", "sessionid", "session"):
                if isinstance(value, str) and value.strip():
                    return value.strip()
        for value in payload.values():
            found = _login_token(value)
            if found:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = _login_token(item)
            if found:
                return found
    return None


def probe_login(login_url: str, auth: ScanAuth | None = None) -> dict:
    """Targeted injection check on a login endpoint. Never raises.

    Baseline invalid credentials vs two classic payloads. Exactly three
    POSTs, JSON first with form fallback.
    """
    result: dict = {"tested": login_url, "outcome": "no-difference", "attempts": []}
    try:
        import httpx

        headers, cookies = _session(auth)
        base_headers = {"Content-Type": "application/json", **headers}

        def _try(body: dict, form: bool = False) -> tuple[int, str, bool]:
            try:
                if form:
                    r = httpx.post(login_url, data=body, headers=headers or None,
                                   cookies=cookies or None, follow_redirects=True, timeout=TIMEOUT_S)
                else:
                    r = httpx.post(login_url, json=body, headers=base_headers or None,
                                   cookies=cookies or None, timeout=TIMEOUT_S)
            except Exception as exc:
                return -1, str(exc)[:100], False
            try:
                token = _login_token(r.json())
            except Exception:
                token = None
            snippet = ""
            try:
                text = r.text or ""
                m = re.search(r"(exception|traceback|syntax error|SQL|ORA-|token)[^<>]{0,120}", text, re.I)
                snippet = m.group(0)[:120] if m else text[:120]
            except Exception:
                pass
            return r.status_code, snippet, bool(token)

        baseline = {"email": "probe.invalid@example.com", "password": "WrongPass0!"}
        st, snip, tok = _try(baseline)
        if st == -1:
            # JSON shape rejected outright — retry form-encoded once.
            st, snip, tok = _try({"username": baseline["email"], "password": baseline["password"]}, form=True)
        result["attempts"].append({"payload": "baseline-invalid", "status": st, "token": tok})
        if st == -1:
            result["outcome"] = "unreachable"
            result["note"] = f"login endpoint not reached ({snip}); kept as-is"
            return result

        payloads = [
            {"email": "' OR 1=1-- -", "password": "x"},
            {"email": "admin@juice-sh.op'-- -", "password": "x"},
        ]
        for i, p in enumerate(payloads[:MAX_LOGIN_PROBES]):
            st, snip, tok = _try(p)
            result["attempts"].append({"payload": f"injection-{i + 1}", "status": st, "token": tok})
            if tok:
                result["outcome"] = "bypass-indicated"
                result["note"] = (
                    f"injection payload {i + 1} returned a session token "
                    f"(HTTP {st}): authentication bypass indicated — rotate credentials and fix"
                )
                return result
            if st == 500:
                result["outcome"] = "error-signal"
                result["note"] = (
                    f"injection payload {i + 1} -> HTTP 500 "
                    f"({snip[:80]}): backend error on crafted input, error-based signal"
                )
        if result["outcome"] == "no-difference":
            result["note"] = (
                "baseline and injection payloads answered alike "
                f"({result['attempts'][0]['status']}): no bypass signal; tag kept for manual review"
            )
    except Exception as exc:
        result["outcome"] = "probe-failed"
        result["note"] = f"probe failed ({str(exc)[:120]}); kept as-is"
    return result


def _is_sqli_candidate(f: Finding) -> bool:
    plugin = str((f.raw or {}).get("pluginid") or "")
    return (
        f.scanner == "zap"
        and plugin in ("40018", "40019", "40020", "40021", "40022")
        and f.severity in (Severity.high, Severity.critical)
    )


def _login_targets(f: Finding) -> list[str]:
    targets = [f.location or ""]
    affected = (f.raw or {}).get("affected_urls")
    if isinstance(affected, list):
        targets += [u for u in affected if isinstance(u, str)]
    seen: list[str] = []
    for u in targets:
        if "/login" in u.lower() or "/signin" in u.lower().replace("-", ""):
            if u not in seen:
                seen.append(u)
    return seen[:MAX_LOGIN_PROBES]


def verify_findings(
    findings: list[Finding],
    auth: ScanAuth | None = None,
    stop_check: Callable[[], object] | None = None,
) -> list[Finding]:
    """Confirm SQLi + probe tagged logins. Bounded, fail-open, in place order."""
    out: list[Finding] = []
    sqli_done = 0
    login_done = 0
    for f in findings:
        if stop_check and stop_check():
            out.append(f)
            continue
        raw = dict(f.raw or {})
        desc = f.description or ""
        rec = f.recommendation or ""
        changed = False
        if _is_sqli_candidate(f) and sqli_done < MAX_SQLI_CONFIRMS and "sqli_confirmation" not in raw:
            sqli_done += 1
            conf = confirm_sqli(f, auth)
            raw["sqli_confirmation"] = conf
            if conf.get("confirmed"):
                add = f" Live verification ({conf.get('result')}): {conf.get('note')}"
                if add not in desc:
                    desc += add
                    changed = True
                # Stack-specific remediation beats the generic boilerplate.
                stack_fix = STACK_SQLI_FIX.get(conf.get("stack") or "generic")
                if stack_fix:
                    raw["sqli_stack"] = conf.get("stack")
                    rec = f"Stack-specific fix ({conf.get('stack')}): {stack_fix}"
                    changed = True
        tags = raw.get("review_tags") or []
        if "auth-error-needs-review" in tags and login_done < MAX_LOGIN_PROBES:
            for url in _login_targets(f):
                if login_done >= MAX_LOGIN_PROBES:
                    break
                if stop_check and stop_check():
                    break
                login_done += 1
                probe = probe_login(url, auth)
                probes = list(raw.get("login_probes") or [])
                probes.append(probe)
                raw["login_probes"] = probes
                add = f" Login probe ({probe.get('outcome')}): {probe.get('note')}"
                if add not in desc:
                    desc += add
                    changed = True
        out.append(f.model_copy(update={"description": desc, "raw": raw, "recommendation": rec}) if changed else f)
    return out
