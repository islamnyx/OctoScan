"""API traffic primitives — HAR parsing, passive checks, multi-role diff.

Workflow (Phase 7): the analyst drives the app through mitmdump once per
test account, saves one HAR per role into
``<data_dir>/engagements/<id>/flows/<role>.har`` (``anonymous.har`` optional
baseline), and the API stage picks them up.  Automated app driving is
Phase 8 (emulator) work — this module stays honest about that.

Contents:
  * ``ApiCall`` — one request/response pair (Pydantic, JSON-serialisable).
  * ``parse_har()`` — HAR dict -> list[ApiCall] (bodies truncated).
  * ``passive_checks()`` — deterministic transport/secret hygiene findings.
  * ``compare_roles()`` — multi-role access diff -> candidate auth findings.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from scan_toolkit.intermediate import IRFinding

log = logging.getLogger(__name__)

_BODY_LIMIT = 2000  # chars of body kept per call (keeps the IR small)

# Segments that look like object IDs get normalised to {id} for endpoint keys.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _looks_like_id(segment: str) -> bool:
    if segment.isdigit():
        return True
    if _UUID_RE.match(segment):
        return True
    # Mongo-style ObjectId / long opaque tokens in paths.
    if re.fullmatch(r"[0-9a-fA-F]{16,}", segment):
        return True
    if len(segment) >= 20 and re.fullmatch(r"[A-Za-z0-9_\-]+", segment):
        return True
    return False


# ---------------------------------------------------------------------------
# ApiCall
# ---------------------------------------------------------------------------

class ApiCall(BaseModel):
    """One captured HTTP request/response pair."""

    method: str
    url: str
    path: str
    query: dict[str, str] = Field(default_factory=dict)
    req_headers: dict[str, str] = Field(default_factory=dict)
    req_body: str | None = None
    status: int | None = None
    resp_headers: dict[str, str] = Field(default_factory=dict)
    resp_body: str | None = None
    role: str | None = None  # filled in by the caller (HAR filename stem)

    @property
    def endpoint_key(self) -> str:
        """METHOD + path with ID-like segments normalised — for role diffing."""
        parts = [p for p in self.path.split("/") if p]
        norm = [("{id}" if _looks_like_id(p) else p) for p in parts]
        return f"{self.method.upper()} /{'/'.join(norm)}"

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300


# ---------------------------------------------------------------------------
# HAR parsing
# ---------------------------------------------------------------------------

def _headers_to_dict(headers: list[dict] | dict | None) -> dict[str, str]:
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    out: dict[str, str] = {}
    for h in headers:
        name = str(h.get("name", "")).lower()
        if name and name not in out:  # keep first occurrence (e.g. set-cookie)
            out[name] = str(h.get("value", ""))
    return out


def parse_har(har: dict, *, role: str | None = None) -> list[ApiCall]:
    """Parse a HAR dict (mitmdump --savehar output) into ApiCall entries.

    Raises ValueError on wrong shape — fail loudly, never silently scan
    an empty capture.
    """
    if not isinstance(har, dict) or not isinstance(har.get("log"), dict):
        raise ValueError("HAR must be an object with a 'log' object")
    entries = har["log"].get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("HAR log.entries must be a list")

    calls: list[ApiCall] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = str(req.get("url", ""))
        parsed = urlparse(url)
        query: dict[str, str] = {}
        for q in req.get("queryString") or []:
            if isinstance(q, dict) and q.get("name"):
                query[str(q["name"])] = str(q.get("value", ""))
        post = req.get("postData") or {}
        req_body = post.get("text")
        content = resp.get("content") or {}
        resp_body = content.get("text")
        calls.append(ApiCall(
            method=str(req.get("method", "GET")).upper(),
            url=url,
            path=parsed.path or "/",
            query=query,
            req_headers=_headers_to_dict(req.get("headers")),
            req_body=str(req_body)[:_BODY_LIMIT] if req_body else None,
            status=int(resp["status"]) if isinstance(resp.get("status"), int) else None,
            resp_headers=_headers_to_dict(resp.get("headers")),
            resp_body=str(resp_body)[:_BODY_LIMIT] if resp_body else None,
            role=role,
        ))
    return calls


def load_role_captures(flows_dir: Path) -> dict[str, list[ApiCall]]:
    """Load ``<role>.har`` files from a flows dir -> {role: calls}.

    Returns {} when the dir has no HAR files (caller records a note and
    degrades — traffic capture is analyst-driven, absence is normal).
    A file that exists but fails to parse raises ValueError (fail loudly).
    """
    captures: dict[str, list[ApiCall]] = {}
    if not flows_dir.exists():
        return captures
    for har_path in sorted(flows_dir.glob("*.har")):
        role = har_path.stem
        try:
            har = json.loads(har_path.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(f"flows/{har_path.name} is not valid JSON: {exc}") from exc
        captures[role] = parse_har(har, role=role)
        log.info("Loaded %d calls for role %r from %s", len(captures[role]), role, har_path.name)
    return captures


# ---------------------------------------------------------------------------
# Passive checks (deterministic — no LLM needed)
# ---------------------------------------------------------------------------

_SENSITIVE_QUERY_KEYS = frozenset({
    "token", "authtoken", "auth_token", "access_token", "id_token",
    "session", "sessionid", "session_id", "jsessionid", "api_key", "apikey",
    "password", "secret", "auth",
})


def passive_checks(calls: list[ApiCall]) -> list[IRFinding]:
    """Transport + secret-hygiene checks over captured calls.

    Deliberately narrow: cleartext HTTP, secrets in URL query strings.
    Everything else (auth logic, IDOR) belongs to the role diff + LLM.
    """
    findings: list[IRFinding] = []
    seen: set[tuple[str, str]] = set()  # (check, endpoint_key) dedupe

    for call in calls:
        scheme = urlparse(call.url).scheme.lower()
        host = urlparse(call.url).hostname or ""
        key = call.endpoint_key

        # 1. Cleartext HTTP (localhost is lower risk — analyst proxying).
        if scheme == "http" and ("cleartext", key) not in seen:
            seen.add(("cleartext", key))
            local = host in ("127.0.0.1", "localhost", "10.0.2.2")
            findings.append(IRFinding(
                tool="mitmproxy",
                rule_id="cleartext-http",
                category="insecure_transport",
                title=f"Cleartext HTTP traffic to {host or 'unknown host'}",
                severity="low" if local else "medium",
                confidence="high",  # observed on the wire, not inferred
                file=None,
                description=(
                    f"{call.method} {call.url} was sent over unencrypted HTTP. "
                    + ("Loopback address — likely proxy/capture artefact, verify "
                       "the production build does not allow cleartext. "
                       if local else "Credentials or tokens on this channel "
                       "can be intercepted on the network. ")
                ),
                evidence=f"{call.method} {call.url} (role={call.role or 'unknown'})",
                recommendation=(
                    "Enforce HTTPS for all API traffic (NSC / ATS config) and "
                    "set cleartextTrafficPermitted=false."
                ),
                raw={"host": host, "url": call.url, "role": call.role},
            ))

        # 2. Secrets / tokens in URL query (logged by servers/proxies).
        leaked = sorted(k for k in call.query if k.lower() in _SENSITIVE_QUERY_KEYS)
        if leaked and ("query-secret", key) not in seen:
            seen.add(("query-secret", key))
            findings.append(IRFinding(
                tool="mitmproxy",
                rule_id="secret-in-query",
                category="sensitive_data_exposure",
                title=f"Sensitive value in URL query: {', '.join(leaked)}",
                severity="high",
                confidence="high",
                cwe_id="CWE-598",
                file=None,
                description=(
                    f"{call.endpoint_key} places {', '.join(leaked)} in the URL "
                    "query string, where it lands in server logs, proxy logs, "
                    "and analytics. Query values are also redacted from the "
                    "stored evidence — see the raw HAR for the original."
                ),
                evidence=(
                    f"{call.method} {call.path} "
                    f"(role={call.role or 'unknown'}; keys=[{', '.join(leaked)}])"
                ),
                recommendation=(
                    "Move secrets/tokens into headers (Authorization) or the "
                    "POST body; never put them in URLs."
                ),
                raw={"endpoint": key, "keys": leaked, "role": call.role},
            ))
    return findings


# ---------------------------------------------------------------------------
# Multi-role comparison
# ---------------------------------------------------------------------------

def compare_roles(captures: dict[str, list[ApiCall]]) -> list[IRFinding]:
    """Diff per-role captures -> candidate broken-access-control findings.

    These are TRIAGE CANDIDATES, not confirmed vulns — every finding says
    so and carries low confidence.  Rules:

    * endpoint reachable (2xx) with role ``anonymous`` -> medium.
    * object-level endpoint (``{id}`` in key) reachable (2xx) by 2+ roles,
      or identical bodies served to different roles -> low, verify manually.
    """
    findings: list[IRFinding] = []
    if len(captures) < 1:
        return findings

    # endpoint -> role -> list of successful calls
    matrix: dict[str, dict[str, list[ApiCall]]] = defaultdict(lambda: defaultdict(list))
    for role, calls in captures.items():
        for call in calls:
            if call.ok:
                matrix[call.endpoint_key][role].append(call)

    for endpoint in sorted(matrix):
        roles_ok = sorted(matrix[endpoint])
        sample = matrix[endpoint][roles_ok[0]][0]

        # 1. No-auth access.
        if "anonymous" in matrix[endpoint]:
            findings.append(IRFinding(
                tool="role_diff",
                rule_id="anonymous-access",
                category="broken_access_control",
                title=f"Endpoint accessible without authentication: {endpoint}",
                severity="medium",
                confidence="medium",
                cwe_id="CWE-862",
                file=None,
                description=(
                    f"{endpoint} returned 2xx for the unauthenticated "
                    "(anonymous) capture. CANDIDATE — verify whether this "
                    "endpoint is intentionally public; if it serves "
                    "user-specific data it is missing authorization."
                ),
                evidence=(
                    f"{endpoint} -> 2xx for roles: {', '.join(roles_ok)} "
                    f"(sample: {sample.method} {sample.path} "
                    f"status={sample.status})"
                ),
                recommendation=(
                    "Confirm the endpoint is meant to be public; otherwise "
                    "require authentication and enforce authorization checks."
                ),
                raw={"endpoint": endpoint, "roles_2xx": roles_ok},
            ))
            continue

        # 2. Object-level endpoint shared across roles.
        if "{id}" in endpoint and len(roles_ok) >= 2:
            bodies = {
                (c.resp_body or "")[:200]
                for role in roles_ok
                for c in matrix[endpoint][role]
            }
            same_body = len(bodies) == 1
            findings.append(IRFinding(
                tool="role_diff",
                rule_id="shared-object-endpoint",
                category="broken_access_control",
                title=f"Object endpoint reachable by multiple roles: {endpoint}",
                severity="low",
                confidence="low",
                cwe_id="CWE-639",
                file=None,
                description=(
                    f"{endpoint} returned 2xx for roles {', '.join(roles_ok)}. "
                    + ("All roles received byte-identical response bodies — "
                       "possible missing object-level authorization (IDOR). "
                       if same_body else "Response bodies differ per role, "
                       "which suggests some authorization exists — still "
                       "worth a manual IDOR check with swapped object IDs. ")
                    + "CANDIDATE — verify manually by replaying with another "
                    "user's object ID."
                ),
                evidence=(
                    f"{endpoint} -> 2xx for roles: {', '.join(roles_ok)}; "
                    f"identical_bodies={same_body}"
                ),
                recommendation=(
                    "Replay the request with a different user's object ID "
                    "under each role; enforce server-side ownership checks."
                ),
                raw={
                    "endpoint": endpoint,
                    "roles_2xx": roles_ok,
                    "identical_bodies": same_body,
                },
            ))
    return findings


def access_matrix(captures: dict[str, list[ApiCall]]) -> dict[str, dict[str, int]]:
    """Endpoint -> role -> count of 2xx calls. Stored in IR notes/raw for the LLM."""
    matrix: dict[str, dict[str, int]] = defaultdict(dict)
    for role, calls in captures.items():
        per_endpoint: dict[str, int] = defaultdict(int)
        for call in calls:
            if call.ok:
                per_endpoint[call.endpoint_key] += 1
        for endpoint, count in per_endpoint.items():
            matrix[endpoint][role] = count
    return {ep: dict(roles) for ep, roles in sorted(matrix.items())}
