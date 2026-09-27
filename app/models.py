from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl, field_validator


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    scanner: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    location: str = ""
    cve: str | None = None
    cvss: float | None = None
    # CWE / OWASP tags (semgrep registry metadata, OSV aliases…).
    # Empty for scanners without taxonomy data; defaults keep old jobs loadable.
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


WEB_SCANNER_CHOICES = {"zap", "headers", "nmap", "testssl", "nikto", "nuclei", "sensitive-files"}
REPO_SCANNER_CHOICES = {"gitleaks", "semgrep", "osv"}


def _clean_scanner_list(v: list[str] | None, allowed: set[str]) -> list[str]:
    if not v:
        return []
    seen: list[str] = []
    for item in v[:10]:
        name = str(item).strip().lower()[:32]
        if name in allowed and name not in seen:
            seen.append(name)
    return seen


class ScanAuth(BaseModel):
    """Session injection for authenticated scans (v1).

    NOT credential login: supply an already-valid session — cookies
    and/or headers (e.g. Authorization: Bearer …). Injected into ZAP
    (replacer rules), nikto (-Add-header), nuclei (-H) and the
    httpx-based scanners (headers, sensitive-file probes).

    Never put passwords here: job.json persists on disk. v1 has no
    form-login automation; log in once in your browser and paste the
    session cookie.
    """

    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)

    # Transport-breaking or smuggling-prone headers must never be
    # scanner-overridden (would corrupt every scanner's requests).
    BLOCKED_HEADERS: ClassVar[frozenset] = frozenset(
        {"host", "content-length", "connection", "transfer-encoding", "upgrade", "expect"}
    )

    @field_validator("cookies", "headers", mode="before")
    @classmethod
    def _clean_map(cls, v: Any) -> dict[str, str]:
        if not v:
            return {}
        if not isinstance(v, dict):
            raise ValueError("must be an object of name/value pairs")
        cleaned: dict[str, str] = {}
        for k, val in list(v.items())[:10]:
            name = str(k).strip()[:128]
            value = str(val).strip()[:1024]
            if not name or not value:
                continue
            if any(c in name for c in ":\r\n \t") or "\n" in value or "\r" in value:
                continue
            if name.lower() in cls.BLOCKED_HEADERS:
                continue
            cleaned[name] = value
        return cleaned


class ScanRequest(BaseModel):
    target_url: HttpUrl
    include_source: bool = False
    repo_url: str | None = None
    # Dashboard scanner picker: subset of web scanners to run.
    # Empty/omitted = run all (backward compatible).
    scanners: list[str] | None = None
    # Authenticated scans (v1 session injection). Omitted = anonymous.
    auth: ScanAuth | None = None

    @field_validator("scanners")
    @classmethod
    def _clean_scanners(cls, v: list[str] | None) -> list[str]:
        return _clean_scanner_list(v, WEB_SCANNER_CHOICES)

    @field_validator("repo_url")
    @classmethod
    def _clean_repo(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()[:512]
        if not v:
            return None
        # Phase-2 source scans are not enabled (stubs.py); reject repo input
        # fail-closed rather than storing an unaudited URL.
        raise ValueError("repo_url not supported in black-box mode")


class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:16])
    target_url: str
    status: ScanStatus = ScanStatus.queued
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    scanners_run: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    # Dashboard selection: which web scanners were requested. Empty = all.
    # Persisted so resume skips correctly and old jobs still load.
    requested_scanners: list[str] = Field(default_factory=list)
    # Session injection for authenticated scans (v1). None = anonymous.
    # Defaults keep old job.json files loadable.
    auth: ScanAuth | None = None
    # Per-scanner coverage metadata (scope actually achieved), kept out of
    # findings so severity counts only reflect real vulns. Old job.json
    # files without this field still load via the default.
    coverage: dict[str, Any] = Field(default_factory=dict)
    # DAST quality gate (FAIL/WARN per ZAP rule, see app/rules.py).
    # Independent of status: completed = scanners ran fine, gate = verdict
    # on findings. Defaults keep old job.json files loadable.
    gate: str = "unknown"
    gate_details: list[str] = Field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


# ---- Phase 2: repo / source scans + BYO AI ----

class RepoScanRequest(BaseModel):
    repo_url: str = Field(max_length=512)
    branch: str | None = Field(default=None, max_length=128)
    include_ai: bool = False
    # Per-scan model override (dashboard's codebase-tab model picker).
    # Falls back to the saved AI config model when omitted.
    ai_model: str | None = Field(default=None, max_length=128)
    # Dashboard scanner picker: subset of {gitleaks, semgrep}.
    # Empty/omitted = run all (backward compatible).
    scanners: list[str] | None = None

    @field_validator("scanners")
    @classmethod
    def _clean_scanners(cls, v: list[str] | None) -> list[str]:
        return _clean_scanner_list(v, REPO_SCANNER_CHOICES)


class AIAnalysis(BaseModel):
    provider: str = ""
    model: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    summary: str = ""
    prioritized_fixes: list[str] = Field(default_factory=list)
    false_positive_notes: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class RepoScanJob(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:16])
    repo_url: str
    branch: str | None = None
    ai_requested: bool = False
    status: ScanStatus = ScanStatus.queued
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    scanners_run: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = 0
    ai: AIAnalysis | None = None
    # Dashboard selection: which source scanners were requested. Empty = all.
    requested_scanners: list[str] = Field(default_factory=list)
    # Rollup summary for the dashboard (counts, dedup stats, secret count).
    # Computed at finalize/pause; defaults keep old job.json files loadable.
    summary: dict[str, Any] = Field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


class AIConfigRequest(BaseModel):
    provider: str = Field(default="", max_length=64)
    base_url: str = Field(default="", max_length=512)
    api_key: str = Field(default="", max_length=512)
    model: str = Field(default="", max_length=128)
    # Provider-profile name (multi-provider support).
    name: str = Field(default="", max_length=64)


class AIProviderRequest(BaseModel):
    name: str = Field(max_length=64)
    provider: str = Field(default="", max_length=64)
    base_url: str = Field(default="", max_length=512)
    api_key: str = Field(default="", max_length=512)
    model: str = Field(default="", max_length=128)
    activate: bool = False


class AIConfigResponse(BaseModel):
    provider: str = ""
    base_url: str = ""
    model: str = ""
    has_key: bool = False
    configured: bool = False


# ---- AI agent (docs/NEXT.md "Islam: API (frozen)") ----
# Frozen keys are exact; extra fields are additive (the page ignores them).


class AgentScanRequest(BaseModel):
    repo_url: str = Field(max_length=512)
    target_url: str | None = Field(default=None, max_length=512)


class AgentStep(BaseModel):
    n: int
    thought: str = ""
    tool: str
    result: str = ""
    args: dict[str, Any] = Field(default_factory=dict)
    status: str = "running"  # running | done | error
    ms: int = 0


class AgentFinding(BaseModel):
    id: str
    title: str
    severity: str
    file: str | None = None
    line: int | None = None
    verdict: str = "review"  # real | false_positive | review
    confidence: float = 0.0
    reason: str = ""
    scanner: str = ""


class AgentFix(BaseModel):
    finding_id: str
    diff: str = ""
    explanation: str = ""
    # true/false only when a semgrep/gitleaks re-scan actually ran;
    # null = not verifiable (OSV, ZAP, rule unavailable, no patch).
    verified: bool | None = None
    file: str | None = None
    rule: str = ""
    note: str = ""


class AgentStats(BaseModel):
    model: str = ""
    calls: int = 0
    median_latency_ms: int = 0
    fallback_used: bool = False
    tokens_in: int = 0
    tokens_out: int = 0


class AgentRun(BaseModel):
    run_id: str = Field(default_factory=lambda: uuid4().hex[:16])
    status: str = "running"  # running | done | failed
    repo_url: str
    target_url: str | None = None
    scan_id: str | None = None
    phase: str = "queued"
    current: str = ""
    steps: list[AgentStep] = Field(default_factory=list)
    findings: list[AgentFinding] = Field(default_factory=list)
    fixes: list[AgentFix] = Field(default_factory=list)
    verdict: str | None = None  # ready | not_ready
    blockers: list[str] = Field(default_factory=list)
    attack_story: str = ""
    stats: AgentStats = Field(default_factory=AgentStats)
    error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
