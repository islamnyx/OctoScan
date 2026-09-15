from datetime import datetime, timezone
from enum import Enum
from typing import Any
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
    raw: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    target_url: HttpUrl
    include_source: bool = False
    repo_url: str | None = None

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
