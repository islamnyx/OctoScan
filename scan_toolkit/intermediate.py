"""Intermediate representation models — the pre-LLM normalized shape.

These Pydantic models sit between raw scanner output and the final ORM Finding
rows.  Each deterministic tool runner produces ``IRToolOutput`` containing
``IRFinding`` entries; a completed stage bundles its tools into a ``StageIR``
document that gets persisted as JSON and handed to the LLM agent in Phase 4+.

The IR is intentionally looser than the final Finding schema:
  - severity/confidence are optional free strings (the LLM agent maps them to
    the DB enums in later phases).
  - ``raw`` carries through unmapped scanner-specific fields so the LLM can
    inspect them without a lossy normalizer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class IRFinding(BaseModel):
    """One normalized finding from a single tool, pre-LLM."""

    tool: str
    rule_id: str | None = None
    category: str | None = None
    title: str | None = None
    severity: str | None = None
    confidence: str | None = None
    cwe_id: str | None = None

    # location
    file: str | None = None
    line: int | None = None
    end_line: int | None = None

    # detail
    description: str | None = None
    evidence: str | None = None
    recommendation: str | None = None

    # passthrough: scanner-specific fields the LLM might inspect
    raw: dict[str, Any] = Field(default_factory=dict)


class IRToolOutput(BaseModel):
    """Output envelope for one tool invocation in a stage."""

    tool: str
    version: str | None = None
    raw_path: str | None = None
    findings: list[IRFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class StageIR(BaseModel):
    """Complete IR for one scan stage — serialized to JSON for the LLM agent."""

    engagement_id: str
    stage: str
    input: dict[str, Any] = Field(default_factory=dict)
    tools: list[IRToolOutput] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    ran_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
