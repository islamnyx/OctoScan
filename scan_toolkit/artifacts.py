"""Engagement artifact storage — client files get COPIED into a per-engagement
folder so scans are reproducible from the folder alone, never from a
referenced-but-moved source path.

Layout (under ``data_dir/engagements/<engagement_id>/``)::

    intake.json           manifest snapshot of Engagement + IntakeChecklist
    binary/<name>         the APK/IPA (copied)
    docs/<name|contents>  API docs — a file, or a directory's contents
    credentials.json      test credentials (sensitive — lives under the
                          gitignored data/ tree, never committed)
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from scan_toolkit.config import get_settings

# ids are hex uuid4().hex[:12] that WE generate — reject anything free-form
# (path-traversal guard, mirrors app/store.py)
_ENG_ID_RE = re.compile(r"^[a-fA-F0-9]{8,16}$")


def validate_engagement_id(engagement_id: str) -> str:
    if not _ENG_ID_RE.match(engagement_id or "") or ".." in engagement_id:
        raise ValueError(f"invalid engagement id: {engagement_id!r}")
    return engagement_id


def engagement_dir(engagement_id: str) -> Path:
    validate_engagement_id(engagement_id)
    return get_settings().data_dir / "engagements" / engagement_id


def _ensure(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def store_binary(engagement_id: str, source: Path) -> tuple[Path, str]:
    """Copy the APK/IPA into the engagement folder. Returns (stored_path, original_name)."""
    source = source.resolve()
    dest = _ensure(engagement_dir(engagement_id) / "binary") / source.name
    shutil.copy2(source, dest)
    return dest.resolve(), source.name


def store_docs(engagement_id: str, source: Path) -> Path:
    """Copy a docs file or a docs directory into the engagement folder."""
    source = source.resolve()
    docs_dir = engagement_dir(engagement_id) / "docs"
    if source.is_dir():
        dest = docs_dir / source.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(source, dest)
        return dest.resolve()
    _ensure(docs_dir)
    dest = docs_dir / source.name
    shutil.copy2(source, dest)
    return dest.resolve()


def store_credentials(engagement_id: str, source: Path) -> tuple[Path, str]:
    """Copy test credentials to a fixed name for downstream parsing. Returns (path, original_name)."""
    source = source.resolve()
    dest = _ensure(engagement_dir(engagement_id)) / "credentials.json"
    shutil.copy2(source, dest)
    return dest.resolve(), source.name


def write_manifest(engagement_id: str, payload: dict) -> Path:
    """Snapshot Engagement + IntakeChecklist to intake.json for reproducibility."""
    dest = engagement_dir(engagement_id) / "intake.json"
    _ensure(dest.parent)
    dest.write_text(json.dumps(payload, indent=2))
    return dest.resolve()