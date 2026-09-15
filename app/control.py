"""Run controls for long scans (pause / resume / finish).

Scanners run sequentially with a checkpoint after each step, so a scan
can stop between steps and continue later. State lives in a tiny
control.json next to the job: {"paused": bool, "finish": bool}.

- pause: sticky flag. The worker thread sees it between steps, marks
  the job paused and exits. Resume clears it and starts a new worker
  that skips already-finished scanners.
- finish: one-shot. The worker finalizes immediately with whatever
  partial results exist. If the job is already paused (no worker),
  the endpoint finalizes inline.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from app.config import settings

_SCAN_ID_RE = re.compile(r"^[a-fA-F0-9]{8,64}$")


def _path(scan_id: str, kind: str) -> Path:
    if not _SCAN_ID_RE.match(scan_id or "") or ".." in scan_id or "/" in scan_id:
        raise ValueError("invalid scan id")
    if kind == "repo":
        return settings.data_dir / "repos" / scan_id / "control.json"
    return settings.data_dir / "scans" / scan_id / "control.json"


def read(scan_id: str, kind: str) -> dict[str, bool]:
    try:
        raw = json.loads(_path(scan_id, kind).read_text())
        if isinstance(raw, dict):
            return {"paused": bool(raw.get("paused")), "finish": bool(raw.get("finish"))}
    except Exception:
        pass
    return {"paused": False, "finish": False}


def _write(scan_id: str, kind: str, flags: dict[str, bool]) -> None:
    path = _path(scan_id, kind)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(flags))


def request_pause(scan_id: str, kind: str) -> None:
    flags = read(scan_id, kind)
    flags["paused"] = True
    _write(scan_id, kind, flags)


def request_finish(scan_id: str, kind: str) -> None:
    flags = read(scan_id, kind)
    flags["finish"] = True
    _write(scan_id, kind, flags)


def clear_pause(scan_id: str, kind: str) -> None:
    flags = read(scan_id, kind)
    flags["paused"] = False
    _write(scan_id, kind, flags)


def clear_all(scan_id: str, kind: str) -> None:
    try:
        _path(scan_id, kind).unlink(missing_ok=True)
    except Exception:
        pass
