"""Live scan activity feed (Phase UX).

In-memory, best-effort: pipeline + scanners log what they are doing
("zap: spider running", "AI: reading app/views.py") and the status page
polls GET /api/{scans,repo-scans}/{id}/activity. Lost on restart —
fine, a restarted scan's threads are dead anyway.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Literal

_lock = threading.Lock()
_logs: dict[str, deque] = {}
_current: dict[str, str] = {}

Kind = Literal["info", "done", "error", "current"]

MAX_ENTRIES = 300


def log(scan_id: str, message: str, kind: Kind = "info") -> None:
    if not scan_id or not message:
        return
    entry = {"ts": round(time.time(), 3), "kind": kind, "msg": str(message)[:400]}
    with _lock:
        _logs.setdefault(scan_id, deque(maxlen=MAX_ENTRIES)).append(entry)


def current(scan_id: str, message: str) -> None:
    """Set the 'what is happening right now' line and log it."""
    if not scan_id or not message:
        return
    with _lock:
        _current[scan_id] = str(message)[:400]
    log(scan_id, message, kind="current")


def feed(scan_id: str) -> dict:
    with _lock:
        events = list(_logs.get(scan_id, ()))
        cur = _current.get(scan_id, "")
    return {"scan_id": scan_id, "current": cur, "events": events}


def clear(scan_id: str) -> None:
    with _lock:
        _logs.pop(scan_id, None)
        _current.pop(scan_id, None)
