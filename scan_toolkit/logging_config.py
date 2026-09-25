"""Root logging configuration (Phase 11).

Modules log via ``logging.getLogger(__name__)`` but nothing configured the
root logger, so records fell through to stderr with no timestamps and no
file trail.  ``configure_logging()`` is idempotent and called once from the
CLI root callback before every command:

  * INFO+ to stderr (human-readable, timestamped).
  * INFO+ to ``<data_dir>/toolkit.log`` (rotating, 1 MB x 3) — the durable
    operational trail next to the audit table.
  * Third-party chatter (httpx) held at WARNING.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

_CONFIGURED = False


def configure_logging(data_dir: Path | None = None,
                      level: int = logging.INFO) -> None:
    """Install stderr + rotating-file handlers exactly once per process."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(level)

    stderr = logging.StreamHandler()
    stderr.setFormatter(fmt)
    root.addHandler(stderr)

    if data_dir is not None:
        data_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            data_dir / "toolkit.log",
            maxBytes=1_000_000, backupCount=3, delay=True,
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    _CONFIGURED = True


def reset_for_tests() -> None:  # pragma: no cover - test helper
    """Allow re-configuration (used by tests that isolate DATA_DIR)."""
    global _CONFIGURED
    _CONFIGURED = False
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # noqa: BLE001, S110 - best-effort cleanup
            pass
