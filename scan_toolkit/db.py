"""SQLAlchemy engine + session management.

The engine is created via an explicit URL — there is no module-level singleton.
Tests inject their own in-memory engine; CLI commands use get_settings().db_url.

SQLite FK enforcement is OFF by default; we enable it per-connection via a
PRAGMA so cascade-delete behaviour is reliable.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


def create_engine(url: str, **kwargs) -> sa.engine.Engine:
    """Create an engine with FK enforcement on.

    Extra kwargs are forwarded to ``sqlalchemy.create_engine`` (e.g.
    ``connect_args={"check_same_thread": False}, poolclass=StaticPool`` for
    in-memory tests)."""
    eng = sa.create_engine(url, **kwargs)

    @event.listens_for(eng, "connect")
    def _set_fk_pragma(dbapi_conn, _connection_record):  # noqa: ANN001
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return eng


def session_factory(engine: sa.engine.Engine) -> sessionmaker[Session]:
    # expire_on_commit=False: keeps objects (and their PK ids) usable after the
    # session commits/closes, so a CLI flow can create a row, close, then act on
    # its id. Trade-off: stale reads within one long-lived session if another
    # connection writes — negligible for a single-user local toolkit.
    return sessionmaker(bind=engine, expire_on_commit=False)


def init_db(url: str | None = None) -> sa.engine.Engine:
    """Create tables (idempotent).  Imports all models so Base.metadata is populated."""
    from scan_toolkit.config import ensure_runtime_dirs, get_settings  # noqa: F811
    import scan_toolkit.models  # noqa: F401 — triggers model registration on Base.metadata

    ensure_runtime_dirs()
    target_url = url or get_settings().db_url
    engine = create_engine(target_url)
    Base.metadata.create_all(engine)
    return engine


@contextmanager
def session_scope(engine: sa.engine.Engine) -> Generator[Session, None, None]:
    """Transactional context manager — commits on clean exit, rolls back on error."""
    factory = session_factory(engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()