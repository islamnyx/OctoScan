"""Shared pytest fixtures — all use an in-memory SQLite DB (no data/ touch)."""

import pytest
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from scan_toolkit import models  # noqa: F401 — registers models on Base.metadata
from scan_toolkit import queue as _queue  # noqa: F401 — registers ScanJob on Base.metadata
from scan_toolkit.db import Base, create_engine, session_factory

_IN_MEMORY_KWARGS = {"connect_args": {"check_same_thread": False}, "poolclass": StaticPool}


@pytest.fixture()
def db_engine():
    """In-memory SQLAlchemy engine (FK pragma + StaticPool via db.create_engine)."""
    eng = create_engine("sqlite+pysqlite:///:memory:", **_IN_MEMORY_KWARGS)
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db_session(db_engine) -> Session:
    """Session using the same factory the CLI uses (expire_on_commit=False)."""
    session = session_factory(db_engine)()
    yield session
    session.rollback()
    session.close()