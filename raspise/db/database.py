"""SQLAlchemy async database engine and session factory."""
from __future__ import annotations

import threading

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from raspise.config import get_config


class Base(DeclarativeBase):
    pass


# Lazy engine singleton — created on first access, not at import time
_engine = None
_session_factory = None
_init_lock = threading.Lock()


def _get_engine():
    global _engine
    if _engine is None:
        with _init_lock:
            if _engine is None:
                cfg = get_config()
                _engine = create_async_engine(
                    cfg.database.url,
                    echo=cfg.server.debug,
                    pool_pre_ping=True,
                    connect_args={"check_same_thread": False},
                )

                # Enable WAL mode and busy timeout for better
                # concurrent read/write performance on SQLite
                @event.listens_for(_engine.sync_engine, "connect")
                def _set_sqlite_pragmas(dbapi_conn, connection_record):
                    cursor = dbapi_conn.cursor()
                    cursor.execute("PRAGMA journal_mode=WAL")
                    cursor.execute("PRAGMA busy_timeout=5000")
                    cursor.close()
    return _engine


def _get_session_factory():
    global _session_factory
    if _session_factory is None:
        with _init_lock:
            if _session_factory is None:
                _session_factory = async_sessionmaker(
                    bind=_get_engine(),
                    class_=AsyncSession,
                    expire_on_commit=False,
                )
    return _session_factory


# Public accessors — backwards compatible
@property
def _engine_prop():
    return _get_engine()


class _EngineProxy:
    """Proxy that lazily creates the engine on first attribute access."""
    def __getattr__(self, name):
        return getattr(_get_engine(), name)

    def __call__(self, *args, **kwargs):
        return _get_engine()(*args, **kwargs)


class _SessionProxy:
    """Proxy that lazily creates the session factory on first call."""
    def __call__(self, *args, **kwargs):
        return _get_session_factory()(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(_get_session_factory(), name)


engine = _EngineProxy()
AsyncSessionLocal = _SessionProxy()


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async session."""
    async with _get_session_factory()() as session:
        yield session


async def init_db() -> None:
    """Create all tables (run once on startup)."""
    async with _get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
