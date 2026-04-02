"""SQLAlchemy async database engine and session factory."""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from raspise.config import get_config


class Base(DeclarativeBase):
    pass


def _make_engine():
    cfg = get_config()
    return create_async_engine(
        cfg.database.url,
        echo=cfg.server.debug,
        pool_pre_ping=True,
    )


# Module-level singletons
engine = _make_engine()
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async session."""
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    """Create all tables (run once on startup)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
