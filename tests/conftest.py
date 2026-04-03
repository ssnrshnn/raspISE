"""Shared test fixtures for RaspISE."""
from __future__ import annotations

import asyncio
import os
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Point config at a minimal in-memory YAML before any raspise imports
os.environ["RASPISE_CONFIG"] = os.path.join(os.path.dirname(__file__), "test_config.yaml")

from raspise.db.database import Base
from raspise.db import get_db
from raspise.api import create_api_app
from raspise.api.auth import hash_password
from raspise.db.models import AdminUser


# ---------------------------------------------------------------------------
# Async event-loop fixture (session-scoped so the engine lives across tests)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# In-memory SQLite engine & session
# ---------------------------------------------------------------------------

_test_engine = create_async_engine(
    "sqlite+aiosqlite://",
    echo=False,
    connect_args={"check_same_thread": False},
)
_TestSession = async_sessionmaker(
    bind=_test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest_asyncio.fixture
async def db() -> AsyncGenerator[AsyncSession, None]:
    """Yield a DB session with fresh tables for every test."""
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with _TestSession() as session:
        yield session

    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ---------------------------------------------------------------------------
# FastAPI test client with DB override
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """HTTPX async client wired to the API app with the test DB."""
    app = create_api_app()

    async def _override_get_db():
        yield db

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Convenience: pre-seeded admin user
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def admin_user(db: AsyncSession) -> AdminUser:
    user = AdminUser(
        username="testadmin",
        password_hash=hash_password("Admin1234"),
        email="admin@test.local",
        is_superuser=True,
        enabled=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient, admin_user: AdminUser) -> str:
    """Return a valid JWT for the seeded admin."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "testadmin", "password": "Admin1234"},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]
