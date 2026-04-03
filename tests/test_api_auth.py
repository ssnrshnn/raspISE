"""Tests for REST API auth flow and basic CRUD endpoints."""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from raspise.api.auth import hash_password, verify_password, create_access_token
from raspise.db.models import AdminUser


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_and_verify(self):
        hashed = hash_password("Secret1234")
        assert verify_password("Secret1234", hashed) is True

    def test_wrong_password(self):
        hashed = hash_password("Secret1234")
        assert verify_password("WrongPassword1", hashed) is False

    def test_unique_hashes(self):
        h1 = hash_password("Same1234")
        h2 = hash_password("Same1234")
        assert h1 != h2  # bcrypt salts differ


# ---------------------------------------------------------------------------
# JWT token
# ---------------------------------------------------------------------------

class TestJWT:
    def test_create_token_returns_string(self):
        token = create_access_token("admin")
        assert isinstance(token, str)
        assert len(token) > 0


# ---------------------------------------------------------------------------
# Login endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestLogin:
    async def test_successful_login(self, client: AsyncClient, admin_user: AdminUser):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "Admin1234"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    async def test_invalid_password(self, client: AsyncClient, admin_user: AdminUser):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "Wrong1234"},
        )
        assert resp.status_code == 401

    async def test_nonexistent_user(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "ghost", "password": "Nope1234"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Protected endpoints require auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProtectedEndpoints:
    async def test_users_list_without_token(self, client: AsyncClient):
        resp = await client.get("/api/v1/users")
        assert resp.status_code == 401

    async def test_users_list_with_token(
        self, client: AsyncClient, admin_token: str
    ):
        resp = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    async def test_health_no_auth_required(self, client: AsyncClient, admin_user: AdminUser):
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")


# ---------------------------------------------------------------------------
# User CRUD
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestUserCRUD:
    async def test_create_and_get_user(
        self, client: AsyncClient, admin_token: str
    ):
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Create
        resp = await client.post(
            "/api/v1/users",
            headers=headers,
            json={
                "username": "newuser",
                "password": "Passw0rd!",
                "email": "new@test.local",
                "full_name": "New User",
            },
        )
        assert resp.status_code == 201
        uid = resp.json()["id"]

        # Get list — should include our new user
        resp = await client.get("/api/v1/users", headers=headers)
        assert resp.status_code == 200
        usernames = [u["username"] for u in resp.json()]
        assert "newuser" in usernames

    async def test_duplicate_username(
        self, client: AsyncClient, admin_token: str
    ):
        headers = {"Authorization": f"Bearer {admin_token}"}
        body = {
            "username": "dupuser",
            "password": "Passw0rd!",
            "email": "",
            "full_name": "",
        }
        resp1 = await client.post("/api/v1/users", headers=headers, json=body)
        assert resp1.status_code == 201
        resp2 = await client.post("/api/v1/users", headers=headers, json=body)
        assert resp2.status_code == 409
