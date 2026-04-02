"""
RaspISE — main entry point
===========================
Starts all services concurrently:

  • FastAPI Admin Web UI  (port 8080, uvicorn)
  • FastAPI REST API      (port 8081, uvicorn)
  • FastAPI Guest Portal  (port 8082, uvicorn)
  • RADIUS server         (UDP 1812 / 1813, separate thread)
  • TACACS+ server        (TCP 49, asyncio)
  • Device Profiler       (Scapy sniffer, separate thread)

On first run, the database is created and a default admin user is seeded.
"""
from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager

import uvicorn

from raspise.config import get_config
from raspise.core import setup_logging, get_logger, bus, Event, EventType
from raspise.db import init_db, AsyncSessionLocal
from raspise.api import api_app
from raspise.portal import portal_app
from raspise.web import web_app


log = get_logger(__name__)


# ---------------------------------------------------------------------------
# DB bootstrap — seed admin user + default policies on first run
# ---------------------------------------------------------------------------

async def _seed_database() -> None:
    from sqlalchemy import select
    from raspise.db.models import AdminUser, Policy, PolicyAction
    from raspise.api.auth import hash_password

    cfg = get_config()

    async with AsyncSessionLocal() as db:
        # Admin user
        existing = (await db.execute(
            select(AdminUser).where(AdminUser.username == cfg.web.admin_username)
        )).scalar_one_or_none()
        if not existing:
            admin = AdminUser(
                username      = cfg.web.admin_username,
                password_hash = hash_password(cfg.web.admin_password),
                is_superuser  = True,
                enabled       = True,
            )
            db.add(admin)
            log.info("Created default admin user: %s", cfg.web.admin_username)

        # Default permit-all policy (lowest priority — catch-all)
        existing_policy = (await db.execute(
            select(Policy).where(Policy.name == "Default-Permit-All")
        )).scalar_one_or_none()
        if not existing_policy:
            db.add(Policy(
                name        = "Default-Permit-All",
                description = "Catch-all: permit any authenticated request",
                priority    = 9999,
                conditions  = "[]",
                action      = PolicyAction.PERMIT,
                vlan        = cfg.radius.default_vlan,
                enabled     = True,
            ))
            log.info("Created default catch-all policy")

        await db.commit()


# ---------------------------------------------------------------------------
# RADIUS thread
# ---------------------------------------------------------------------------

def _start_radius_thread(loop: asyncio.AbstractEventLoop) -> None:
    cfg = get_config()
    if not cfg.radius.enabled:
        log.info("RADIUS server disabled in config")
        return

    from raspise.radius import run_radius_server
    t = threading.Thread(
        target=run_radius_server,
        args=(loop,),
        daemon=True,
        name="radius-server",
    )
    t.start()


# ---------------------------------------------------------------------------
# Profiler thread
# ---------------------------------------------------------------------------

def _start_profiler(loop: asyncio.AbstractEventLoop) -> None:
    cfg = get_config()
    if not cfg.profiler.enabled:
        log.info("Device profiler disabled in config")
        return

    from raspise.profiler import profiler
    profiler.start(loop)


# ---------------------------------------------------------------------------
# Startup / shutdown lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(_app):
    # ── Startup ──────────────────────────────────────────────────────
    setup_logging()
    cfg  = get_config()
    loop = asyncio.get_event_loop()

    log.info("═══════════════════════════════════════")
    log.info("  RaspISE v1.0  —  %s", cfg.server.name)
    log.info("═══════════════════════════════════════")

    await init_db()
    await _seed_database()

    # TACACS+
    if cfg.tacacs.enabled:
        from raspise.tacacs import run_tacacs_server
        asyncio.ensure_future(run_tacacs_server())

    # RADIUS (blocking UDP server — needs its own thread)
    _start_radius_thread(loop)

    # Device profiler
    _start_profiler(loop)

    # Publish system-start event
    await bus.publish(Event(EventType.SYSTEM_START, data={"node": cfg.server.name}))

    log.info("Admin UI  → http://localhost:%d", cfg.web.port)
    log.info("REST API  → http://localhost:%d/api/v1/docs", cfg.api.port)
    log.info("Portal    → http://localhost:%d", cfg.portal.port)

    yield

    # ── Shutdown ─────────────────────────────────────────────────────
    from raspise.profiler import profiler
    profiler.stop()
    await bus.publish(Event(EventType.SYSTEM_STOP))
    log.info("RaspISE shutting down.")


# Attach lifespan to each FastAPI app
for _app in (api_app, portal_app, web_app):
    _app.router.lifespan_context = _lifespan


# ---------------------------------------------------------------------------
# Multi-server runner
# ---------------------------------------------------------------------------

async def _serve_all() -> None:
    cfg = get_config()

    servers = [
        uvicorn.Server(uvicorn.Config(
            web_app,
            host=cfg.web.host, port=cfg.web.port,
            log_level="warning",
        )),
        uvicorn.Server(uvicorn.Config(
            api_app,
            host=cfg.api.host, port=cfg.api.port,
            log_level="warning",
        )),
        uvicorn.Server(uvicorn.Config(
            portal_app,
            host=cfg.portal.host, port=cfg.portal.port,
            log_level="warning",
        )),
    ]

    await asyncio.gather(*[s.serve() for s in servers])


def main() -> None:
    setup_logging()
    asyncio.run(_serve_all())


if __name__ == "__main__":
    main()
