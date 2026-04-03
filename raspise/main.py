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
from datetime import datetime, timedelta

import uvicorn

from raspise.config import get_config
from raspise.core import setup_logging, get_logger, bus, Event, EventType
from raspise.db import init_db, AsyncSessionLocal
from raspise.api import api_app
from raspise.portal import portal_app
from raspise.web import web_app


log = get_logger(__name__)

# Guard so background services (RADIUS, TACACS+, profiler) start exactly once
# even though _lifespan is shared across 3 concurrent uvicorn apps.
_services_started = False


# ---------------------------------------------------------------------------
# DB bootstrap — seed admin user + default policies on first run
# ---------------------------------------------------------------------------

async def _seed_database() -> None:
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError
    from raspise.db.models import AdminUser, Policy, PolicyAction
    from raspise.api.auth import hash_password

    cfg = get_config()

    async with AsyncSessionLocal() as db:
        # Disable autoflush so pending INSERTs don't fire during SELECTs;
        # multiple app lifespans may race here — IntegrityError on commit is OK.
        with db.sync_session.no_autoflush:
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

        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()  # another lifespan instance seeded first; that's fine


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

_LOG_RETENTION_DAYS = 90
_LOG_CLEANUP_INTERVAL = 3600  # check once per hour


async def _log_retention_loop() -> None:
    """Prune auth_logs and tacacs_logs older than _LOG_RETENTION_DAYS."""
    from sqlalchemy import delete as sa_delete
    from raspise.db.database import AsyncSessionLocal
    from raspise.db.models import AuthLog, TacacsLog

    while True:
        try:
            cutoff = datetime.utcnow() - timedelta(days=_LOG_RETENTION_DAYS)
            async with AsyncSessionLocal() as db:
                r1 = await db.execute(
                    sa_delete(AuthLog).where(AuthLog.timestamp < cutoff)
                )
                r2 = await db.execute(
                    sa_delete(TacacsLog).where(TacacsLog.timestamp < cutoff)
                )
                await db.commit()
                total = r1.rowcount + r2.rowcount
                if total:
                    log.info("Log retention: pruned %d old log entries (>%dd)", total, _LOG_RETENTION_DAYS)
        except Exception as exc:
            log.warning("Log retention cleanup failed: %s", exc)
        await asyncio.sleep(_LOG_CLEANUP_INTERVAL)


@asynccontextmanager
async def _lifespan(_app):
    global _services_started
    # ── Startup ──────────────────────────────────────────────────────
    setup_logging()
    cfg  = get_config()
    loop = asyncio.get_running_loop()
    bus.set_loop(loop)

    log.info("═══════════════════════════════════════")
    log.info("  RaspISE v1.0  —  %s", cfg.server.name)
    log.info("═══════════════════════════════════════")

    # Warn if using insecure default secret key
    _INSECURE_KEYS = {"change_me", "CHANGE_ME_USE_A_STRONG_RANDOM_STRING", ""}
    if cfg.server.secret_key in _INSECURE_KEYS:
        log.warning(
            "╔════════════════════════════════════════════════════════════╗"
        )
        log.warning(
            "║  WARNING: server.secret_key is set to the default value!  ║"
        )
        log.warning(
            "║  JWT tokens and session cookies are NOT secure.           ║"
        )
        log.warning(
            "║  Generate a new key: python3 -c 'import secrets;          ║"
        )
        log.warning(
            "║    print(secrets.token_hex(32))'                          ║"
        )
        log.warning(
            "╚════════════════════════════════════════════════════════════╝"
        )

    await init_db()
    await _seed_database()

    if not _services_started:
        _services_started = True

        # TACACS+
        if cfg.tacacs.enabled:
            from raspise.tacacs import run_tacacs_server
            asyncio.ensure_future(run_tacacs_server())

        # RADIUS (blocking UDP server — needs its own thread)
        _start_radius_thread(loop)

        # Device profiler
        _start_profiler(loop)

        # Guest session expiry cleanup
        from raspise.portal.app import expire_guest_sessions_loop
        asyncio.ensure_future(expire_guest_sessions_loop())

        # Log retention cleanup (prune old auth_logs and tacacs_logs)
        asyncio.ensure_future(_log_retention_loop())

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
