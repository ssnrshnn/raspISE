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
from datetime import datetime, timedelta, timezone

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
_services_lock = threading.Lock()
_init_done = asyncio.Event()


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

_radius_thread: threading.Thread | None = None


def _start_radius_thread(loop: asyncio.AbstractEventLoop) -> None:
    global _radius_thread
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
    _radius_thread = t


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


def _task_done_callback(task: asyncio.Task) -> None:
    """Log unhandled exceptions from background tasks."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("Background task %r crashed: %s", task.get_name(), exc, exc_info=exc)


def _create_monitored_task(coro, *, name: str | None = None) -> asyncio.Task:
    """Create an asyncio task with an error-logging done callback."""
    task = asyncio.create_task(coro, name=name)
    task.add_done_callback(_task_done_callback)
    return task


async def _log_retention_loop() -> None:
    """Prune auth_logs and tacacs_logs older than _LOG_RETENTION_DAYS."""
    from sqlalchemy import delete as sa_delete
    from raspise.db.database import AsyncSessionLocal
    from raspise.db.models import AuthLog, TacacsLog

    while True:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=_LOG_RETENTION_DAYS)
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


_STALE_SESSION_HOURS = 24
_STALE_SESSION_INTERVAL = 1800  # check every 30 minutes


async def _stale_session_cleanup_loop() -> None:
    """Remove active sessions that haven't been updated in >24 hours (NAS crash/unreachable)."""
    from sqlalchemy import delete as sa_delete
    from raspise.db.database import AsyncSessionLocal
    from raspise.db.models import ActiveSession

    while True:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=_STALE_SESSION_HOURS)
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    sa_delete(ActiveSession).where(ActiveSession.updated_at < cutoff)
                )
                await db.commit()
                if result.rowcount:
                    log.info("Stale session cleanup: removed %d sessions (>%dh without update)",
                             result.rowcount, _STALE_SESSION_HOURS)
        except Exception as exc:
            log.warning("Stale session cleanup failed: %s", exc)
        await asyncio.sleep(_STALE_SESSION_INTERVAL)


@asynccontextmanager
async def _lifespan(_app):
    global _services_started
    # ── Startup ──────────────────────────────────────────────────────
    setup_logging()
    cfg  = get_config()
    loop = asyncio.get_running_loop()
    bus.set_loop(loop)

    with _services_lock:
        _should_start = not _services_started
        if _should_start:
            _services_started = True

    if _should_start:
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

        # Warn if using default admin credentials
        _DEFAULT_PASSWORDS = {"RaspISE@admin1", "admin", "password", ""}
        if cfg.web.admin_password in _DEFAULT_PASSWORDS:
            log.warning("╔════════════════════════════════════════════════════════════╗")
            log.warning("║  WARNING: admin password is set to the default value!     ║")
            log.warning("║  Change it in config.yaml → web.admin_password            ║")
            log.warning("╚════════════════════════════════════════════════════════════╝")

        # Warn if using default TACACS+ key
        if cfg.tacacs.enabled and cfg.tacacs.key in ("tacacs_secret", "testing123", ""):
            log.warning("╔════════════════════════════════════════════════════════════╗")
            log.warning("║  WARNING: TACACS+ key is set to the default value!        ║")
            log.warning("║  Change it in config.yaml → tacacs.key                    ║")
            log.warning("╚════════════════════════════════════════════════════════════╝")

        await init_db()
        await _seed_database()

        # TACACS+
        if cfg.tacacs.enabled:
            from raspise.tacacs import run_tacacs_server
            _create_monitored_task(run_tacacs_server(), name="tacacs-server")

        # RADIUS (blocking UDP server — needs its own thread)
        _start_radius_thread(loop)

        # Device profiler
        _start_profiler(loop)

        # Guest session expiry cleanup
        from raspise.portal.app import expire_guest_sessions_loop
        _create_monitored_task(expire_guest_sessions_loop(), name="guest-session-expiry")

        # Log retention cleanup (prune old auth_logs and tacacs_logs)
        _create_monitored_task(_log_retention_loop(), name="log-retention")

        # Stale session cleanup (remove sessions not updated in >24h)
        _create_monitored_task(_stale_session_cleanup_loop(), name="stale-session-cleanup")

        # Event webhook dispatcher
        from raspise.core.webhooks import run_webhook_dispatcher
        _create_monitored_task(run_webhook_dispatcher(), name="webhook-dispatcher")

        # Prometheus metrics collector
        from raspise.core.metrics import run_metrics_collector
        _create_monitored_task(run_metrics_collector(bus), name="metrics-collector")

        # Publish system-start event
        await bus.publish(Event(EventType.SYSTEM_START, data={"node": cfg.server.name}))

        log.info("Admin UI  → http://localhost:%d", cfg.web.port)
        log.info("REST API  → http://localhost:%d/api/v1/docs", cfg.api.port)
        log.info("Portal    → http://localhost:%d", cfg.portal.port)

        _init_done.set()
    else:
        # Wait for the first app to finish DB init before serving requests
        await _init_done.wait()

    yield

    # ── Shutdown ─────────────────────────────────────────────────────
    from raspise.profiler import profiler
    profiler.stop()

    # Gracefully stop the RADIUS server if running
    from raspise.radius.server import _active_radius_server
    if _active_radius_server is not None:
        try:
            _active_radius_server._running = False
        except Exception:
            pass
    if _radius_thread is not None and _radius_thread.is_alive():
        _radius_thread.join(timeout=5)
        if _radius_thread.is_alive():
            log.warning("RADIUS thread did not exit within 5 s")

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
