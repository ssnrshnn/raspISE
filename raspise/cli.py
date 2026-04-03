"""RaspISE CLI management commands.

Usage:
    raspise-cli reset-password --username admin
    raspise-cli check-config
    raspise-cli backup --output /tmp/raspise-backup.db
    raspise-cli restore --input /tmp/raspise-backup.db
    raspise-cli db-upgrade
"""
from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

import click

from raspise.config import get_config


@click.group()
def cli():
    """RaspISE management commands."""


@cli.command("check-config")
def check_config():
    """Validate the configuration file and print a summary."""
    try:
        cfg = get_config()
    except Exception as exc:
        click.secho(f"Config error: {exc}", fg="red")
        sys.exit(1)

    click.secho("Configuration OK", fg="green")
    click.echo(f"  Server name : {cfg.server.name}")
    click.echo(f"  Database    : {cfg.database.url}")
    click.echo(f"  RADIUS      : {'enabled' if cfg.radius.enabled else 'disabled'}")
    click.echo(f"  TACACS+     : {'enabled' if cfg.tacacs.enabled else 'disabled'}")
    click.echo(f"  Portal      : {'enabled' if cfg.portal.enabled else 'disabled'}")
    click.echo(f"  Profiler    : {'enabled' if cfg.profiler.enabled else 'disabled'}")
    click.echo(f"  Display     : {'enabled' if cfg.display.enabled else 'disabled'} ({cfg.display.driver})")

    if cfg.server.secret_key == "change_me":
        click.secho("  WARNING: server.secret_key is still the default!", fg="yellow")
    if cfg.web.admin_password == "RaspISE@admin1":
        click.secho("  WARNING: web.admin_password is still the default!", fg="yellow")


@cli.command("reset-password")
@click.option("--username", default="admin", help="Admin username to reset.")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="New password.")
def reset_password(username: str, password: str):
    """Reset an admin user's password."""
    if len(password) < 8:
        click.secho("Password must be at least 8 characters.", fg="red")
        sys.exit(1)

    async def _reset():
        from sqlalchemy import select
        from raspise.db.database import init_db
        from raspise.db.database import _get_session_factory
        from raspise.db.models import AdminUser
        from raspise.api.auth import hash_password

        await init_db()
        factory = _get_session_factory()
        async with factory() as db:
            user = (await db.execute(
                select(AdminUser).where(AdminUser.username == username)
            )).scalar_one_or_none()
            if not user:
                click.secho(f"Admin user '{username}' not found.", fg="red")
                sys.exit(1)
            user.password_hash = hash_password(password)
            await db.commit()
            click.secho(f"Password reset for '{username}'.", fg="green")

    asyncio.run(_reset())


@cli.command("backup")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output file path for the backup.")
def backup(output: str):
    """Copy the SQLite database file to the specified path."""
    cfg = get_config()
    db_url = cfg.database.url
    # Extract the file path from the SQLite URL
    # Format: sqlite+aiosqlite:////var/lib/raspise/raspise.db
    if ":///" in db_url:
        db_path = db_url.split(":///", 1)[1]
        # For absolute paths, sqlite uses 4 slashes: sqlite:////abs/path
        if db_path.startswith("/"):
            pass  # already absolute
    else:
        click.secho("Backup only supports SQLite databases.", fg="red")
        sys.exit(1)

    src = Path(db_path)
    if not src.exists():
        click.secho(f"Database file not found: {src}", fg="red")
        sys.exit(1)

    dst = Path(output)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    # Also copy WAL/SHM if present
    for suffix in ("-wal", "-shm"):
        wal = src.with_name(src.name + suffix)
        if wal.exists():
            shutil.copy2(wal, dst.with_name(dst.name + suffix))
    click.secho(f"Backed up to {dst}", fg="green")


@cli.command("restore")
@click.option("--input", "-i", "input_file", required=True, type=click.Path(exists=True), help="Backup file to restore.")
@click.confirmation_option(prompt="This will overwrite the current database. Continue?")
def restore(input_file: str):
    """Restore a SQLite database backup."""
    cfg = get_config()
    db_url = cfg.database.url
    if ":///" in db_url:
        db_path = db_url.split(":///", 1)[1]
    else:
        click.secho("Restore only supports SQLite databases.", fg="red")
        sys.exit(1)

    dst = Path(db_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(input_file, dst)
    click.secho(f"Restored database from {input_file}", fg="green")


@cli.command("db-upgrade")
def db_upgrade():
    """Run Alembic migrations (upgrade to head)."""
    try:
        from alembic.config import Config
        from alembic import command
    except ImportError:
        click.secho("alembic is not installed. Run: pip install alembic", fg="red")
        sys.exit(1)

    # Locate alembic.ini relative to this file
    project_root = Path(__file__).resolve().parent.parent
    ini_path = project_root / "alembic.ini"
    if not ini_path.exists():
        click.secho(f"alembic.ini not found at {ini_path}", fg="red")
        sys.exit(1)

    alembic_cfg = Config(str(ini_path))
    command.upgrade(alembic_cfg, "head")
    click.secho("Database upgraded to latest migration.", fg="green")


if __name__ == "__main__":
    cli()
