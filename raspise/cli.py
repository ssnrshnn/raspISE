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
from sqlalchemy.engine import make_url

from raspise.config import get_config


def _sqlite_path_from_url(db_url: str) -> Path:
    """Extract the filesystem path from a SQLite URL, or exit with error."""
    try:
        url = make_url(db_url)
    except Exception as exc:
        click.secho(f"Invalid database URL: {exc}", fg="red")
        sys.exit(1)
    if url.get_backend_name() != "sqlite":
        click.secho("Only SQLite databases are supported for this command.", fg="red")
        sys.exit(1)
    # url.database is the path portion (None for :memory:)
    if not url.database:
        click.secho("In-memory databases cannot be backed up/restored.", fg="red")
        sys.exit(1)
    return Path(url.database)


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
    if not any(c.isalpha() for c in password):
        click.secho("Password must contain at least one letter.", fg="red")
        sys.exit(1)
    if not any(c.isdigit() for c in password):
        click.secho("Password must contain at least one digit.", fg="red")
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
    src = _sqlite_path_from_url(cfg.database.url)
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
    # Validate that the input file is actually a SQLite database
    _SQLITE_MAGIC = b"SQLite format 3\000"
    try:
        with open(input_file, "rb") as f:
            header = f.read(16)
        if header[:16] != _SQLITE_MAGIC:
            click.secho("Error: input file is not a valid SQLite database.", fg="red")
            sys.exit(1)
    except OSError as exc:
        click.secho(f"Error reading input file: {exc}", fg="red")
        sys.exit(1)

    cfg = get_config()
    dst = _sqlite_path_from_url(cfg.database.url)
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
