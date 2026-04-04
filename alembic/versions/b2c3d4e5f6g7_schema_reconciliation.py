"""comprehensive schema reconciliation

Bring old databases (created by create_all before Alembic was introduced)
in line with the current models.  Every check is idempotent so this
migration is safe to run on brand-new databases as well.

Revision ID: b2c3d4e5f6g7
Revises: a1b2c3d4e5f6
Create Date: 2026-04-05 10:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b2c3d4e5f6g7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _table_exists(conn, name: str) -> bool:
    row = conn.execute(
        sa.text("SELECT 1 FROM sqlite_master WHERE type='table' AND name=:n"),
        {"n": name},
    ).fetchone()
    return row is not None


def _get_columns(conn, table: str) -> set[str]:
    rows = conn.execute(sa.text(f"PRAGMA table_info('{table}')"))
    return {r[1] for r in rows}


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def upgrade() -> None:
    conn = op.get_bind()

    # ── 1. Ensure command_sets table exists ────────────────────────────
    if not _table_exists(conn, "command_sets"):
        op.create_table(
            "command_sets",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(64), nullable=False),
            sa.Column("description", sa.String(255), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )

    # ── 2. Ensure command_rules table exists ───────────────────────────
    if not _table_exists(conn, "command_rules"):
        op.create_table(
            "command_rules",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("command_set_id", sa.Integer(), nullable=False),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
            sa.Column("action", sa.Enum("PERMIT", "DENY", name="commandruleaction"), nullable=False),
            sa.Column("command_pattern", sa.String(256), nullable=False),
            sa.Column("args_pattern", sa.String(256), nullable=False, server_default=""),
            sa.ForeignKeyConstraint(["command_set_id"], ["command_sets.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )

    # ── 3. Add command_set_id to groups if missing ─────────────────────
    if "command_set_id" not in _get_columns(conn, "groups"):
        with op.batch_alter_table("groups", schema=None) as batch_op:
            batch_op.add_column(
                sa.Column("command_set_id", sa.Integer(), nullable=True)
            )
            batch_op.create_foreign_key(
                "fk_groups_command_set_id",
                "command_sets",
                ["command_set_id"],
                ["id"],
                ondelete="SET NULL",
            )

    # ── 4. Add must_change_password to users if missing ────────────────
    if "must_change_password" not in _get_columns(conn, "users"):
        with op.batch_alter_table("users", schema=None) as batch_op:
            batch_op.add_column(
                sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default="0")
            )

    # ── 5. Add totp_secret to admin_users if still missing ─────────────
    if "totp_secret" not in _get_columns(conn, "admin_users"):
        with op.batch_alter_table("admin_users", schema=None) as batch_op:
            batch_op.add_column(
                sa.Column("totp_secret", sa.String(64), nullable=True)
            )

    # ── 6. Ensure admin_audit_logs table exists ────────────────────────
    if not _table_exists(conn, "admin_audit_logs"):
        op.create_table(
            "admin_audit_logs",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True),
                      server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
            sa.Column("admin_username", sa.String(64), nullable=False),
            sa.Column("action", sa.String(32), nullable=False),
            sa.Column("resource_type", sa.String(64), nullable=False),
            sa.Column("resource_id", sa.String(64), nullable=False, server_default=""),
            sa.Column("detail", sa.Text(), nullable=False, server_default=""),
            sa.PrimaryKeyConstraint("id"),
        )
        with op.batch_alter_table("admin_audit_logs", schema=None) as batch_op:
            batch_op.create_index("ix_admin_audit_logs_timestamp", ["timestamp"])
            batch_op.create_index("ix_admin_audit_logs_admin_username", ["admin_username"])


# ---------------------------------------------------------------------------
# Downgrade
# ---------------------------------------------------------------------------

def downgrade() -> None:
    # Remove admin_audit_logs
    op.drop_table("admin_audit_logs")

    # Remove must_change_password from users
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("must_change_password")

    # Remove command_set_id from groups
    with op.batch_alter_table("groups", schema=None) as batch_op:
        batch_op.drop_constraint("fk_groups_command_set_id", type_="foreignkey")
        batch_op.drop_column("command_set_id")

    op.drop_table("command_rules")
    op.drop_table("command_sets")
