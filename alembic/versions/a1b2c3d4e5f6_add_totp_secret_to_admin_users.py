"""add totp_secret to admin_users

Revision ID: a1b2c3d4e5f6
Revises: bd6e57d105df
Create Date: 2026-04-04 12:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'bd6e57d105df'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    # Check if column already exists (fresh installs include it in the initial migration)
    result = conn.execute(sa.text("PRAGMA table_info('admin_users')"))
    columns = [row[1] for row in result]
    if 'totp_secret' not in columns:
        with op.batch_alter_table('admin_users', schema=None) as batch_op:
            batch_op.add_column(sa.Column('totp_secret', sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('admin_users', schema=None) as batch_op:
        batch_op.drop_column('totp_secret')
