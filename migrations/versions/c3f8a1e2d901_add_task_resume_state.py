"""add task resume state column for Phase 9 resume-after-approval

Revision ID: c3f8a1e2d901
Revises: b7a2c9d1e4f0
Create Date: 2026-11-19 19:35:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "c3f8a1e2d901"
down_revision = "b7a2c9d1e4f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agent_tasks", schema=None) as batch_op:
        batch_op.add_column(sa.Column("resume_state_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agent_tasks", schema=None) as batch_op:
        batch_op.drop_column("resume_state_json")
