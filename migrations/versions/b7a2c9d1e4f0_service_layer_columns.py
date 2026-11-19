"""service-layer columns

Revision ID: b7a2c9d1e4f0
Revises: ea3516f6309f
Create Date: 2026-10-20 01:35:00

This is the upgrade path from the 0.1 development schema. A 0.1 database has no
`alembic_version`; stamp it at `ea3516f6309f` first, then run `alembic upgrade
head`. A fresh database runs both revisions in order.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "b7a2c9d1e4f0"
down_revision = "ea3516f6309f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agent_tasks", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("tenant_id", sa.String(length=64), nullable=False, server_default="default")
        )
        batch_op.add_column(sa.Column("answer", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("termination", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("error", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("trace_json", sa.JSON(), nullable=True))
        batch_op.create_index(batch_op.f("ix_agent_tasks_tenant_id"), ["tenant_id"], unique=False)

    with op.batch_alter_table("approval_requests", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("tenant_id", sa.String(length=64), nullable=False, server_default="default")
        )
        batch_op.create_index(
            batch_op.f("ix_approval_requests_tenant_id"), ["tenant_id"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("approval_requests", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_approval_requests_tenant_id"))
        batch_op.drop_column("tenant_id")

    with op.batch_alter_table("agent_tasks", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_agent_tasks_tenant_id"))
        batch_op.drop_column("trace_json")
        batch_op.drop_column("error")
        batch_op.drop_column("termination")
        batch_op.drop_column("answer")
        batch_op.drop_column("tenant_id")
