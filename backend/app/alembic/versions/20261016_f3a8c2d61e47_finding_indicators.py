"""finding indicators for correlation (SP4, D-49)

Revision ID: f3a8c2d61e47
Revises: e2c9f4a17b33
Create Date: 2026-10-16

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f3a8c2d61e47"
down_revision: str | Sequence[str] | None = "e2c9f4a17b33"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("brand_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("brands.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("source", sa.String(200), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("finding_id", "kind", "value"),
    )
    op.create_index("ix_finding_indicators_finding_id", "finding_indicators", ["finding_id"])
    op.create_index("ix_finding_indicators_lookup", "finding_indicators", ["brand_id", "kind", "value"])


def downgrade() -> None:
    op.drop_table("finding_indicators")
