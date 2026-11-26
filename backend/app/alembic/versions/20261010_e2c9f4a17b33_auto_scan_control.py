"""automatic scan control: master switch + per-brand on/off, frequency and scanners (D-39)

Existing brands get automatic scanning OFF (owner decision 2026-10-10: control cost; "Run scan now" still works).

Revision ID: e2c9f4a17b33
Revises: d7a3b5e1f082
Create Date: 2026-10-10 09:00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e2c9f4a17b33"
down_revision: str | Sequence[str] | None = "d7a3b5e1f082"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("brands", sa.Column("auto_scan_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("brands", sa.Column("auto_scan_frequency", sa.String(20), nullable=False, server_default="daily"))
    op.add_column("brands", sa.Column("auto_scan_runners", postgresql.ARRAY(sa.String()), nullable=False,
                                      server_default=sa.text("'{}'::varchar[]")))
    op.add_column("brands", sa.Column("last_auto_scan_at", sa.DateTime(timezone=True)))
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
    )
    op.execute("""INSERT INTO app_settings (key, value, updated_at) VALUES ('auto_scan', '{"enabled": true}', now())""")


def downgrade() -> None:
    op.drop_table("app_settings")
    for col in ("last_auto_scan_at", "auto_scan_runners", "auto_scan_frequency", "auto_scan_enabled"):
        op.drop_column("brands", col)
