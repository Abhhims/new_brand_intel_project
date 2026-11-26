"""scan components and honest scan states; demo mode removed (SP1, D-31, D-32)

Revision ID: 7b1d0c4e9a21
Revises: 36da6b432331
Create Date: 2026-10-09 09:00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "7b1d0c4e9a21"
down_revision: str | Sequence[str] | None = "36da6b432331"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW = ("queued", "running", "completed", "partially_completed", "completed_with_errors", "failed", "cancelled")
OLD = ("queued", "running", "succeeded", "partial", "failed")


def _swap(values: tuple[str, ...], using: str) -> None:
    op.execute("ALTER TABLE scan_runs ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TYPE scan_status RENAME TO scan_status_old")
    op.execute("CREATE TYPE scan_status AS ENUM (" + ", ".join(f"'{v}'" for v in values) + ")")
    op.execute(f"ALTER TABLE scan_runs ALTER COLUMN status TYPE scan_status USING ({using})::scan_status")
    op.execute("DROP TYPE scan_status_old")


def upgrade() -> None:
    _swap(NEW, """CASE status::text
        WHEN 'succeeded' THEN 'completed'
        WHEN 'partial' THEN 'completed_with_errors'
        WHEN 'failed' THEN CASE WHEN coalesce(error, '') ILIKE '%interrupted%' THEN 'cancelled' ELSE 'failed' END
        ELSE status::text END""")
    op.add_column("scan_runs", sa.Column("components", postgresql.JSONB(astext_type=sa.Text()), nullable=False,
                                         server_default=sa.text("'[]'::jsonb")))
    # D-32: the product has no demo mode. Refuse rather than silently turn demo brands into live ones.
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM brands WHERE demo_mode) THEN
            RAISE EXCEPTION 'Brands with demo_mode=true exist: delete them before upgrading (decision D-32)';
        END IF; END $$""")
    op.drop_column("brands", "demo_mode")


def downgrade() -> None:
    op.add_column("brands", sa.Column("demo_mode", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.drop_column("scan_runs", "components")
    _swap(OLD, """CASE status::text
        WHEN 'completed' THEN 'succeeded'
        WHEN 'partially_completed' THEN 'partial'
        WHEN 'completed_with_errors' THEN 'partial'
        WHEN 'cancelled' THEN 'failed'
        ELSE status::text END""")
