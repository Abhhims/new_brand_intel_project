"""social media brand-misuse module (posts, videos, ads, channels)

Revision ID: d7a3b5e1f082
Revises: c41e7a9d2b10
Create Date: 2026-10-09 20:00:00

"""
from collections.abc import Sequence

from alembic import op

revision: str = "d7a3b5e1f082"
down_revision: str | Sequence[str] | None = "c41e7a9d2b10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE module_name ADD VALUE IF NOT EXISTS 'social_media'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value; remove the data that uses it and leave the unused value in place.
    op.execute("DELETE FROM findings WHERE module = 'social_media'")
    op.execute("DELETE FROM scan_runs WHERE module = 'social_media'")
