"""allowlist signing certificates

Adds the `signing_cert` allowlist kind: SHA-256 fingerprints of a brand's official APK signing
certificates, used by the Fake APK module (decision D-26).

Revision ID: 5ce191d6512a
Revises: 82c293d5eeb0
Create Date: 2026-10-07 18:37:00.864278

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '5ce191d6512a'
down_revision: str | Sequence[str] | None = '82c293d5eeb0'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ADD VALUE cannot run inside a transaction block on older PostgreSQL versions
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE allow_kind ADD VALUE IF NOT EXISTS 'signing_cert'")


def downgrade() -> None:
    # PostgreSQL cannot drop an enum value; remove rows that use it and leave the type as is.
    op.execute("DELETE FROM brand_allowlist WHERE kind = 'signing_cert'")
