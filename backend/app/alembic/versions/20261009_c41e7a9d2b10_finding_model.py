"""finding model: candidate -> finding -> alert, observations, timeline, analyst decisions (SP2, D-33…D-37)

Phase 1 alerts become findings with the SAME id; each gets one migrated observation and one alert record (also the
same id, so old links to /alerts/<id> still open). alert_events become the finding timeline.

Revision ID: c41e7a9d2b10
Revises: 7b1d0c4e9a21
Create Date: 2026-10-09 18:00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c41e7a9d2b10"
down_revision: str | Sequence[str] | None = "7b1d0c4e9a21"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DECISIONS = ("New", "Investigating", "Confirmed Threat", "False Positive", "Legitimate", "Ignored", "Resolved")
OLD_STATUSES = ("New", "Under Review", "Confirmed", "False Positive", "Closed")
TO_DECISION = """CASE {col}
    WHEN 'Under Review' THEN 'Investigating'
    WHEN 'Confirmed' THEN 'Confirmed Threat'
    WHEN 'Closed' THEN 'Resolved'
    ELSE {col} END"""
TO_STATUS = """CASE {col}
    WHEN 'Investigating' THEN 'Under Review'
    WHEN 'Confirmed Threat' THEN 'Confirmed'
    WHEN 'Resolved' THEN 'Closed'
    WHEN 'Legitimate' THEN 'False Positive'
    WHEN 'Ignored' THEN 'Closed'
    ELSE {col} END"""

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def _enum_values(values: tuple[str, ...]) -> str:
    return ", ".join("'" + v.replace("'", "''") + "'" for v in values)


def upgrade() -> None:
    # --- alerts -> findings ------------------------------------------------------------------------------------
    op.rename_table("alerts", "findings")
    op.execute("ALTER TABLE findings RENAME CONSTRAINT uq_alert_entity TO uq_finding_entity")
    op.execute("ALTER TABLE findings RENAME CONSTRAINT alerts_pkey TO findings_pkey")
    op.execute("ALTER INDEX ix_alerts_brand_id RENAME TO ix_findings_brand_id")
    op.execute("ALTER INDEX ix_alerts_first_seen RENAME TO ix_findings_first_seen")
    op.drop_index("ix_alerts_filters", table_name="findings")

    op.execute(f"CREATE TYPE finding_decision AS ENUM ({_enum_values(DECISIONS)})")
    op.execute("CREATE TYPE finding_stage AS ENUM ('Candidate', 'Finding')")
    op.add_column("findings", sa.Column("decision", postgresql.ENUM(name="finding_decision", create_type=False),
                                        nullable=True))
    op.execute(f"UPDATE findings SET decision = ({TO_DECISION.format(col='status::text')})::finding_decision")
    op.alter_column("findings", "decision", nullable=False)
    op.drop_column("findings", "status")
    op.execute("DROP TYPE alert_status")
    op.add_column("findings", sa.Column("stage", postgresql.ENUM(name="finding_stage", create_type=False),
                                        nullable=False, server_default="Finding"))
    op.add_column("findings", sa.Column("decided_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL")))
    op.add_column("findings", sa.Column("decided_at", sa.DateTime(timezone=True)))
    op.add_column("findings", sa.Column("decision_note", sa.Text()))
    op.add_column("findings", sa.Column("state", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.add_column("findings", sa.Column("last_alert_at", sa.DateTime(timezone=True)))
    op.create_index("ix_findings_filters", "findings", ["brand_id", "module", "risk_level", "decision"])
    # comparable facts recovered from the stored scoring rules (D-36)
    op.execute("""UPDATE findings SET state = jsonb_strip_nulls(jsonb_build_object(
        'live', CASE WHEN module = 'phishing' THEN true END,
        'mx', CASE WHEN module IN ('typosquat', 'mx', 'phishing') THEN signals->'rules' ? 'mx_present' END,
        'login_form', CASE WHEN signals->'rules' ? 'login_payment_keywords' THEN true END,
        'logo_match', CASE WHEN signals->'rules' ? 'official_logo' OR signals->'rules' ? 'social_image_match'
                           THEN true END))""")

    # --- brands: alert threshold (D-34) -------------------------------------------------------------------------
    op.add_column("brands", sa.Column("alert_min_level", postgresql.ENUM(name="risk_level", create_type=False),
                                      nullable=False, server_default="Medium"))

    # --- observations ---------------------------------------------------------------------------------------------
    op.create_table(
        "observations",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("finding_id", UUID, sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", UUID, sa.ForeignKey("scan_runs.id", ondelete="SET NULL")),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stage", postgresql.ENUM(name="finding_stage", create_type=False), nullable=False),
        sa.Column("module", postgresql.ENUM(name="module_name", create_type=False), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("risk_level", postgresql.ENUM(name="risk_level", create_type=False), nullable=False),
        sa.Column("signals", JSONB, nullable=False),
        sa.Column("state", JSONB, nullable=False),
        sa.Column("details", JSONB, nullable=False),
    )
    op.create_index("ix_observations_finding_id", "observations", ["finding_id"])
    op.create_index("ix_observations_scan_id", "observations", ["scan_id"])
    op.create_index("ix_observations_observed_at", "observations", ["observed_at"])
    op.execute("""INSERT INTO observations (id, finding_id, scan_id, channel, observed_at, stage, module, score,
                      risk_level, signals, state, details)
                  SELECT id, id, NULL, 'migration', last_seen, stage, module, score, risk_level, signals, state, details
                  FROM findings""")

    # --- alert records ---------------------------------------------------------------------------------------------
    op.create_table(
        "alerts",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("finding_id", UUID, sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("brand_id", UUID, sa.ForeignKey("brands.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", UUID, sa.ForeignKey("scan_runs.id", ondelete="SET NULL")),
        sa.Column("observation_id", UUID, sa.ForeignKey("observations.id", ondelete="SET NULL")),
        sa.Column("trigger", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("risk_level", postgresql.ENUM(name="risk_level", create_type=False), nullable=False),
        sa.Column("reasons", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alerts_finding_id", "alerts", ["finding_id"])
    op.create_index("ix_alerts_brand_id", "alerts", ["brand_id"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])
    op.execute("""INSERT INTO alerts (id, finding_id, brand_id, scan_id, observation_id, trigger, reason, score,
                      risk_level, reasons, created_at)
                  SELECT id, id, brand_id, NULL, id, 'migrated', 'Migrated from Phase 1', score, risk_level,
                         coalesce(signals->'rules', '{}'::jsonb), first_seen
                  FROM findings""")
    op.execute("UPDATE findings SET last_alert_at = first_seen")

    # --- alert_events -> finding_events ---------------------------------------------------------------------------
    op.rename_table("alert_events", "finding_events")
    op.execute("ALTER TABLE finding_events RENAME CONSTRAINT alert_events_pkey TO finding_events_pkey")
    op.alter_column("finding_events", "alert_id", new_column_name="finding_id")
    op.execute("ALTER INDEX ix_alert_events_alert_id RENAME TO ix_finding_events_finding_id")
    op.add_column("finding_events", sa.Column("observation_id", UUID,
                                              sa.ForeignKey("observations.id", ondelete="SET NULL")))
    op.add_column("finding_events", sa.Column("alert_id", UUID, sa.ForeignKey("alerts.id", ondelete="SET NULL")))
    op.execute(f"""UPDATE finding_events SET
        kind = CASE kind WHEN 'status' THEN 'decision' WHEN 'created' THEN 'discovered' ELSE kind END,
        from_status = {TO_DECISION.format(col='from_status')},
        to_status = {TO_DECISION.format(col='to_status')}""")

    # --- evidence and emails point at the finding -------------------------------------------------------------------
    op.alter_column("evidence", "alert_id", new_column_name="finding_id")
    op.execute("ALTER INDEX ix_evidence_alert_id RENAME TO ix_evidence_finding_id")
    op.add_column("evidence", sa.Column("observation_id", UUID,
                                        sa.ForeignKey("observations.id", ondelete="SET NULL")))
    op.execute("UPDATE evidence SET observation_id = finding_id")
    op.alter_column("email_messages", "alert_id", new_column_name="finding_id")
    op.execute("ALTER INDEX ix_email_messages_alert_id RENAME TO ix_email_messages_finding_id")


def downgrade() -> None:
    op.execute("ALTER INDEX ix_email_messages_finding_id RENAME TO ix_email_messages_alert_id")
    op.alter_column("email_messages", "finding_id", new_column_name="alert_id")
    op.drop_column("evidence", "observation_id")
    op.execute("ALTER INDEX ix_evidence_finding_id RENAME TO ix_evidence_alert_id")
    op.alter_column("evidence", "finding_id", new_column_name="alert_id")

    op.drop_column("finding_events", "alert_id")
    op.drop_column("finding_events", "observation_id")
    op.execute(f"""UPDATE finding_events SET
        kind = CASE kind WHEN 'decision' THEN 'status' WHEN 'discovered' THEN 'created' ELSE kind END,
        from_status = {TO_STATUS.format(col='from_status')},
        to_status = {TO_STATUS.format(col='to_status')}""")
    op.execute("ALTER INDEX ix_finding_events_finding_id RENAME TO ix_alert_events_alert_id")
    op.alter_column("finding_events", "finding_id", new_column_name="alert_id")
    op.execute("ALTER TABLE finding_events RENAME CONSTRAINT finding_events_pkey TO alert_events_pkey")
    op.rename_table("finding_events", "alert_events")

    op.drop_table("alerts")
    op.drop_table("observations")
    op.drop_column("brands", "alert_min_level")

    # Phase 1 has one alert per entity: keep only findings that were alerted (candidates/below-threshold dropped)
    op.execute("DELETE FROM findings WHERE last_alert_at IS NULL")
    op.execute(f"CREATE TYPE alert_status AS ENUM ({_enum_values(OLD_STATUSES)})")
    op.add_column("findings", sa.Column("status", postgresql.ENUM(name="alert_status", create_type=False)))
    op.execute(f"UPDATE findings SET status = ({TO_STATUS.format(col='decision::text')})::alert_status")
    op.alter_column("findings", "status", nullable=False)
    op.drop_index("ix_findings_filters", table_name="findings")
    for col in ("decision", "stage", "decided_by", "decided_at", "decision_note", "state", "last_alert_at"):
        op.drop_column("findings", col)
    op.execute("DROP TYPE finding_decision")
    op.execute("DROP TYPE finding_stage")
    op.execute("ALTER INDEX ix_findings_first_seen RENAME TO ix_alerts_first_seen")
    op.execute("ALTER INDEX ix_findings_brand_id RENAME TO ix_alerts_brand_id")
    op.execute("ALTER TABLE findings RENAME CONSTRAINT findings_pkey TO alerts_pkey")
    op.execute("ALTER TABLE findings RENAME CONSTRAINT uq_finding_entity TO uq_alert_entity")
    op.rename_table("findings", "alerts")
    op.create_index("ix_alerts_filters", "alerts", ["brand_id", "module", "risk_level", "status"])
