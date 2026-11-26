"""Database schema (FND-02). See docs/guides/DATA-MODEL.md for the explained version."""

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


def _enum(cls: type[enum.Enum], name: str) -> Enum:
    return Enum(cls, name=name, values_callable=lambda e: [m.value for m in e])


class Role(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"


class ModuleName(str, enum.Enum):
    typosquat = "typosquat"
    mx = "mx"
    phishing = "phishing"
    apk = "apk"
    rogue_app = "rogue_app"
    social = "social"
    documents = "documents"
    logo = "logo"
    email = "email"                  # phishing email analysis (D-28)
    email_posture = "email_posture"  # brand domains' SPF/DMARC/DKIM/MTA-STS
    dmarc = "dmarc"                  # senders failing DMARC while using the brand domain
    social_media = "social_media"    # brand misuse in posts, videos, ads and channels across social platforms


class RiskLevel(str, enum.Enum):
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"


class FindingDecision(str, enum.Enum):
    """Analyst decision on a finding (RDA-11, D-35). "Reopened" is a timeline event, not a state."""
    new = "New"
    investigating = "Investigating"
    confirmed_threat = "Confirmed Threat"
    false_positive = "False Positive"
    legitimate = "Legitimate"
    ignored = "Ignored"
    resolved = "Resolved"


class FindingStage(str, enum.Enum):
    """Candidate = discovered, weak; Finding = analysed with evidence (RDA-12, D-33)."""
    candidate = "Candidate"
    finding = "Finding"


class AssetKind(str, enum.Enum):
    logo = "logo"
    favicon = "favicon"
    app_icon = "app_icon"


class AllowKind(str, enum.Enum):
    domain = "domain"
    package = "package"
    publisher = "publisher"
    social_handle = "social_handle"
    email_domain = "email_domain"
    signing_cert = "signing_cert"  # SHA-256 of the official APK signing certificate (D-26)


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    partially_completed = "partially_completed"      # ran; some components not configured / unavailable (D-31)
    completed_with_errors = "completed_with_errors"  # ran; some components failed part-way
    failed = "failed"
    cancelled = "cancelled"                          # interrupted (worker restart / stale)


class EvidenceKind(str, enum.Enum):
    screenshot = "screenshot"
    favicon = "favicon"
    html = "html"
    metadata = "metadata"
    file = "file"
    ssl = "ssl"
    whois = "whois"
    dns = "dns"
    image = "image"


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(_enum(Role, "role"), default=Role.analyst)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Brand(Base):
    __tablename__ = "brands"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    keywords: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    product_terms: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # D-34: a finding becomes an alert from this risk level up
    alert_min_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "risk_level"), default=RiskLevel.medium,
                                                       server_default=RiskLevel.medium.value)
    # Automatic (scheduled) scanning, off by default to control cost (D-39). "Run scan now" always works.
    auto_scan_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    auto_scan_frequency: Mapped[str] = mapped_column(String(20), default="daily", server_default="daily")
    auto_scan_runners: Mapped[list[str]] = mapped_column(ARRAY(String), default=list,
                                                         server_default=text("'{}'::varchar[]"))
    last_auto_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    assets: Mapped[list["BrandAsset"]] = relationship(back_populates="brand", cascade="all, delete-orphan")
    allowlist: Mapped[list["BrandAllow"]] = relationship(back_populates="brand", cascade="all, delete-orphan")

    def allowed(self, kind: AllowKind) -> list[str]:
        return [a.value for a in self.allowlist if a.kind == kind]


class BrandAsset(Base):
    __tablename__ = "brand_assets"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    kind: Mapped[AssetKind] = mapped_column(_enum(AssetKind, "asset_kind"))
    filename: Mapped[str] = mapped_column(String(255))
    storage_key: Mapped[str] = mapped_column(String(500))
    content_type: Mapped[str] = mapped_column(String(100))
    sha256: Mapped[str] = mapped_column(String(64))
    phash: Mapped[str | None] = mapped_column(String(64))
    dhash: Mapped[str | None] = mapped_column(String(64))
    mmh3: Mapped[int | None] = mapped_column(Integer)  # favicon hash, Shodan style
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    brand: Mapped[Brand] = relationship(back_populates="assets")


class BrandAllow(Base):
    __tablename__ = "brand_allowlist"
    __table_args__ = (UniqueConstraint("brand_id", "kind", "value"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    kind: Mapped[AllowKind] = mapped_column(_enum(AllowKind, "allow_kind"))
    value: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    brand: Mapped[Brand] = relationship(back_populates="allowlist")


class AppSetting(Base):
    """Platform-wide settings changed from the dashboard (e.g. the automatic-scan master switch, D-39)."""
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    module: Mapped[ModuleName] = mapped_column(_enum(ModuleName, "module_name"))
    trigger: Mapped[str] = mapped_column(String(20), default="schedule")
    status: Mapped[ScanStatus] = mapped_column(_enum(ScanStatus, "scan_status"), default=ScanStatus.queued)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    # Per-component results [{name, status, message, counts, fatal}] (D-31)
    components: Mapped[list] = mapped_column(JSONB, default=list, server_default=text("'[]'::jsonb"))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    brand: Mapped[Brand] = relationship()


class Finding(Base):
    """One entity (domain, app, account, document, email…) per brand, across every scan that saw it (RDA-12, D-33)."""
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("brand_id", "module", "entity_key", name="uq_finding_entity"),
        Index("ix_findings_filters", "brand_id", "module", "risk_level", "decision"),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    module: Mapped[ModuleName] = mapped_column(_enum(ModuleName, "module_name"))
    entity_key: Mapped[str] = mapped_column(String(1000))
    stage: Mapped[FindingStage] = mapped_column(_enum(FindingStage, "finding_stage"), default=FindingStage.finding)
    title: Mapped[str] = mapped_column(String(500))
    similarity: Mapped[float | None] = mapped_column(Float)
    score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "risk_level"))
    decision: Mapped[FindingDecision] = mapped_column(_enum(FindingDecision, "finding_decision"),
                                                      default=FindingDecision.new)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)
    suspected_phishing: Mapped[bool] = mapped_column(Boolean, default=False)
    signals: Mapped[dict] = mapped_column(JSONB, default=dict)  # which scoring rules fired
    details: Mapped[dict] = mapped_column(JSONB, default=dict)  # the module's Expected Output fields
    state: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))  # comparable facts
    source_url: Mapped[str | None] = mapped_column(String(2000))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_alert_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    brand: Mapped[Brand] = relationship()
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="Evidence.captured_at"
    )
    events: Mapped[list["FindingEvent"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingEvent.at"
    )
    observations: Mapped[list["Observation"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="Observation.observed_at.desc()"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="Alert.created_at.desc()"
    )


class Observation(Base):
    """What one scan (or email intake) saw of a finding (RDA-15)."""
    __tablename__ = "observations"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"), index=True)
    channel: Mapped[str] = mapped_column(String(20), default="scan")  # scan | upload | mailbox | migration
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    stage: Mapped[FindingStage] = mapped_column(_enum(FindingStage, "finding_stage"))
    module: Mapped[ModuleName] = mapped_column(_enum(ModuleName, "module_name"))
    score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "risk_level"))
    signals: Mapped[dict] = mapped_column(JSONB, default=dict)
    state: Mapped[dict] = mapped_column(JSONB, default=dict)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)

    finding: Mapped[Finding] = relationship(back_populates="observations")


class FindingIndicator(Base):
    """A stable identifier seen in a finding's own evidence (SP4, D-49): certificate, APK signer, file hash, scam
    phone / UPI number, mail-server domain, developer e-mail, linked domain. Findings that share a value are related;
    the shared value and where it was seen are the evidence for the link."""
    __tablename__ = "finding_indicators"
    __table_args__ = (UniqueConstraint("finding_id", "kind", "value"),
                      Index("ix_finding_indicators_lookup", "brand_id", "kind", "value"))
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"))
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    value: Mapped[str] = mapped_column(String(500))
    source: Mapped[str] = mapped_column(String(200))  # where in the finding's evidence it was seen
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    """Raised each time a finding meets the alert rule: first crossing, meaningful change or reopen (D-34, D-36)."""
    __tablename__ = "alerts"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"))
    observation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("observations.id", ondelete="SET NULL"))
    trigger: Mapped[str] = mapped_column(String(20))  # first_crossing | change | reopen | migrated
    reason: Mapped[str] = mapped_column(Text)
    score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "risk_level"))
    reasons: Mapped[dict] = mapped_column(JSONB, default=dict)  # scoring rules that fired at alert time
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    finding: Mapped[Finding] = relationship(back_populates="alerts")
    brand: Mapped[Brand] = relationship()


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    observation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("observations.id", ondelete="SET NULL"))
    kind: Mapped[EvidenceKind] = mapped_column(_enum(EvidenceKind, "evidence_kind"))
    storage_key: Mapped[str | None] = mapped_column(String(500))
    content_type: Mapped[str | None] = mapped_column(String(100))
    sha256: Mapped[str | None] = mapped_column(String(64))
    size: Mapped[int | None] = mapped_column(Integer)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class FindingEvent(Base):
    """Timeline: discovered | promoted | changed | rescored | stage | alerted | decision | reopened | app_status."""
    __tablename__ = "finding_events"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    observation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("observations.id", ondelete="SET NULL"))
    alert_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(30), default="decision")
    from_status: Mapped[str | None] = mapped_column(String(30))
    to_status: Mapped[str | None] = mapped_column(String(30))
    note: Mapped[str | None] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="events")
    user: Mapped[User | None] = relationship()


class DomainCheck(Base):
    __tablename__ = "domain_checks"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    fuzzer: Mapped[str | None] = mapped_column(String(50))
    registered: Mapped[bool] = mapped_column(Boolean, default=False)
    a_records: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    mx_records: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    ns_records: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    whois: Mapped[dict] = mapped_column(JSONB, default=dict)
    http_status: Mapped[int | None] = mapped_column(Integer)
    final_url: Mapped[str | None] = mapped_column(String(2000))
    title: Mapped[str | None] = mapped_column(String(1000))
    ssl: Mapped[dict] = mapped_column(JSONB, default=dict)
    favicon_mmh3: Mapped[int | None] = mapped_column(Integer)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AppListing(Base):
    __tablename__ = "app_listings"
    __table_args__ = (UniqueConstraint("brand_id", "store", "package"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    store: Mapped[str] = mapped_column(String(50))
    package: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(500))
    publisher: Mapped[str | None] = mapped_column(String(500))
    installs: Mapped[str | None] = mapped_column(String(50))
    version: Mapped[str | None] = mapped_column(String(100))
    updated: Mapped[str | None] = mapped_column(String(100))
    state: Mapped[str] = mapped_column(String(20), default="new")  # new | updated | unchanged | removed
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------------------------------------- phishing email (D-28)
class EmailMessage(Base):
    """One analysed email. The raw message is stored in the evidence bucket."""

    __tablename__ = "email_messages"
    __table_args__ = (UniqueConstraint("brand_id", "fingerprint", name="uq_email_fingerprint"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(500))  # Message-ID, else SHA-256 of the raw message
    channel: Mapped[str] = mapped_column(String(30))  # upload | mailbox | graph | gmail
    message_id: Mapped[str | None] = mapped_column(String(1000))
    subject: Mapped[str | None] = mapped_column(String(2000))
    from_addr: Mapped[str | None] = mapped_column(String(500))
    reply_to: Mapped[str | None] = mapped_column(String(500))
    return_path: Mapped[str | None] = mapped_column(String(500))
    sender_ip: Mapped[str | None] = mapped_column(String(64))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    auth: Mapped[dict] = mapped_column(JSONB, default=dict)
    raw_storage_key: Mapped[str | None] = mapped_column(String(500))
    raw_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued | analysed | failed
    error: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    analysed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EmailIndicator(Base):
    """A URL / domain / IP / attachment found in an email, with every tool's verdict."""

    __tablename__ = "email_indicators"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("email_messages.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # url | domain | ip | attachment
    value: Mapped[str] = mapped_column(String(2000), index=True)
    verdicts: Mapped[list] = mapped_column(JSONB, default=list)
    malicious_sources: Mapped[int] = mapped_column(Integer, default=0)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DmarcReport(Base):
    """One row of a DMARC aggregate report: a source IP sending as the brand domain."""

    __tablename__ = "dmarc_reports"
    __table_args__ = (UniqueConstraint("report_id", "source_ip", "header_from", name="uq_dmarc_row"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    report_id: Mapped[str] = mapped_column(String(500))
    org_name: Mapped[str | None] = mapped_column(String(500))
    domain: Mapped[str] = mapped_column(String(255), index=True)
    policy: Mapped[str | None] = mapped_column(String(20))
    begin: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(Integer, default=0)
    header_from: Mapped[str | None] = mapped_column(String(255))
    disposition: Mapped[str | None] = mapped_column(String(20))
    dkim_result: Mapped[str | None] = mapped_column(String(20))
    spf_result: Mapped[str | None] = mapped_column(String(20))
    dmarc_pass: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MailSource(Base):
    """A configured email intake for a brand. Credentials stay in .env, referenced by `config_key`."""

    __tablename__ = "mail_sources"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("brands.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # imap_reports | imap_dmarc | graph | gmail
    config_key: Mapped[str] = mapped_column(String(100))  # prefix of the .env settings, e.g. IMAP / DMARC_IMAP
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
