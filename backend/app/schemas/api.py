"""Request/response models for the REST API (FND-08, DEL-04)."""

import uuid
from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.db.models import AllowKind, AssetKind, FindingDecision, FindingStage, ModuleName, RiskLevel, Role, ScanStatus

# Internal analyst accounts often use internal domains (e.g. *.local), which strict validators reject
Email = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=320,
                                          pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]


AutoScanFrequency = Literal["daily", "every_3_days", "weekly"]
AutoRunner = Literal["domains", "apk", "rogue_app", "social", "social_media", "documents", "logo", "email_posture"]


class AutoScanSettings(BaseModel):
    """Master switch for scheduled scans (D-39). Brands still need their own switch on."""
    enabled: bool
    updated_at: datetime | None = None
    brands_enabled: int = 0
    brands_total: int = 0
    schedule_utc: str = "02:00 daily check; domains re-checked every 6 h for brands on a daily frequency"


class AutoScanSettingsIn(BaseModel):
    enabled: bool


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------- auth / users
class LoginIn(BaseModel):
    email: Email
    password: str


class UserOut(ORM):
    id: uuid.UUID
    email: str
    name: str
    role: Role
    is_active: bool
    created_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class UserCreate(BaseModel):
    email: Email
    name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=10)
    role: Role = Role.analyst


class UserUpdate(BaseModel):
    name: str | None = None
    password: str | None = Field(default=None, min_length=10)
    role: Role | None = None
    is_active: bool | None = None


# ---------------------------------------------------------------- brands
class AssetOut(ORM):
    id: uuid.UUID
    kind: AssetKind
    filename: str
    content_type: str
    sha256: str
    phash: str | None
    mmh3: int | None
    created_at: datetime
    url: str | None = None


class AllowOut(ORM):
    id: uuid.UUID
    kind: AllowKind
    value: str


class AllowIn(BaseModel):
    kind: AllowKind
    value: str = Field(min_length=1, max_length=500)


class BrandIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    keywords: list[str] = Field(default_factory=list)
    product_terms: list[str] = Field(default_factory=list)
    is_active: bool = True
    alert_min_level: RiskLevel = RiskLevel.medium
    auto_scan_enabled: bool = False
    auto_scan_frequency: AutoScanFrequency = "daily"
    auto_scan_runners: list[AutoRunner] | None = None  # None = every scanner
    allowlist: list[AllowIn] = Field(default_factory=list)


class BrandUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    description: str | None = None
    keywords: list[str] | None = None
    product_terms: list[str] | None = None
    is_active: bool | None = None
    alert_min_level: RiskLevel | None = None
    auto_scan_enabled: bool | None = None
    auto_scan_frequency: AutoScanFrequency | None = None
    auto_scan_runners: list[AutoRunner] | None = None


class BrandOut(ORM):
    id: uuid.UUID
    name: str
    description: str | None
    keywords: list[str]
    product_terms: list[str]
    is_active: bool
    alert_min_level: RiskLevel = RiskLevel.medium
    auto_scan_enabled: bool = False
    auto_scan_frequency: str = "daily"
    auto_scan_runners: list[str] = []
    last_auto_scan_at: datetime | None = None
    next_auto_scan_at: datetime | None = None
    created_at: datetime
    assets: list[AssetOut] = []
    allowlist: list[AllowOut] = []
    open_alerts: int = 0


# ---------------------------------------------------------------- scans
class ScanIn(BaseModel):
    brand_id: uuid.UUID
    modules: list[ModuleName] | None = None  # None = all modules
    # Optional date range (D-50): only content published / domains registered or seen in it
    date_from: date | None = None
    date_to: date | None = None

    @model_validator(mode="after")
    def _range(self):
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("'From' date must be on or before the 'To' date")
        return self


class ScanOut(ORM):
    id: uuid.UUID
    brand_id: uuid.UUID
    brand_name: str | None = None
    module: ModuleName
    trigger: str
    status: ScanStatus
    started_at: datetime | None
    finished_at: datetime | None
    stats: dict
    components: list[dict] = []
    error: str | None
    created_at: datetime


class IntegrationOut(BaseModel):
    id: str
    name: str
    category: str
    modules: list[str]
    configured: bool
    how_to_configure: str
    last_status: str | None = None  # ok | skipped | not_configured | unavailable | failed; None = never ran
    last_message: str | None = None
    last_checked_at: datetime | None = None


# ---------------------------------------------------------------- alerts
class EvidenceOut(ORM):
    id: uuid.UUID
    kind: str
    content_type: str | None
    sha256: str | None
    size: int | None
    meta: dict
    captured_at: datetime
    url: str | None = None


class EventOut(ORM):
    id: uuid.UUID
    kind: str
    from_status: str | None
    to_status: str | None
    note: str | None
    at: datetime
    user_name: str | None = None


class ObservationOut(ORM):
    id: uuid.UUID
    scan_id: uuid.UUID | None
    channel: str
    observed_at: datetime
    stage: FindingStage
    module: ModuleName
    score: int
    risk_level: RiskLevel
    state: dict


class AlertRecordOut(ORM):
    id: uuid.UUID
    finding_id: uuid.UUID
    scan_id: uuid.UUID | None
    trigger: str
    reason: str
    score: int
    risk_level: RiskLevel
    reasons: dict
    created_at: datetime


class FindingOut(ORM):
    """One entity (SP2): current state + the analyst decision."""
    id: uuid.UUID
    brand_id: uuid.UUID
    brand_name: str
    module: ModuleName
    entity_key: str
    stage: FindingStage
    title: str
    similarity: float | None
    score: int
    risk_level: RiskLevel
    decision: FindingDecision
    decision_note: str | None = None
    decided_at: datetime | None = None
    suspected_phishing: bool
    details: dict
    signals: dict
    state: dict = {}
    source_url: str | None
    first_seen: datetime
    last_seen: datetime
    last_alert_at: datetime | None = None
    updated_at: datetime
    thumbnail_url: str | None = None
    alert_count: int = 0


class FindingDetailOut(FindingOut):
    decided_by_name: str | None = None
    evidence: list[EvidenceOut] = []
    events: list[EventOut] = []
    observations: list[ObservationOut] = []
    alerts: list[AlertRecordOut] = []


class FindingPage(BaseModel):
    items: list[FindingOut]
    total: int
    page: int
    page_size: int


class AlertOut(ORM):
    """An alert record (why and when it was raised) with its finding's current state (RDA-13).
    `status` is the finding's current analyst decision."""
    id: uuid.UUID
    finding_id: uuid.UUID
    brand_id: uuid.UUID
    brand_name: str
    module: ModuleName
    entity_key: str
    stage: FindingStage
    title: str
    similarity: float | None
    score: int
    risk_level: RiskLevel
    status: FindingDecision
    suspected_phishing: bool
    details: dict
    signals: dict
    source_url: str | None
    first_seen: datetime
    last_seen: datetime
    updated_at: datetime
    alerted_at: datetime
    trigger: str
    reason: str
    scan_id: uuid.UUID | None = None
    thumbnail_url: str | None = None


class AlertDetailOut(AlertOut):
    evidence: list[EvidenceOut] = []
    events: list[EventOut] = []
    observations: list[ObservationOut] = []
    alerts: list[AlertRecordOut] = []
    decision_note: str | None = None


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int


class StatusChangeIn(BaseModel):
    """Set the finding's analyst decision (D-35). A note is required for False Positive, Legitimate and Ignored."""
    status: FindingDecision
    note: str | None = Field(default=None, max_length=2000)
    add_to_allowlist: bool = False


class DecisionIn(BaseModel):
    decision: FindingDecision
    note: str | None = Field(default=None, max_length=2000)
    add_to_allowlist: bool = False


class BulkDecisionIn(DecisionIn):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


# ---------------------------------------------------------------- stats
class ExecutiveStats(BaseModel):
    date: str
    total_alerts_today: int
    high_critical_alerts: int
    high_critical_today: int
    new_phishing_domains: int
    new_impersonation_accounts: int
    new_rogue_apps: int
    sensitive_document_exposures: int
    phishing_emails_today: int = 0
    spoofed_sender_attempts: int = 0
    open_alerts: int
    by_module: dict[str, int]
    by_risk: dict[str, int]
    by_status: dict[str, int]  # by analyst decision (D-35)
    candidates: int = 0  # Candidates not yet analysed into findings (D-33)
    findings_below_alert_level: int = 0  # analysed findings held back by the brand's alert level (D-34)
    # Scan coverage (D-31): "No threats detected" only means something if a scan actually completed
    last_completed_scan_at: datetime | None = None
    components_unavailable: int = 0  # non-ok components in the latest completed run of each brand/scanner
    scans_failed: int = 0  # brand/scanner pairs whose latest run failed or was cancelled (nothing checked)


class EmailOut(BaseModel):
    id: uuid.UUID
    brand_id: uuid.UUID
    subject: str | None
    from_addr: str | None
    sender_ip: str | None
    channel: str
    status: str
    received_at: datetime
    risk_level: str | None = None
    score: int | None = None
    finding_id: uuid.UUID | None = None
    verdict: str | None = None


class EmailDetailOut(EmailOut):
    indicators: list[dict] = []
    not_checked: list[dict] = []
    finding: "FindingDetailOut | None" = None


class EmailPage(BaseModel):
    items: list[EmailOut]
    total: int
    page: int
    page_size: int


class TrendPoint(BaseModel):
    date: str
    total: int
    low: int
    medium: int
    high: int
    critical: int


class RelatedFindingOut(BaseModel):
    """Another finding that shares an identifier with this one (SP4, D-49). `strong` = points to one operator;
    weak links (shared IP, favicon) are shown but are not proof."""
    finding_id: uuid.UUID
    module: ModuleName
    entity_key: str
    title: str
    risk_level: RiskLevel
    score: int
    decision: FindingDecision
    kind: str
    label: str
    value: str
    strong: bool
    seen_in: str  # where in the other finding's evidence the value was seen


class CampaignFindingOut(BaseModel):
    finding_id: uuid.UUID
    module: ModuleName
    entity_key: str
    title: str
    risk_level: RiskLevel
    score: int
    decision: FindingDecision


class CampaignOut(BaseModel):
    """Findings connected by strong shared identifiers: probably one operator — not an attribution."""
    size: int
    shared: list[dict]
    findings: list[CampaignFindingOut]
