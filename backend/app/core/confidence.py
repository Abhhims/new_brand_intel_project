"""Confidence: how sure we are that a finding is a real brand threat — separate from risk (SP3, D-47, RDA-08).

Risk (app/core/scoring.py) says how bad it would be; confidence says how good the evidence is:
- independent kinds of evidence (name, page content, contact details, visuals, identity, threat intelligence) agree;
- the evidence was observed directly (page captured, platform data) rather than read from a search snippet;
- nothing that should have been checked is unknown (failed capture / lookup, source not configured);
- nothing contradicts it (parked page, live page about something else).
One pure function over facts that are stored with every finding, so stored findings can be re-assessed.
Every point is a named factor with a reason, kept with the score.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.db.models import ModuleName

CONFIDENCE_POLICY = "2026-10-16"
BASE = 20

# Independent kinds of evidence. A family counts once, however many of its rules fired, so one observation is
# never counted twice. Points = what that kind of evidence adds to our certainty.
FAMILIES: dict[str, tuple[int, str, frozenset[str]]] = {
    "content": (15, "The content itself shows abuse (login/payment form, scam or support wording, sensitive data)",
                frozenset({"login_payment_keywords", "scam_language", "fake_support_claim", "brand_abuse",
                           "credential_or_payment_language", "doc_sensitive_pattern", "doc_many_emails"})),
    "contact": (15, "Contact details published next to the brand (phone, WhatsApp, Telegram, UPI)",
                frozenset({"scam_contact_details"})),
    "visual": (15, "Official logo or favicon matched", frozenset({"official_logo", "social_image_match"})),
    "identity": (15, "Publisher / sender / signer is not the brand's (verified against official values)",
                 frozenset({"publisher_mismatch", "lookalike_sender", "auth_fail_brand_from"})),
    "infrastructure": (5, "Infrastructure is ready for abuse (mail server, TLS, SPF, young domain)",
                       frozenset({"mx_present", "https", "lookalike_can_send", "young_domain", "bad_sender_ip",
                                  "reply_to_mismatch"})),
}
NAME_RULES = frozenset({"brand_exact_in_domain", "typo_similarity_gt_80", "brand_in_content", "doc_brand_keyword",
                        "brand_impersonation", "doc_official_domain"})
POSTURE_MODULES = (ModuleName.email_posture, ModuleName.dmarc)
DOMAIN_MODULES = (ModuleName.typosquat, ModuleName.mx, ModuleName.phishing, ModuleName.logo)


@dataclass(frozen=True)
class Factor:
    name: str
    points: int
    why: str


@dataclass
class Confidence:
    score: int
    level: str
    factors: list[Factor] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"score": self.score, "level": self.level, "policy": CONFIDENCE_POLICY,
                "factors": [{"factor": f.name, "points": f.points, "why": f.why} for f in self.factors]}

    @property
    def label(self) -> str:
        return f"{self.level} ({self.score})"


def level_for(value: int) -> str:
    return "High" if value >= 70 else "Medium" if value >= 40 else "Low"


def assess(module: ModuleName, fired: set[str] | list[str], details: dict, *, analysed: bool,
           captured: bool, links: int = 0) -> Confidence:
    """`fired` = scoring rules that fired, `details` = the finding's output fields, `analysed` = Finding (not
    Candidate), `captured` = a screenshot or page/file was stored as evidence, `links` = other findings that share a
    strong identifier with this one (SP4, D-49)."""
    fired, d = set(fired), details or {}
    out: list[Factor] = []

    def add(name: str, points: int, why: str) -> None:
        out.append(Factor(name, points, why))

    if module in POSTURE_MODULES:
        add("direct_observation", 70, "Read directly from the domain's DNS records / DMARC reports")
        if d.get("Not Checked"):
            add("not_checked", -10, f"Not checked: {', '.join(map(str, d['Not Checked']))}")
        return _result(out)

    add("base", BASE, "Detected by an automated check")
    families = 0
    for name, (points, why, rules) in FAMILIES.items():
        if fired & rules:
            add(name, points, why)
            families += points >= 15
    if "known_malicious_url" in fired or "malware_attachment" in fired:
        add("threat_intel", 30, "Listed as malicious by two or more independent threat-intelligence sources")
        families += 1
    elif fired & {"single_source_url_hit", "rspamd_phish", "live_phishing_page", "suspicious_attachment"}:
        add("threat_intel_single", 10, "One threat-intelligence source or engine flags it (not corroborated)")
    if families == 0 and fired & NAME_RULES:
        add("name_only", -10, "Only the name matches; nothing else ties it to abuse of the brand")
    if families >= 2:
        add("corroborated", 10, f"{families} independent kinds of evidence agree")
    if links:
        add("correlated", 10, f"Shares a certificate, signer, contact or server with {links} other finding"
                              f"{'s' if links > 1 else ''} (same operator likely)")

    add("observed" if analysed else "candidate", 10 if analysed else -10,
        "Analysed with evidence (Finding)" if analysed else "Discovered only, not analysed yet (Candidate)")
    if captured:
        add("captured", 10, "Evidence captured directly (screenshot, page or file)")

    # coverage gaps: something that should have been checked is unknown
    if d.get("Website Live") == "unknown (capture failed)":
        add("capture_failed", -10, "Website could not be captured; page content unknown")
    if d.get("Registrar") == "lookup failed":
        add("whois_failed", -5, "Registration (WHOIS/RDAP) lookup failed")
    intel = str(d.get("Threat Intel") or "")
    if module in DOMAIN_MODULES and (intel == "Not checked" or "not checked:" in intel):
        add("intel_partial", -5, f"Threat intelligence incomplete: {intel}")
    if d.get("Not Checked"):
        add("not_checked", -10, f"Not checked: {', '.join(map(str, d['Not Checked']))}")
    if str(d.get("Discovery Source") or "").lower().startswith("web search"):
        add("snippet_only", -10, "Found through a search-result snippet, not platform data")
    if module == ModuleName.apk:
        match = d.get("Signer Matches Official")
        if match is False:
            add("signer_verified", 25, "Signing certificate verified as not the official one")
        elif match is None:
            add("signer_unknown", -10, "Signing certificate not verified")
    if module == ModuleName.documents and d.get("Exposure Confidence") in ("Low", "High"):
        high = d["Exposure Confidence"] == "High"
        add("exposure", 10 if high else -10, f"Document exposure confidence {d['Exposure Confidence']}")

    # contradictions
    if d.get("Parked Page") is True:
        add("parked", -20, "Parked / for-sale page: no active abuse seen")
    if d.get("Website Live") is True and d.get("Brand Evidence On Page") is False and d.get("Parked Page") is not True:
        add("no_brand_on_page", -15, "The live page shows no brand content")
    return _result(out)


def _result(factors: list[Factor]) -> Confidence:
    value = max(0, min(100, sum(f.points for f in factors)))
    return Confidence(score=value, level=level_for(value), factors=factors)
