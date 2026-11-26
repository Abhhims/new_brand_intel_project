"""Module catalogue: the Expected Output columns of each module (requirements §3) and the runners."""

from __future__ import annotations

from app.db.models import ModuleName

# The eight Phase-1 requirement modules (§2). Email modules (D-28) are tracked by their own requirement IDs.
PHASE1_MODULES = (ModuleName.typosquat, ModuleName.mx, ModuleName.phishing, ModuleName.apk, ModuleName.rogue_app,
                  ModuleName.social, ModuleName.documents, ModuleName.logo)

_DOMAIN_FIELDS = ["Domain", "Similarity Score", "MX Enabled", "Website Live", "SSL Present", "Screenshot",
                  "Risk Level", "Confidence", "Email Risk", "Suspected Phishing", "Fuzzer", "Registered", "Registrar",
                  "Created", "MX Records", "A Records", "Page Title", "HTTP Status", "Final URL",
                  "Favicon Match", "Keywords Found", "SSL Issuer", "SSL Expires", "Logo Match Score",
                  "Brand Evidence On Page", "Brand Terms On Page", "Official Site References", "Parked Page",
                  "Score Cap", "Threat Intel", "Discovery Source"]

# Column labels exactly as in the requirement tables first, then supporting fields.
OUTPUT_FIELDS: dict[ModuleName, list[str]] = {
    ModuleName.typosquat: _DOMAIN_FIELDS,
    ModuleName.mx: _DOMAIN_FIELDS,
    ModuleName.phishing: _DOMAIN_FIELDS,
    ModuleName.apk: ["App Name", "Package Name", "Similarity Score", "Source", "Logo Match", "Risk Level", "Confidence",
                     "Version", "Developer", "SHA256", "Logo Match Score", "Package Similarity",
                     "Name Similarity", "Official Package", "Suspicious Developer", "Signed By", "Signer SHA-256",
                     "Signer Matches Official", "Signature Schemes"],
    ModuleName.rogue_app: ["Store", "App Name", "Publisher", "Official Publisher Match", "Install Count",
                           "Risk Level", "Confidence", "Package Name", "App Status", "Similarity Score", "Logo Match",
                           "Brand Terms Used", "Store URL", "Last Updated", "Version", "Rating",
                           "Developer Email", "Developer Uses Free E-mail", "Developer Website", "Developer Address",
                           "Privacy Policy", "Scam Contacts", "Scam Phrases", "Description Excerpt"],
    ModuleName.social: ["Platform", "Username", "Display Name", "Similarity Score", "Logo Match", "Followers",
                        "Risk Level", "Confidence", "Profile URL", "Bio", "Bio Mentions Brand", "Support Terms",
                        "Logo Match Score", "Discovery Source"],
    ModuleName.documents: ["Document Name", "File Type", "URL", "Brand Match", "Exposure Confidence",
                           "Risk Level", "Confidence", "Sensitive Patterns", "Emails Found", "Domains Found", "SHA256",
                           "Discovery Source", "Hosted On Official Domain"],
    ModuleName.logo: ["Website", "Page URL", "Logo Match Score", "Screenshot", "Risk Level", "Confidence",
                      "Matched Image URL", "Official Asset"],
    ModuleName.email: ["Subject", "From", "Sender Domain", "Reply-To", "Return-Path", "Sender IP", "Risk Level", "Confidence",
                       "Verdict", "SPF", "DKIM", "DMARC", "Rspamd", "URLs", "Malicious URLs", "Attachments",
                       "Malicious Attachments", "Brand Match", "Look-alike Domains", "Language Flags",
                       "Not Checked", "Channel", "Received"],
    ModuleName.email_posture: ["Domain", "Risk Level", "Confidence", "DMARC Record", "DMARC Policy", "DMARC Issues", "SPF Record",
                               "SPF Issues", "DKIM Selectors Found", "MTA-STS", "Summary"],
    ModuleName.social_media: ["Platform", "Content Type", "Title", "Author", "Author URL", "URL", "Published",
                              "Risk Level", "Confidence", "Criticality Reason", "Views", "Likes", "Comments",
                              "Brand Terms", "Logo Match",
                              "Scam Contacts", "Scam Phrases", "Text Excerpt", "Discovery Source"],
    ModuleName.dmarc: ["Domain", "Source IP", "Reporting Organisation", "Messages", "SPF", "DKIM", "Disposition",
                       "Risk Level", "Confidence", "Report Period"],
}

MODULE_LABELS: dict[ModuleName, str] = {
    ModuleName.typosquat: "Typosquat Monitoring",
    ModuleName.mx: "MX Record Monitoring",
    ModuleName.phishing: "Active Phishing Detection",
    ModuleName.apk: "Fake APK Monitoring",
    ModuleName.rogue_app: "Rogue Mobile App Monitoring",
    ModuleName.social: "Social Media Impersonation",
    ModuleName.documents: "Sensitive Document Monitoring",
    ModuleName.logo: "Brand Logo on Websites",
    ModuleName.email: "Phishing Email Analysis",
    ModuleName.email_posture: "Email Domain Security",
    ModuleName.dmarc: "DMARC Spoofing Reports",
    ModuleName.social_media: "Social Media Brand Misuse",
}

# Which runner executes each scan. The domain pipeline covers typosquat + MX + phishing (D-19).
RUNNERS: dict[ModuleName, str] = {
    ModuleName.typosquat: "domains",
    ModuleName.mx: "domains",
    ModuleName.phishing: "domains",
    ModuleName.apk: "apk",
    ModuleName.rogue_app: "rogue_app",
    ModuleName.social: "social",
    ModuleName.documents: "documents",
    ModuleName.email_posture: "email_posture",
    ModuleName.logo: "logo",
    ModuleName.social_media: "social_media",
}


def get_runner(name: str):
    """Import lazily so the API process doesn't load heavy detection libraries."""
    if name == "domains":
        from app.modules.domains.module import DomainModule
        return DomainModule()
    if name == "apk":
        from app.modules.apk.module import ApkModule
        return ApkModule()
    if name == "rogue_app":
        from app.modules.rogue_app.module import RogueAppModule
        return RogueAppModule()
    if name == "social":
        from app.modules.social.module import SocialModule
        return SocialModule()
    if name == "social_media":
        from app.modules.social_media.module import SocialMediaModule
        return SocialMediaModule()
    if name == "documents":
        from app.modules.documents.module import DocumentsModule
        return DocumentsModule()
    if name == "logo":
        from app.modules.logo.module import LogoModule
        return LogoModule()
    if name == "email_posture":
        from app.modules.email.posture import PostureModule
        return PostureModule()
    raise KeyError(name)
