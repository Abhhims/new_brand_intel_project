import type { AutoRunner, AutoScanFrequency, Decision, FindingStage, AllowKind, AssetKind, ComponentStatus, ModuleName, RiskLevel, ScanStatus } from "@/lib/api"

/** Modules an analyst can start a scan for. */
export const MODULES: ModuleName[] = [
  "typosquat",
  "mx",
  "phishing",
  "apk",
  "rogue_app",
  "social",
  "social_media",
  "documents",
  "logo",
]

/** Phishing-email modules (D-28). Alerts appear in the queue but these are not run from the scan dialog. */
export const EMAIL_MODULES: ModuleName[] = ["email", "email_posture", "dmarc"]

/** Every module that can appear in the alert queue, for the queue's module filter. */
export const ALERT_MODULES: ModuleName[] = [...MODULES, ...EMAIL_MODULES]

export const MODULE_LABELS: Record<ModuleName, string> = {
  typosquat: "Typosquat Monitoring",
  mx: "MX Record Monitoring",
  phishing: "Active Phishing Detection",
  apk: "Fake APK Monitoring",
  rogue_app: "Rogue Mobile App Monitoring",
  social: "Social Media Impersonation",
  social_media: "Social Media Brand Misuse",
  documents: "Sensitive Document Monitoring",
  logo: "Brand Logo on Websites",
  email: "Phishing Email Analysis",
  email_posture: "Email Domain Security",
  dmarc: "DMARC Spoofing Reports",
}

/** Compact names for chart axes and tight table cells. */
export const MODULE_SHORT: Record<ModuleName, string> = {
  typosquat: "Typosquat",
  mx: "MX records",
  phishing: "Phishing",
  apk: "Fake APK",
  rogue_app: "Rogue apps",
  social: "Social",
  social_media: "Social misuse",
  documents: "Documents",
  logo: "Logo use",
  email: "Email",
  email_posture: "Email posture",
  dmarc: "DMARC",
}

export function moduleLabel(m: string): string {
  return MODULE_LABELS[m as ModuleName] ?? m
}

export const RISK_LEVELS: RiskLevel[] = ["Critical", "High", "Medium", "Low"]
export const RISK_RANK: Record<RiskLevel, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 }

/** Analyst decisions on a finding (backend D-35). */
export const STATUSES: Decision[] = [
  "New",
  "Investigating",
  "Confirmed Threat",
  "False Positive",
  "Legitimate",
  "Ignored",
  "Resolved",
]
export const DECISIONS = STATUSES
export const OPEN_STATUSES: Decision[] = ["New", "Investigating", "Confirmed Threat"]
export const STAGES: FindingStage[] = ["Candidate", "Finding"]

export const TRANSITIONS: Record<Decision, Decision[]> = {
  New: ["Investigating", "Confirmed Threat", "False Positive", "Legitimate", "Ignored"],
  Investigating: ["New", "Confirmed Threat", "False Positive", "Legitimate", "Ignored"],
  "Confirmed Threat": ["Investigating", "Resolved"],
  "False Positive": ["New", "Investigating"],
  Legitimate: ["New", "Investigating"],
  Ignored: ["New", "Investigating"],
  Resolved: ["New", "Investigating"],
}

/** Decisions the backend refuses without a note. */
export const NOTE_REQUIRED = new Set<Decision>(["False Positive", "Legitimate", "Ignored"])

/** Modules whose entity can be added to the brand allowlist when marked Legitimate. */
export const ALLOWLIST_MODULES = new Set<string>(["typosquat", "mx", "phishing", "rogue_app", "apk", "social"])

/** Button label for moving to a decision from the current one ("New" from a closed decision = reopen). */
export function decisionAction(from: Decision, to: Decision): string {
  if (to === "New") return "Reopen"
  if (to === "Investigating") return from === "New" ? "Start investigating" : "Investigate"
  if (to === "Confirmed Threat") return "Confirm threat"
  if (to === "False Positive") return "False positive"
  if (to === "Legitimate") return "Legitimate"
  if (to === "Ignored") return "Ignore"
  return "Resolve"
}

export const TRIGGER_LABELS: Record<string, string> = {
  first_crossing: "First crossed the alert level",
  change: "Changed materially",
  reopen: "Reopened",
  migrated: "Migrated from before findings",
}

export const AUTO_FREQUENCIES: { value: AutoScanFrequency; label: string }[] = [
  { value: "daily", label: "Daily" },
  { value: "every_3_days", label: "Every 3 days" },
  { value: "weekly", label: "Weekly" },
]
export const AUTO_FREQUENCY_LABELS: Record<AutoScanFrequency, string> = {
  daily: "Daily",
  every_3_days: "Every 3 days",
  weekly: "Weekly",
}

/** Scanners a brand can choose for automatic scans (backend AutoRunner). */
export const AUTO_RUNNERS: { value: AutoRunner; label: string }[] = [
  { value: "domains", label: "Domains & phishing sites" },
  { value: "apk", label: "Fake APK" },
  { value: "rogue_app", label: "Google Play apps" },
  { value: "social", label: "Social impersonation" },
  { value: "social_media", label: "Social media (uses API quota)" },
  { value: "documents", label: "Sensitive documents" },
  { value: "logo", label: "Logo on websites" },
  { value: "email_posture", label: "Email security" },
]

export const ASSET_KINDS: { value: AssetKind; label: string; hint: string }[] = [
  { value: "logo", label: "Logo", hint: "Matched against website images and screenshots" },
  { value: "favicon", label: "Favicon", hint: "Matched against favicons of suspicious domains" },
  { value: "app_icon", label: "App icon", hint: "Matched against app store and APK icons" },
]

export const ALLOW_KINDS: { value: AllowKind; label: string; placeholder: string }[] = [
  { value: "domain", label: "Official domains", placeholder: "example.com" },
  { value: "email_domain", label: "Email domains", placeholder: "mail.example.com" },
  { value: "package", label: "App packages", placeholder: "com.example.app" },
  { value: "publisher", label: "App publishers", placeholder: "Example Bank Ltd" },
  { value: "social_handle", label: "Social handles", placeholder: "examplebank or a profile URL" },
  {
    value: "signing_cert",
    label: "App signing certificates (SHA-256)",
    placeholder: "Play Console → App integrity → App signing key certificate SHA-256",
  },
]

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  partially_completed: "Partially completed",
  completed_with_errors: "Completed with errors",
  failed: "Failed",
  cancelled: "Cancelled",
}

/** Plain-English meaning of each scan state (backend D-31), shown as a tooltip. */
export const SCAN_STATUS_HELP: Record<ScanStatus, string> = {
  queued: "Waiting for a worker.",
  running: "The scan is in progress.",
  completed: "Every part of the scan ran successfully.",
  partially_completed:
    "The scan ran, but some sources were not configured or unavailable, so coverage was reduced. Results are real but incomplete.",
  completed_with_errors: "The scan ran, but some lookups or captures failed part-way. Results are real but incomplete.",
  failed: "The scan could not produce results. Nothing was checked, so this is not a clean result.",
  cancelled: "The scan was interrupted (worker restart or timeout). A newer scan replaces it.",
}

export const COMPONENT_STATUS_LABELS: Record<ComponentStatus, string> = {
  ok: "Completed",
  skipped: "Skipped",
  not_configured: "Not configured",
  unavailable: "Unavailable",
  failed: "Failed",
}

/** Platforms the social_media module searches (details["Platform"]). */
export const SOCIAL_PLATFORMS = [
  "YouTube",
  "Facebook",
  "Instagram",
  "X",
  "Threads",
  "Meta Ads",
  "Pinterest",
  "TikTok",
  "LinkedIn",
  "Telegram",
] as const

/** Content types reported by the social_media module (details["Content Type"]). */
export const SOCIAL_CONTENT_TYPES = ["Video", "Post", "Ad", "Channel", "Account"] as const

/** Human names for scoring rules (backend app/core/scoring.py RULE_POINTS). */
export const RULE_LABELS: Record<string, string> = {
  brand_exact_in_domain: "Brand name appears exactly in the domain",
  typo_similarity_gt_80: "Typo similarity above 80%",
  mx_present: "Domain can receive email (MX present)",
  https: "Serves HTTPS",
  login_payment_keywords: "Login or payment keywords on the page",
  official_logo: "Uses the official brand logo",
  social_image_match: "Profile image matches the brand",
  publisher_mismatch: "Publisher is not the official publisher",
  doc_brand_keyword: "Document mentions the brand",
  doc_official_domain: "Document references an official domain",
  doc_sensitive_pattern: "Document contains sensitive patterns",
  doc_many_emails: "Document lists many email addresses",
  // Social media brand misuse (social_media)
  brand_in_content: "Brand name used in the content, account or channel name",
  scam_contact_details: "Phone, WhatsApp, Telegram or UPI contact published next to the brand",
  scam_language: "Wrong-details scam wording (update your KYC, account blocked, guaranteed returns, fees)",
  paid_ad: "A paid advertisement",
  fake_support_claim: "Claims to be the brand's customer care / helpline / toll-free number",
  brand_abuse: "Brand abuse: earning or referral bait, cashback lure, unofficial APK",
  // Phishing-email analysis (app/modules/email, spec §4)
  known_malicious_url: "A link is listed by two or more threat sources",
  single_source_url_hit: "A link is listed by one threat source",
  malware_attachment: "An attachment is known malware",
  suspicious_attachment: "An attachment looks dangerous (macro, script or double extension)",
  auth_fail_brand_from: "Sent from an official brand domain but DMARC failed (spoofing)",
  lookalike_sender: "Sender, Reply-To or link uses a look-alike of the brand domain",
  brand_impersonation: "Uses brand terms or logo but was not sent from an official domain",
  reply_to_mismatch: "Reply-To or Return-Path differs from the sender and is not official",
  credential_or_payment_language: "Login, payment or urgency language",
  young_domain: "Sender or link domain was registered less than 30 days ago",
  bad_sender_ip: "Sender IP has a poor abuse reputation",
  rspamd_phish: "Rspamd flagged the message as phishing or spam",
  live_phishing_page: "A linked page analysed as suspected phishing",
  // Email-domain posture (email_posture) and look-alike email readiness
  lookalike_can_send: "Look-alike domain is configured to send email",
  posture_dmarc_missing: "No usable DMARC record (missing, duplicate or invalid)",
  posture_dmarc_none: "DMARC policy is p=none (monitor only, no protection)",
  posture_spf_missing: "No SPF record, or SPF allows any sender (+all)",
  posture_spf_softfail: "SPF ends in ~all (soft fail only)",
  posture_dkim_missing: "No DKIM key found on common selectors",
  posture_mta_sts_missing: "No MTA-STS policy",
}

/** Module output fields, in requirement order (backend app/modules/registry.py OUTPUT_FIELDS). */
const DOMAIN_FIELDS = [
  "Domain", "Similarity Score", "MX Enabled", "Website Live", "SSL Present", "Screenshot", "Risk Level",
  "Email Risk", "Suspected Phishing", "Fuzzer", "Registered", "Registrar", "Created", "MX Records", "A Records",
  "Page Title", "HTTP Status", "Final URL", "Favicon Match", "Keywords Found", "SSL Issuer", "SSL Expires",
  "Logo Match Score", "Discovery Source",
]

export const OUTPUT_FIELDS: Record<ModuleName, string[]> = {
  typosquat: DOMAIN_FIELDS,
  mx: DOMAIN_FIELDS,
  phishing: DOMAIN_FIELDS,
  apk: [
    "App Name", "Package Name", "Similarity Score", "Source", "Logo Match", "Risk Level", "Version", "Developer",
    "SHA256", "Logo Match Score", "Package Similarity", "Name Similarity", "Official Package", "Suspicious Developer",
  ],
  rogue_app: [
    "Store", "App Name", "Publisher", "Official Publisher Match", "Install Count", "Risk Level", "Package Name",
    "App Status", "Similarity Score", "Logo Match", "Brand Terms Used", "Store URL", "Last Updated",
  ],
  social: [
    "Platform", "Username", "Display Name", "Similarity Score", "Logo Match", "Followers", "Risk Level",
    "Profile URL", "Bio", "Bio Mentions Brand", "Support Terms", "Logo Match Score", "Discovery Source",
  ],
  social_media: [
    "Platform", "Content Type", "Title", "Author", "Author URL", "URL", "Published", "Risk Level", "Views", "Likes",
    "Comments", "Subscribers", "Videos", "Reposts", "Shown On", "Stopped", "Brand Terms", "Logo Match",
    "Logo Match Score", "Scam Contacts", "Scam Phrases", "Text Excerpt", "Discovery Source",
  ],
  documents: [
    "Document Name", "File Type", "URL", "Brand Match", "Exposure Confidence", "Risk Level", "Sensitive Patterns",
    "Emails Found", "Domains Found", "SHA256", "Discovery Source",
  ],
  logo: ["Website", "Page URL", "Logo Match Score", "Screenshot", "Risk Level", "Matched Image URL", "Official Asset"],
  email: [
    "Subject", "From", "Sender Domain", "Reply-To", "Return-Path", "Sender IP", "Risk Level", "Verdict", "SPF",
    "DKIM", "DMARC", "Rspamd", "URLs", "Malicious URLs", "Attachments", "Malicious Attachments", "Brand Match",
    "Look-alike Domains", "Language Flags", "Not Checked", "Channel", "Received", "Official Sender",
  ],
  email_posture: [
    "Domain", "Risk Level", "DMARC Record", "DMARC Policy", "DMARC Issues", "SPF Record", "SPF Issues",
    "DKIM Selectors Found", "MTA-STS", "Summary",
  ],
  dmarc: [
    "Domain", "Source IP", "Reporting Organisation", "Messages", "SPF", "DKIM", "Disposition", "Risk Level",
    "Report Period",
  ],
}

/** Fields whose values are technical identifiers and read better in monospace. */
export const MONO_FIELDS = new Set([
  "Domain", "MX Records", "A Records", "Final URL", "Package Name", "SHA256", "Official Package", "Username",
  "Profile URL", "Author URL", "Scam Contacts", "URL", "Store URL", "Page URL", "Matched Image URL", "Website", "Domains Found", "Emails Found",
  "Sender Domain", "Sender IP", "Return-Path", "DMARC Record", "SPF Record", "Source IP", "Look-alike Domains",
])
