"""Pure text checks for social media content: scam contact details and scam wording (no network, easy to test)."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit


def normalize(text: str) -> str:
    """Undo look-alike lettering scammers use to dodge filters: 𝕔𝕦𝕤𝕥𝕠𝕞𝕖𝕣 𝕔𝕒𝕣𝕖 / 𝐍𝐚𝐯𝐢 / ９８７… → plain text, and
    digits of any script (Devanagari ९८७…) → 0-9."""
    text = unicodedata.normalize("NFKC", text or "")
    return "".join(str(unicodedata.digit(c)) if c.isdigit() and not c.isascii() else c for c in text)

# Indian mobile numbers (+91 optional) and toll-free numbers, plus international numbers written with a +
_PHONE_RE = re.compile(
    r"(?<![\w/])(?:\+?91[\s.-]?)?[6-9]\d{4}[\s.-]?\d{5}(?!\d)"
    r"|(?<![\w/])1[\s.-]?8[05]0[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
    r"|(?<![\w/])\+(?!91)\d{1,3}[\s.-]?\d{3,4}[\s.-]?\d{3,4}[\s.-]?\d{0,4}(?!\d)"
)
_WHATSAPP_RE = re.compile(r"(?:wa\.me/\+?\d+|api\.whatsapp\.com/send\?phone=\+?\d+|chat\.whatsapp\.com/[A-Za-z0-9]+)",
                          re.I)
_TELEGRAM_RE = re.compile(r"(?<![\w.])(?:t\.me|telegram\.me)/(?!s/)[A-Za-z0-9_+]{4,}", re.I)
# UPI virtual payment addresses: name@<bank/PSP handle>
_UPI_RE = re.compile(
    r"\b[\w.\-]{2,64}@(?:okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|upi|apl|yapl|ptsbi|pthdfc|ptaxis|ptyes"
    r"|fbl|airtel|jio|boi|sbi|icici|hdfcbank|axisbank|kotak|indus|federal|barodampay|ikwik|freecharge|naviaxis"
    r"|superyes|waaxis|wahdfcbank|waicici|wasbi)\b", re.I)

# Example handles apps and posts use to explain UPI ("pay to name@ybl"), not real payment addresses
_PLACEHOLDER_UPI = {"name", "yourname", "your.name", "username", "user", "example", "upiid", "upi", "mobile",
                    "mobilenumber", "number", "phone", "xyz", "abc", "test", "id", "yourupi", "youruid"}

# Social media criticality (see core/scoring.py): three groups of wording.
# 1. Fake support claim → Critical: the brand's "customer care / helpline number" published by someone else.
SUPPORT_PHRASES = [
    "customer care", "customer support", "customer service", "helpline", "help line", "toll free", "care number",
    "helpline number", "contact number", "complaint number", "whatsapp us", "contact us on whatsapp",
    "कस्टमर केयर", "कस्टमर सपोर्ट", "ग्राहक सेवा", "हेल्पलाइन", "टोल फ्री",
]
# Help videos often say "contact customer support in the app": in a description only an explicit number claim
# counts; in the title any support wording does (the video presents itself as the brand's customer care).
NUMBER_CLAIMS = {"care number", "helpline number", "contact number", "complaint number", "toll free", "टोल फ्री"}
# 2. Wrong-details scam wording → High.
WRONG_DETAILS_PHRASES = [
    "update your kyc", "account blocked", "account suspended", "verify your account",
    "guaranteed returns", "guaranteed return", "double your money", "double money", "fixed returns", "daily profit",
    "registration fee", "official agent", "authorised agent", "authorized agent", "lottery",
    "lucky draw", "you have won", "claim your", "refund call", "refund number",
]
# 3. Brand abuse → Medium: earning / referral bait, cashback lures, unofficial APKs, easy-loan promises.
ABUSE_PHRASES = [
    "refer and earn", "refer & earn", "referral", "earn money", "earning", "paise kamaye", "paisa kamaye",
    "paise kaise kamaye", "kamaye", "cashback", "apk", "mod apk", "free recharge",
    "loan without", "without cibil", "no documents", "work from home", "earn daily", "investment plan",
    "investment scheme", "invest now", "high returns", "free gift",
    "पैसे कमाए", "पैसे कमाएं", "कमाएं", "कमाई", "रेफर", "कैशबैक",
]
# Other wording shown to the analyst but not scored on its own (common in ordinary tutorials and loan explainers)
INFO_PHRASES = ["kyc", "kyc update", "kyc pending", "refund", "processing fee", "instant loan", "loan approval",
                "pre-approved loan", "call now", "dm for", "dm us", "franchise", "dealership", "job offer",
                "hiring now", "chit fund scheme", "chit scheme"]
SCAM_PHRASES = list(dict.fromkeys(SUPPORT_PHRASES + WRONG_DETAILS_PHRASES + ABUSE_PHRASES + INFO_PHRASES))
# Hashtags glue words together (#navicustomercare): these are also matched with spaces removed
_SQUASHED = {p: p.replace(" ", "") for p in ("customer care", "customer support", "customer service", "helpline",
                                             "toll free", "care number", "helpline number", "contact number")}


def _norm_phone(p: str) -> str:
    digits = re.sub(r"\D", "", p)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    return digits


def contact_details(text: str) -> dict[str, list[str]]:
    """Phone numbers, WhatsApp / Telegram links and UPI IDs found in the text."""
    text = normalize(text)
    phones = list(dict.fromkeys(_norm_phone(m.group(0)) for m in _PHONE_RE.finditer(text)))
    phones = [p for p in phones if 8 <= len(p) <= 13]
    out = {
        "phone": phones,
        "whatsapp": list(dict.fromkeys(m.group(0) for m in _WHATSAPP_RE.finditer(text))),
        "telegram": list(dict.fromkeys(m.group(0) for m in _TELEGRAM_RE.finditer(text))),
        "upi": list(dict.fromkeys(m.group(0).lower() for m in _UPI_RE.finditer(text)
                                  if m.group(0).split("@")[0].lower() not in _PLACEHOLDER_UPI)),
    }
    return {k: v[:10] for k, v in out.items() if v}


# Wording that on its own suggests fraud next to a brand name (fake support claim or wrong-details scam)
STRONG_SCAM_PHRASES = set(SUPPORT_PHRASES) | set(WRONG_DETAILS_PHRASES)
# Contact kinds that count as fake contact details. Telegram links are usually the video creator's own channel.
SCORED_CONTACTS = ("phone", "whatsapp", "upi")


def strong_phrases(phrases: list[str]) -> list[str]:
    return [p for p in phrases if p in STRONG_SCAM_PHRASES]


def support_phrases(phrases: list[str]) -> list[str]:
    return [p for p in phrases if p in SUPPORT_PHRASES]


def fake_support_claim(title_phrases: list[str], phrases: list[str]) -> bool:
    """Presents itself as the brand's customer care: support wording in the title, or a number claim anywhere."""
    return bool(support_phrases(title_phrases)) or any(p in NUMBER_CLAIMS for p in phrases)


def wrong_details_phrases(phrases: list[str]) -> list[str]:
    return [p for p in phrases if p in WRONG_DETAILS_PHRASES]


def abuse_phrases(phrases: list[str]) -> list[str]:
    return [p for p in phrases if p in ABUSE_PHRASES]


def scam_phrases(text: str) -> list[str]:
    low = re.sub(r"[\s\-_]+", " ", normalize(text).lower())
    squashed = re.sub(r"[^a-z]", "", low)
    return [p for p in SCAM_PHRASES if re.search(rf"(?<![a-z]){re.escape(p)}(?![a-z])", low)
            or (p in _SQUASHED and _SQUASHED[p] in squashed)]


def drop_official(contacts: dict[str, list[str]], official_domains: list[str], official_handles: list[str]) -> dict:
    """Contact details that point at the brand itself (its own Telegram handle) are not scam contacts."""
    handles = {h.lower() for h in official_handles}
    out = dict(contacts)
    if "telegram" in out:
        out["telegram"] = [t for t in out["telegram"] if t.split("/", 1)[-1].lower() not in handles]
        if not out["telegram"]:
            out.pop("telegram")
    return out


def platform_of(url: str) -> str | None:
    host = (urlsplit(url).hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    host = host[2:] if host.startswith("m.") else host
    table = [
        (("youtube.com", "youtu.be"), "YouTube"), (("instagram.com",), "Instagram"),
        (("facebook.com", "fb.com", "fb.watch"), "Facebook"), (("x.com", "twitter.com"), "X"),
        (("threads.net", "threads.com"), "Threads"), (("tiktok.com",), "TikTok"),
        (("linkedin.com",), "LinkedIn"), (("t.me", "telegram.me"), "Telegram"),
    ]
    for hosts, name in table:
        if any(host == h or host.endswith("." + h) for h in hosts):
            return name
    if host == "pinterest.com" or host.startswith("pinterest.") or ".pinterest." in host or host == "pin.it":
        return "Pinterest"
    return None


def content_type_of(platform: str, url: str) -> str:
    """video | post | channel | account, from the URL shape."""
    path = urlsplit(url).path.lower()
    parts = [p for p in path.split("/") if p]
    if platform == "YouTube":
        if "watch" in parts or "shorts" in parts or urlsplit(url).hostname in ("youtu.be",) or "live" in parts:
            return "video"
        return "channel"
    if platform == "Instagram":
        return "video" if "reel" in parts or "reels" in parts or "tv" in parts else (
            "post" if "p" in parts else "account")
    if platform == "Facebook":
        if any(p in parts for p in ("videos", "watch", "reel", "reels")) or "fb.watch" in url:
            return "video"
        return "post" if any(p in parts for p in ("posts", "permalink.php", "story.php", "photos", "share")) \
            else "account"
    if platform in ("X", "Threads"):
        return "post" if "status" in parts or "post" in parts else "account"
    if platform == "TikTok":
        return "video" if "video" in parts else "account"
    if platform == "Pinterest":
        return "post" if "pin" in parts else "account"
    if platform == "LinkedIn":
        return "post" if "posts" in parts or "feed" in parts or "pulse" in parts else "account"
    if platform == "Telegram":
        return "post" if len(parts) >= 2 and parts[-1].isdigit() else "account"
    return "post"
