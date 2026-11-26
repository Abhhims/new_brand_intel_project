"""Name similarity used by every module: domains, app names, packages, social handles."""

import re
import unicodedata
from functools import lru_cache

import idna
import tldextract
from rapidfuzz import fuzz

# Offline public-suffix list (bundled snapshot), so workers never block on a download
_extract = tldextract.TLDExtract(suffix_list_urls=())
# Same list including the private section (vercel.app, web.app, github.io, blogspot.com...): each customer of a hosting
# platform owns its own name there, so 'axisofficial.web.app' is one site, not a page of 'web.app'
_extract_private = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

# Characters attackers swap for Latin letters. Values are the Latin letter(s) they imitate.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q",
    "ԝ": "w", "ɡ": "g", "ⅼ": "l",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x",
    # Digits / symbols
    "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
}
_MULTI = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]
PARTIAL_MIN = 85
_AMBIGUOUS = {"1": ("l", "i"), "|": ("l", "i"), "!": ("i", "l")}


def to_unicode_domain(domain: str) -> str:
    try:
        return idna.decode(domain)
    except idna.IDNAError:
        try:
            return domain.encode("ascii").decode("idna")
        except UnicodeError:
            return domain


def _base_fold(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).lower()
    text = "".join(_CONFUSABLES.get(ch, ch) for ch in text)
    # strip accents: é -> e
    text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    return text


@lru_cache(maxsize=50_000)
def fold_homoglyphs(text: str) -> tuple[str, ...]:
    """All plausible Latin readings of `text` (ambiguous glyphs like '1' give l and i)."""
    base = _base_fold(text)
    variants = {""}
    for ch in base:
        options = _AMBIGUOUS.get(ch, (ch,))
        variants = {v + o for v in variants for o in options}
        if len(variants) > 64:  # bound the blow-up on pathological input
            variants = set(list(variants)[:64])
    out = set(variants)
    for v in variants:
        for a, b in _MULTI:
            start = v.find(a)
            while start != -1:  # each occurrence on its own ('rnodern' -> 'modern'), then all
                out.add(v[:start] + b + v[start + len(a):])
                start = v.find(a, start + 1)
            if a in v:
                out.add(v.replace(a, b))
    return tuple(sorted(out))


def domain_label(domain_or_url: str) -> str:
    """Registrable label: 'login.example-secure.co.in' -> 'example-secure'."""
    parts = _extract(to_unicode_domain(domain_or_url.strip().lower()))
    return parts.domain or domain_or_url


def registered_domain(domain_or_url: str) -> str:
    parts = _extract(domain_or_url.strip().lower())
    return parts.top_domain_under_public_suffix or parts.domain


def site_domain(host: str) -> str:
    """Site a hostname belongs to, hosting platforms included: 'x.axisofficial.web.app' -> 'axisofficial.web.app',
    'login.example.co.in' -> 'example.co.in'."""
    parts = _extract_private(host.strip().lower())
    return parts.top_domain_under_public_suffix or registered_domain(host)


def hosting_platform(host: str) -> str | None:
    """'axisofficial.web.app' -> 'web.app' (a site on a shared hosting platform); None for an ordinary domain."""
    plain, private = _extract(host.strip().lower()), _extract_private(host.strip().lower())
    return plain.top_domain_under_public_suffix if private.suffix != plain.suffix else None


def host_labels(host: str) -> list[str]:
    """Name parts an owner chose, without the public/platform suffix:
    'uat-axis-pay.rewardkartshop.in' -> ['uat-axis-pay', 'rewardkartshop']; 'axisofficial.web.app' -> ['axisofficial']."""
    parts = _extract_private(to_unicode_domain(host.strip().lower()))
    return [x for x in (parts.subdomain.split(".") if parts.subdomain else []) + [parts.domain]
            if x and x != "www"]


def _clean(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text)


def similarity(candidate: str, target: str) -> float:
    """0-100 similarity of `candidate` to brand term `target`, robust to homoglyphs and add-ons.

    Uses the best of: full ratio (typos) and partial ratio (brand embedded with prefixes/suffixes,
    only when the brand term is long enough for that to be meaningful).
    """
    if not candidate or not target:
        return 0.0
    target_clean = _clean(_base_fold(target))
    best = 0.0
    for reading in fold_homoglyphs(candidate):
        c = _clean(reading)
        if not c:
            continue
        best = max(best, fuzz.ratio(c, target_clean))
        if len(target_clean) >= 4 and len(c) > len(target_clean):
            # Only count an embedded match when the brand is (nearly) intact inside the name;
            # low partial scores are noise between unrelated words.
            partial = fuzz.partial_ratio(target_clean, c)
            if partial >= PARTIAL_MIN:
                best = max(best, partial)
        if best >= 100:
            break
    return round(best, 2)


def best_similarity(candidate: str, targets: list[str]) -> tuple[float, str | None]:
    best, which = 0.0, None
    for t in targets:
        s = similarity(candidate, t)
        if s > best:
            best, which = s, t
    return best, which


def brand_terms_in_text(text: str, terms: list[str]) -> list[str]:
    """Brand terms that appear in `text` (case-insensitive, separators ignored, homoglyph-folded)."""
    if not text:
        return []
    hay = " ".join(_base_fold(text).replace("-", " ").replace("_", " ").split())
    found = []
    for term in terms:
        needle = " ".join(_base_fold(term).replace("-", " ").replace("_", " ").split())
        if needle and re.search(rf"(?<![a-z0-9]){re.escape(needle)}", hay):
            found.append(term)
    return found
