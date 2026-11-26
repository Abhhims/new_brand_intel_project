"""Typosquat variant generation (TYP-01…08) using dnstwist's fuzzers plus our own prefix/suffix list."""

from __future__ import annotations

import dnstwist

from app.config import get_settings
from app.core.similarity import registered_domain

# Attackers' favourite add-on words (TYP-05)
AFFIXES = ["login", "secure", "verify", "account", "support", "help", "online", "bank", "banking", "pay",
           "payment", "update", "auth", "my", "app", "portal", "service", "customer", "care", "kyc", "rewards",
           "offer", "offers", "web", "net", "mobile", "signin", "official", "netbanking", "card", "cards",
           "creditcard", "credit", "loan", "loans", "upi", "points", "cashback", "refund", "emi", "helpline",
           "otp", "ekyc", "verification", "corp", "bnk", "in", "india", "online-banking", "reward", "apply"]

# dnstwist fuzzer → requirement wording (shown to analysts and in the demo)
FUZZER_CATEGORY = {
    "omission": "Character omission",                    # TYP-01
    "replacement": "Character substitution",             # TYP-02
    "bitsquatting": "Character substitution",
    "vowel-swap": "Character substitution",
    "transposition": "Transposition",                    # TYP-03
    "homoglyph": "Homoglyph",                            # TYP-04
    "dictionary": "Added prefix/suffix",                 # TYP-05
    "hyphenation": "Added prefix/suffix",
    "subdomain": "Added prefix/suffix",
    "addition": "Character insertion",                   # TYP-06
    "insertion": "Character insertion",
    "repetition": "Character insertion",
    "plural": "Character insertion",
    "tld-swap": "TLD variation",                         # TYP-07
    "various": "Other pattern",
    "cyrillic": "Homoglyph",
    "certificate-transparency": "Certificate Transparency",
    "brand-subdomain": "Brand in subdomain",              # D-51 discovery sources
    "hosting-platform": "Site on a hosting platform",
    "urlscan": "urlscan.io public scans",
    "phishing-feed": "Phishing feed listing",
    "search-engine": "Web search",
    "commoncrawl": "Common Crawl archive",
    "certstream": "CertStream (new certificate)",
}

# Found by a discovery source rather than generated (D-51); the page decides, not name similarity
DISCOVERED = {"certificate-transparency", "brand-subdomain", "hosting-platform", "urlscan", "phishing-feed",
              "search-engine", "commoncrawl", "certstream"}

# Fuzzers we also apply across every monitored TLD (homoglyph/bitsquatting stay on the base TLD
# to keep the daily volume bounded)
CROSS_TLD_FUZZERS = {"omission", "replacement", "transposition", "dictionary", "hyphenation", "addition",
                     "insertion", "repetition", "vowel-swap", "plural"}

MAX_VARIANTS = 12_000


def _seed_domains(official_domains: list[str], keywords: list[str]) -> list[str]:
    seeds = [registered_domain(d) for d in official_domains if d]
    if not seeds:  # no official domain configured: use the main keyword on .com
        seeds = [k.lower().replace(" ", "") + ".com" for k in keywords[:1]]
    return list(dict.fromkeys(seeds))


# When over the cap, these (very numerous, lower-yield) fuzzers are dropped first
LOW_PRIORITY_FUZZERS = {"homoglyph", "bitsquatting"}


def generate_variants(official_domains: list[str], keywords: list[str],
                      tlds: list[str] | None = None, limit: int = MAX_VARIANTS) -> dict[str, str]:
    """Return {variant_domain: fuzzer} for the brand, highest-yield patterns first. Official domains excluded."""
    tlds = [t.lstrip(".").lower() for t in (tlds or get_settings().typo_tlds)]
    official = {registered_domain(d) for d in official_domains}
    first: dict[str, str] = {}
    later: dict[str, str] = {}
    for seed in _seed_domains(official_domains, keywords):
        label, _, base_tld = seed.partition(".")
        # The exact brand label on every monitored TLD (e.g. example.in) — the most common squat (TYP-07/08)
        for tld in tlds:
            first.setdefault(f"{label}.{tld}", "tld-swap")
        fuzzer = dnstwist.Fuzzer(seed, dictionary=AFFIXES, tld_dictionary=[t for t in tlds if t != base_tld])
        fuzzer.generate()
        for item in fuzzer.domains:
            name, kind = item["domain"].lower(), item["fuzzer"]
            if kind == "*original":
                continue
            (later if kind in LOW_PRIORITY_FUZZERS else first).setdefault(name, kind)
            if kind in CROSS_TLD_FUZZERS:
                stem = name[: -len(base_tld) - 1] if name.endswith("." + base_tld) else None
                if stem and "." not in stem:
                    for tld in tlds:
                        first.setdefault(f"{stem}.{tld}", kind)
    ordered = {d: k for d, k in {**later, **first}.items() if d not in official}
    ordered = {d: ordered[d] for d in [*first, *later] if d in ordered}
    return dict(list(ordered.items())[:limit])


def category(fuzzer: str) -> str:
    return FUZZER_CATEGORY.get(fuzzer, fuzzer.replace("-", " ").title())
