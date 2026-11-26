"""Extract URLs from an email and turn redirect-wrapped / obfuscated links into their real target."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlsplit

from app.core.similarity import registered_domain
from app.modules.email.model import ImageRef, UrlRef

_URL_RE = re.compile(r"""(?xi)\b((?:https?://|www\.)[^\s<>"'\])}]+)""")
_TRAILING = ".,);:!?'\"”’>]}"


def deobfuscate_text(text: str) -> str:
    """Un-defang every link in a block of text (not just one URL)."""
    text = re.sub(r"h(xx|XX)tps?", lambda m: "http" + ("s" if m.group(0).lower().endswith("s") else ""), text)
    text = re.sub(r"h(xx|XX)p", "http", text)
    return text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[dot]", ".").replace("[:]", ":")


def deobfuscate(url: str) -> str:
    """hxxp://a[.]test/e → http://a.test/e; defang common tricks."""
    u = url.strip()
    u = re.sub(r"^h(xx|XX)p", "http", u)
    u = u.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[dot]", ".")
    u = u.replace("[:]", ":").replace("hxtp", "http")
    return u


def unwrap(url: str) -> str:
    """Resolve Microsoft Safe Links, Google redirects and Proofpoint URL Defense to the real target."""
    url = deobfuscate(url)
    for _ in range(3):  # wrappers can nest
        parts = urlsplit(url)
        host = parts.hostname or ""
        q = parse_qs(parts.query)
        nxt = None
        if "safelinks.protection.outlook.com" in host and "url" in q:
            nxt = unquote(q["url"][0])
        elif host.endswith("google.com") and parts.path == "/url" and ("q" in q or "url" in q):
            nxt = unquote((q.get("q") or q.get("url"))[0])
        elif "urldefense" in host or "proofpoint.com" in host:
            raw_u = q.get("u", [None])[0]
            if raw_u:
                token = unquote(raw_u)
                if "-" in token:  # v2 encoding: -3A -> :, -2F -> /, _ -> /, -25 -> %
                    token = token.replace("-3A", ":").replace("-2F", "/").replace("_", "/").replace("-25", "%")
                nxt = token
        if not nxt or nxt == url:
            break
        url = deobfuscate(nxt)
    return url


def _normalise(url: str) -> str:
    url = unwrap(url).rstrip(_TRAILING)
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self.images: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href", "").strip():
            self._href = a["href"].strip()
            self._text = []
        elif tag == "img" and a.get("src", "").strip():
            src = a["src"].strip()
            if src.lower().startswith(("http://", "https://")):
                self.images.append(src)

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def extract_urls(text: str, html: str = "") -> list[UrlRef]:
    out: dict[str, UrlRef] = {}

    def add(url: str, link_text: str, source: str) -> None:
        if not url.lower().startswith(("http://", "https://", "hxxp", "www.")):
            return
        normalised = _normalise(url)
        if not urlsplit(normalised).hostname:
            return
        mismatch = False
        if link_text and link_text.lower().startswith(("http", "www")):
            mismatch = registered_domain(link_text) != registered_domain(normalised)
        ref = out.get(normalised)
        if ref is None:
            out[normalised] = UrlRef(url=normalised, text=link_text, source=source, text_mismatch=mismatch)
        elif mismatch:
            ref.text_mismatch = True

    # scan a de-obfuscated copy so hxxps:// and [.] links in the body are found
    for raw in _URL_RE.findall(deobfuscate_text(text or "")):
        add(raw, "", "text")
    if html:
        collector = _LinkCollector()
        try:
            collector.feed(html)
        except Exception:  # noqa: BLE001 - never let malformed HTML break parsing
            pass
        for href, link_text in collector.links:
            add(href, link_text, "html")
        for raw in _URL_RE.findall(re.sub(r"<[^>]+>", " ", html)):
            add(raw, "", "html")
    return list(out.values())


def extract_images(html: str) -> list[ImageRef]:
    if not html:
        return []
    collector = _LinkCollector()
    try:
        collector.feed(html)
    except Exception:  # noqa: BLE001
        pass
    return [ImageRef(url=u) for u in dict.fromkeys(collector.images)]
