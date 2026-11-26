"""Headless browser capture (FND-11): screenshot, title, text, favicon and page images.

Runs only in the browser worker (queue "browser", its own container — decision D-18). Every
request the page makes is checked with the same destination rules as the safe fetcher; downloads
are refused and nothing from the page is ever executed outside the sandboxed browser.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from urllib.parse import urljoin

import structlog
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Route, sync_playwright

from app.config import get_settings
from app.core.fetch import BlockedDestination, FetchError, check_destination, try_fetch

log = structlog.get_logger(__name__)

MAX_IMAGES = 40
MAX_IMAGE_BYTES = 2 * 1024 * 1024


@dataclass
class PageImage:
    url: str
    data: bytes
    content_type: str | None = None


@dataclass
class PageCapture:
    url: str
    final_url: str
    status: int | None
    title: str
    text: str
    html: str
    screenshot: bytes | None
    favicon: bytes | None = None
    favicon_url: str | None = None
    has_password_field: bool = False
    form_actions: list[str] = field(default_factory=list)
    images: list[PageImage] = field(default_factory=list)
    error: str | None = None


_COLLECT_JS = """
() => {
  const abs = (u) => { try { return new URL(u, document.baseURI).href } catch { return null } };
  const icons = [...document.querySelectorAll('link[rel~="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]')]
      .map(l => abs(l.getAttribute('href'))).filter(Boolean);
  const imgs = new Set();
  document.querySelectorAll('img').forEach(i => { const u = abs(i.currentSrc || i.src); if (u) imgs.add(u) });
  document.querySelectorAll('*').forEach(el => {
    const bg = getComputedStyle(el).backgroundImage;
    const m = bg && bg.match(/url\\(["']?(.*?)["']?\\)/);
    if (m && m[1]) { const u = abs(m[1]); if (u) imgs.add(u) }
  });
  const svgs = [...document.querySelectorAll('svg')].slice(0, 10).map(s => s.outerHTML);
  return {
    icons, images: [...imgs], svgs,
    hasPassword: !!document.querySelector('input[type="password"]'),
    forms: [...document.forms].map(f => abs(f.getAttribute('action') || '')).filter(Boolean),
    text: (document.body ? document.body.innerText : '').slice(0, 200000),
  };
}
"""


def _guard(route: Route) -> None:
    url = route.request.url
    if url.startswith(("data:", "blob:", "about:")):
        route.continue_()
        return
    try:
        check_destination(url)
    except (BlockedDestination, FetchError):
        route.abort("blockedbyclient")
        return
    route.continue_()


def capture(url: str, *, collect_images: bool = False, full_page: bool = True,
            timeout_ms: int = 30_000) -> PageCapture:
    s = get_settings()
    check_destination(url)
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--disable-dev-shm-usage", "--no-first-run"])
        try:
            context = browser.new_context(
                viewport={"width": 1366, "height": 900}, user_agent=s.fetch_user_agent,
                accept_downloads=False, ignore_https_errors=True, java_script_enabled=True,
                service_workers="block",
            )
            context.route("**/*", _guard)
            page = context.new_page()
            status = None
            error = None
            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                status = resp.status if resp else None
                try:
                    page.wait_for_load_state("networkidle", timeout=8_000)
                except PlaywrightError:
                    pass
            except PlaywrightError as exc:
                error = str(exc).splitlines()[0]
            try:
                shot = page.screenshot(full_page=full_page, type="png", timeout=15_000)
            except PlaywrightError:
                shot = None
            try:
                info = page.evaluate(_COLLECT_JS)
                html = page.content()
                title = page.title()
            except PlaywrightError:
                info, html, title = {"icons": [], "images": [], "svgs": [], "hasPassword": False,
                                     "forms": [], "text": ""}, "", ""
            final_url = page.url
            svg_pngs: list[PageImage] = []
            if collect_images:
                for i, _svg in enumerate(info.get("svgs", [])[:10]):
                    try:
                        el = page.locator("svg").nth(i)
                        if el.is_visible():
                            svg_pngs.append(PageImage(url=f"{final_url}#svg{i}", data=el.screenshot(type="png"),
                                                      content_type="image/png"))
                    except PlaywrightError:
                        continue
        finally:
            browser.close()

    cap = PageCapture(
        url=url, final_url=final_url, status=status, title=title or "", text=info.get("text", ""),
        html=html, screenshot=shot, has_password_field=bool(info.get("hasPassword")),
        form_actions=info.get("forms", []), error=error,
    )
    # Favicon: declared icons first, then /favicon.ico
    for icon_url in list(info.get("icons", [])) + [urljoin(final_url, "/favicon.ico")]:
        if icon_url.startswith("data:image") and "base64," in icon_url:
            cap.favicon, cap.favicon_url = base64.b64decode(icon_url.split("base64,", 1)[1]), "data-uri"
            break
        r = try_fetch(icon_url, max_bytes=MAX_IMAGE_BYTES)
        if r and r.status == 200 and r.content:
            cap.favicon, cap.favicon_url = r.content, r.final_url
            break
    if collect_images:
        for img_url in list(dict.fromkeys(info.get("images", [])))[:MAX_IMAGES]:
            if img_url.startswith("data:image") and "base64," in img_url:
                try:
                    cap.images.append(PageImage(url="data-uri", data=base64.b64decode(img_url.split("base64,", 1)[1])))
                except ValueError:
                    pass
                continue
            r = try_fetch(img_url, max_bytes=MAX_IMAGE_BYTES)
            if r and r.status == 200 and r.content:
                cap.images.append(PageImage(url=r.final_url, data=r.content, content_type=r.content_type))
        cap.images.extend(svg_pngs)
    log.info("page_captured", url=url, final_url=cap.final_url, status=cap.status, images=len(cap.images))
    return cap
