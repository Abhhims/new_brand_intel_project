"""CertStream watcher (D-52): a long-running process that reads the live Certificate Transparency stream and keeps
every newly certified hostname that names an active brand, so phishing sites are seen within minutes of getting
their certificate - long before search engines or feeds list them.

Matches go to Redis (sorted set per brand, score = time seen, kept CERTSTREAM_RETENTION_DAYS); the domain scan
reads them as the "CertStream" discovery source. The stream comes from a self-hosted certstream-server-go
container (the public calidog server is unreliable).

    docker compose --profile app --profile certstream up -d
"""

from __future__ import annotations

import json
import re
import time

import certstream
import redis
import structlog
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.db.models import Brand
from app.db.session import session_scope
from app.modules.base import BrandContext
from app.modules.domains.discovery import CERTSTREAM_HEARTBEAT, HostMatcher, certstream_key

log = structlog.get_logger(__name__)

RELOAD_SECONDS = 600
HEARTBEAT_SECONDS = 60


class Watcher:
    def __init__(self) -> None:
        self.s = get_settings()
        self.rds = redis.Redis.from_url(self.s.redis_url)
        self.matchers: list[tuple[str, HostMatcher]] = []
        self.needles: list[str] = []
        self.loaded = 0.0
        self.beat = 0.0
        self.seen = self.matched = 0

    def reload(self) -> None:
        with session_scope() as db:
            brands = db.scalars(select(Brand).where(Brand.is_active.is_(True))
                                .options(selectinload(Brand.assets), selectinload(Brand.allowlist))).all()
            self.matchers = [(str(b.id), HostMatcher(BrandContext.from_brand(b))) for b in brands]
        self.needles = sorted({n for _, m in self.matchers for n in m.strong + m.weak})
        self.loaded = time.monotonic()
        log.info("certwatch_brands_loaded", brands=len(self.matchers), needles=self.needles)

    def domains(self, frame: dict) -> list[str]:
        if frame.get("message_type") == "dns_entries":  # /domains-only endpoint
            return frame.get("data") or []
        if frame.get("message_type") == "certificate_update":  # full stream
            return ((frame.get("data") or {}).get("leaf_cert") or {}).get("all_domains") or []
        return []

    def on_message(self, frame: dict, _context) -> None:
        now = time.monotonic()
        if now - self.loaded > RELOAD_SECONDS:
            try:
                self.reload()
            except Exception:  # noqa: BLE001 - keep the last matchers
                log.exception("certwatch_reload_failed")
                self.loaded = now
        for raw in self.domains(frame):
            self.seen += 1
            flat = re.sub(r"[^a-z0-9]", "", raw.lower())
            if not any(n in flat for n in self.needles):  # cheap pre-filter: almost every name stops here
                continue
            for brand_id, matcher in self.matchers:
                host = matcher.candidate(raw, strict=True)
                if host:
                    self.matched += 1
                    key = certstream_key(brand_id)
                    self.rds.zadd(key, {host: time.time()})
                    log.info("certwatch_match", brand=brand_id, host=host, raw=raw)
        if now - self.beat > HEARTBEAT_SECONDS:
            self.beat = now
            cutoff = time.time() - self.s.certstream_retention_days * 86400
            for brand_id, _ in self.matchers:
                self.rds.zremrangebyscore(certstream_key(brand_id), "-inf", cutoff)
            self.rds.setex(CERTSTREAM_HEARTBEAT, 5 * HEARTBEAT_SECONDS,
                           json.dumps({"seen": self.seen, "matched": self.matched, "at": time.time()}))


def main() -> None:
    w = Watcher()
    while True:
        try:
            w.reload()
            break
        except Exception:  # noqa: BLE001 - database not up yet
            log.exception("certwatch_initial_load_failed")
            time.sleep(15)
    log.info("certwatch_start", url=w.s.certstream_url)
    while True:  # listen_for_events reconnects by itself; this guards against it returning or raising
        try:
            certstream.listen_for_events(w.on_message, url=w.s.certstream_url, setup_logger=False)
        except Exception:  # noqa: BLE001
            log.exception("certwatch_stream_error")
        time.sleep(10)


if __name__ == "__main__":
    main()
