"""Apify actor runs (D-43): paid scrapers for social platforms without a usable official search API.

One run = start the actor with an input, wait for it (server-side long polling), read its dataset. Every request goes
through the safe fetcher; the token is sent in a header, never in a URL. Costs are capped per run (`maxItems`,
`maxTotalChargeUsd`) and identical inputs are cached in Redis, so the content and impersonation modules share one run.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import structlog

from app.config import get_settings
from app.core.fetch import FetchError, fetch

log = structlog.get_logger(__name__)

BASE = "https://api.apify.com/v2/"
TERMINAL = {"SUCCEEDED", "FAILED", "ABORTED", "TIMED-OUT"}
WAIT = 60  # seconds the API holds a request open while the run is going


class ApifyError(Exception):
    """The run could not be started or read (bad token, no credit, API down)."""


@dataclass
class RunResult:
    items: list[dict] = field(default_factory=list)
    status: str = "SUCCEEDED"
    error: str | None = None
    cached: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None


def configured() -> bool:
    return bool(get_settings().apify_token)


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {get_settings().apify_token}", "Content-Type": "application/json",
            "Accept": "application/json"}


def _call(method: str, path: str, body: dict | None = None) -> dict | list:
    try:
        r = fetch(BASE + path, method=method, headers=_headers(), timeout=WAIT + 30,
                  content=json.dumps(body).encode() if body is not None else None)
    except FetchError as exc:
        raise ApifyError(f"Apify API unreachable: {exc}") from exc
    try:
        data = json.loads(r.content or b"null")
    except ValueError:
        data = None
    if r.status >= 400:
        err = (data or {}).get("error", {}) if isinstance(data, dict) else {}
        raise ApifyError(f"HTTP {r.status}: {err.get('message') or err.get('type') or r.text[:200]}")
    return data


# ------------------------------------------------------------------------------------------------ cache
def _redis():
    try:
        import redis

        client = redis.Redis.from_url(get_settings().redis_url, socket_timeout=2)
        client.ping()
        return client
    except Exception:  # noqa: BLE001 - no cache, the run just happens again
        return None


def _cache_key(actor: str, run_input: dict, max_items: int) -> str:
    raw = json.dumps([actor, run_input, max_items], sort_keys=True, ensure_ascii=False)
    return "apify:" + hashlib.sha256(raw.encode()).hexdigest()


def _cache_get(r, key: str) -> list[dict] | None:
    try:
        raw = r.get(key) if r is not None else None
        return json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        return None


def _cache_put(r, key: str, items: list[dict]) -> None:
    minutes = get_settings().apify_cache_minutes
    if r is None or minutes <= 0:
        return
    try:
        r.setex(key, minutes * 60, json.dumps(items, ensure_ascii=False, default=str))
    except Exception:  # noqa: BLE001
        pass


def _claim(r, key: str) -> bool:
    """True when this worker may run the search (no other worker is running the same one right now)."""
    if r is None or get_settings().apify_cache_minutes <= 0:
        return True
    try:
        return bool(r.set(key + ":lock", "1", nx=True, ex=get_settings().apify_run_timeout_seconds + 120))
    except Exception:  # noqa: BLE001
        return True


def _release(r, key: str) -> None:
    try:
        if r is not None:
            r.delete(key + ":lock")
    except Exception:  # noqa: BLE001
        pass


def _await_other(r, key: str) -> list[dict] | None:
    """Wait for the other worker's run of the same search; None (run it here) if it fails or takes too long."""
    deadline = time.monotonic() + get_settings().apify_run_timeout_seconds + 60
    while time.monotonic() < deadline:
        cached = _cache_get(r, key)
        if cached is not None:
            return cached
        try:
            if not r.exists(key + ":lock"):
                return None  # it finished without a usable result
        except Exception:  # noqa: BLE001
            return None
        time.sleep(5)
    return None


# ------------------------------------------------------------------------------------------------ runs
def _start(actor: str, run_input: dict, max_items: int) -> dict:
    s = get_settings()
    query = urlencode({"maxItems": max_items, "maxTotalChargeUsd": s.apify_max_charge_usd})
    data = _call("POST", f"acts/{actor.replace('/', '~')}/runs?{query}", run_input)
    return data.get("data", {}) if isinstance(data, dict) else {}


def _wait(run: dict, deadline: float) -> dict:
    while run.get("status") not in TERMINAL and time.monotonic() < deadline:
        data = _call("GET", f"actor-runs/{run['id']}?waitForFinish={WAIT}")
        run = data.get("data", run) if isinstance(data, dict) else run
    if run.get("status") not in TERMINAL:
        try:
            _call("POST", f"actor-runs/{run['id']}/abort")
        except ApifyError as exc:
            log.info("apify_abort_failed", run=run.get("id"), error=str(exc))
        run = {**run, "status": "TIMED-OUT"}
    return run


def _items(run: dict, max_items: int) -> list[dict]:
    if not run.get("defaultDatasetId"):
        return []
    data = _call("GET", f"datasets/{run['defaultDatasetId']}/items?" + urlencode(
        {"clean": "true", "format": "json", "limit": max_items}))
    # actors write error / "no results" placeholder items next to real ones
    return [i for i in data if isinstance(i, dict) and not i.get("error") and not i.get("noResults")] \
        if isinstance(data, list) else []


def run_many(actor: str, runs: list[tuple[dict, int]]) -> list[RunResult]:
    """Run `actor` once per (input, max items) — all started first, then awaited — and return one result per run, in
    order. A failed run is reported in its result; ApifyError is raised only when nothing could be started."""
    r = _redis()
    results: list[RunResult | None] = [None] * len(runs)
    started: list[tuple[int, dict, str, int]] = []
    errors: list[str] = []
    for n, (run_input, max_items) in enumerate(runs):
        key = _cache_key(actor, run_input, max_items)
        cached = _cache_get(r, key)
        if cached is None and not _claim(r, key):
            cached = _await_other(r, key)  # the other module is running this exact search: share its result
        if cached is not None:
            results[n] = RunResult(items=cached, cached=True)
            continue
        try:
            started.append((n, _start(actor, run_input, max_items), key, max_items))
        except ApifyError as exc:
            _release(r, key)
            errors.append(str(exc))
            results[n] = RunResult(status="NOT-STARTED", error=str(exc))
            if "HTTP 401" in str(exc) or "HTTP 402" in str(exc) or "HTTP 403" in str(exc):
                break  # bad token / no credit / actor not allowed: the other inputs fail the same way
    if errors and not started and all(x is None or not x.ok for x in results):
        raise ApifyError(errors[0])
    deadline = time.monotonic() + get_settings().apify_run_timeout_seconds
    for n, run, key, max_items in started:
        try:
            run = _wait(run, deadline)
            items = _items(run, max_items)
        except ApifyError as exc:
            _release(r, key)
            results[n] = RunResult(status=run.get("status", "UNKNOWN"), error=str(exc))
            continue
        status = run.get("status", "UNKNOWN")
        error = None if status == "SUCCEEDED" or items else f"run {status.lower()}"
        if status == "SUCCEEDED":
            _cache_put(r, key, items)
        _release(r, key)
        results[n] = RunResult(items=items, status=status, error=error)
    return [x or RunResult(status="NOT-STARTED", error="not started") for x in results]
