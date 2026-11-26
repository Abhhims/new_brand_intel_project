"""Simulated sources for the automated tests ONLY (decisions D-09, D-27, D-32).

The product has no demo mode: these classes live in the test suite and are injected into the real module runners
through their constructor parameters, so tests exercise the real scan engine against the local test website
(backend/tests/fixtures/site, served on FIXTURES_BASE_URL).

'{base}' in fixture values is replaced with the test website URL.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from app.modules.apk.module import ApkModule, Listing
from app.modules.base import BrandContext
from app.modules.documents.module import DocumentsModule
from app.modules.domains.infra import DnsInfo, _ct_rows
from app.modules.domains.module import DomainModule
from app.modules.logo.module import LogoModule
from app.modules.rogue_app.module import RogueAppModule
from app.modules.social.module import Profile, SocialModule

FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "fixtures"
BASE_URL = os.environ.get("FIXTURES_BASE_URL", "http://localhost:8088").rstrip("/")


def _substitute(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("{base}", BASE_URL)
    if isinstance(value, list):
        return [_substitute(v) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(v) for k, v in value.items()}
    return value


def load(name: str) -> Any:
    """Load tests/fixtures/sources/<name>.json with {base} substituted."""
    data = json.loads((FIXTURES_ROOT / "sources" / f"{name}.json").read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data.pop("_comment", None)
    return _substitute(data)


class FixtureInfra:
    """Domain facts from sources/dns.json + ct.json; websites served by the test website."""

    def __init__(self) -> None:
        self.data: dict = load("dns")

    def resolve_many(self, domains: list[str]) -> dict[str, DnsInfo]:
        return {d: self.resolve(d) for d in domains}

    def resolve(self, domain: str) -> DnsInfo:
        row = self.data.get(domain)
        if not row:
            return DnsInfo(status="nxdomain")
        return DnsInfo(a=row.get("a", []), mx=row.get("mx", []), ns=row.get("ns", []), status="resolved")

    def whois(self, domain: str) -> dict:
        return (self.data.get(domain) or {}).get("whois") or {}

    def ct_search(self, term: str):
        return _ct_rows(load("ct")["results"])

    def web_urls(self, domain: str, info: DnsInfo | None = None) -> list[str]:
        web = (self.data.get(domain) or {}).get("web")
        return [web] if web else []

    def tls(self, domain: str) -> dict | None:
        return (self.data.get(domain) or {}).get("tls")

    def email_records(self, domain: str) -> tuple[list[str], list[str]]:
        return [], []

    @property
    def extra_domains(self) -> list[str]:
        """Test domains, so tests see them even if a fuzzer variant list changes."""
        return list(self.data.keys())


def _reported(report) -> None:
    if report is not None:
        report.ok("Simulated test source")


class FixtureApkSource:
    def listings(self, ctx: BrandContext, report=None) -> list[Listing]:
        _reported(report)
        return [Listing(**{k: r.get(k) for k in Listing.__dataclass_fields__}) for r in load("apk_search")["results"]]


class FixturePlaySource:
    def search(self, ctx: BrandContext, report=None) -> list[dict]:
        _reported(report)
        return load("play_search")["results"]


class FixtureSocialSource:
    def profiles(self, ctx: BrandContext, report=None) -> list[Profile]:
        _reported(report)
        return [Profile(**{k: r.get(k) for k in ("platform", "username", "display_name", "bio", "followers",
                                                 "avatar_url", "profile_url")}, discovery="simulated source")
                for r in load("social")["results"]]


class FixtureDocSource:
    def results(self, ctx: BrandContext, report=None) -> list[dict]:
        _reported(report)
        return load("documents_search")["results"]


def fixture_runner(name: str):
    """Real module runners wired to the simulated sources (used in place of registry.get_runner in tests)."""
    from app.modules.registry import get_runner as live_runner

    factories = {
        "domains": lambda: DomainModule(infra=FixtureInfra()),
        "apk": lambda: ApkModule(source=FixtureApkSource()),
        "rogue_app": lambda: RogueAppModule(source=FixturePlaySource()),
        "social": lambda: SocialModule(source=FixtureSocialSource()),
        "documents": lambda: DocumentsModule(source=FixtureDocSource()),
        "logo": lambda: LogoModule(extra_targets=load("logo_targets")["results"]),
    }
    return factories[name]() if name in factories else live_runner(name)
