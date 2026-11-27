"""T5c — tarayıcı keşfi tarama bütçesini yememeli (canlı Juice/crAPI bulguları).

Ağ YOK; tarayıcı açılmaz: sahte crawler_factory `crawl`'u taklit eder.
"""
from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, RbacPolicy, Scope
from pentestai.net import SessionStore
from pentestai.policy import PolicyEngine
from pentestai.recon.browser import CapturedCall, TrafficToEndpoints, VisibilityMap
from pentestai.recon.browser.crawler import CrawlResult
from pentestai.recon.browser.discovery import BrowserDiscovery, BrowserDiscoveryResult
from pentestai.scanner import BROWSER_TIME_SHARE, Scanner

BASE = "http://localhost:3000"
CONVERTER = TrafficToEndpoints(["localhost"])


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])


class _SleepyCrawler:
    """`delay` sn bekleyip rolüne özgü bir API çağrısı döndüren sahte crawler."""

    def __init__(self, delay: float, fail_for: str = "", hang_for: str = "") -> None:
        self.delay, self.fail_for, self.hang_for = delay, fail_for, hang_for

    async def crawl(self, start_url: str, *, role: str = "", **_: object) -> CrawlResult:
        if role == self.hang_for:
            await asyncio.Event().wait()
        await asyncio.sleep(self.delay)
        if role == self.fail_for:
            raise RuntimeError("sahte gezinti hatası")
        result = CrawlResult()
        result.calls.append(CapturedCall(method="GET", url=f"{BASE}/api/{role}/info",
                                         status=200, content_type="application/json", role=role))
        result.pages_visited = 1
        return result


def _sessions(store: SessionStore):
    return [store.create(Actor(name=n, role=r, auth=AuthState(headers={"Authorization": f"Bearer {n}"})))
            for n, r in (("alice", "user"), ("root", "admin"))]


def _discovery(crawler: _SleepyCrawler) -> BrowserDiscovery:
    return BrowserDiscovery(PolicyEngine(_scope()), crawler_factory=lambda: crawler)


@pytest.mark.asyncio
async def test_actor_crawls_run_concurrently():
    store = SessionStore(base_url=BASE)
    started = time.monotonic()
    res = await _discovery(_SleepyCrawler(1.0)).run(BASE, _sessions(store), ["localhost"])
    elapsed = time.monotonic() - started
    await store.aclose_all()
    assert elapsed < 2.5, f"gezintiler sıralı koştu ({elapsed:.1f} sn; 3 gezinti × 1 sn)"
    assert {e.path_template for e in res.endpoints} == {
        "/api/user/info", "/api/admin/info", "/api/anonymous/info"}


@pytest.mark.asyncio
async def test_one_failing_crawl_does_not_stop_others(capsys):
    store = SessionStore(base_url=BASE)
    res = await _discovery(_SleepyCrawler(0.1, fail_for="admin")).run(
        BASE, _sessions(store), ["localhost"])
    await store.aclose_all()
    assert {e.path_template for e in res.endpoints} == {"/api/user/info", "/api/anonymous/info"}
    assert "root keşfi tamamlanamadı" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_time_limit_returns_finished_crawls_and_warns(capsys):
    store = SessionStore(base_url=BASE)
    discovery = _discovery(_SleepyCrawler(0.1, hang_for="admin"))
    discovery.time_limit_seconds = 0.01   # +15 sn tolerans yerine testte kısalt
    import pentestai.recon.browser.discovery as mod
    original = mod.asyncio.wait

    async def short_wait(tasks, timeout=None):
        return await original(tasks, timeout=1.0)

    mod.asyncio.wait = short_wait
    try:
        res = await discovery.run(BASE, _sessions(store), ["localhost"])
    finally:
        mod.asyncio.wait = original
        await store.aclose_all()
    assert {e.path_template for e in res.endpoints} == {"/api/user/info", "/api/anonymous/info"}
    assert "süre payı dolduğu için kesildi" in capsys.readouterr().out


def _visibility(roles: dict[str, list[str]]) -> VisibilityMap:
    vis = VisibilityMap()
    for role, paths in roles.items():
        vis.add(role, [CapturedCall(method="GET", url=f"{BASE}{p}", status=200,
                                    content_type="application/json") for p in paths], CONVERTER)
    return vis


def test_anonymous_and_single_role_produce_no_rbac_candidates():
    vis = _visibility({"anonymous": ["/api/public"], "user": ["/api/public", "/api/me"]})
    assert vis.rbac_candidates() == []
    assert vis.to_rbac_policy().rules == []


def test_candidates_come_only_from_non_anonymous_role_differences():
    vis = _visibility({"anonymous": ["/api/public"],
                       "user": ["/api/public", "/api/me"],
                       "admin": ["/api/public", "/api/me", "/api/admin/users"]})
    cands = {(c.path_template, tuple(c.visible_to), tuple(c.hidden_from))
             for c in vis.rbac_candidates()}
    assert cands == {("/api/admin/users", ("admin",), ("user",))}


class _RecordingDiscovery(BrowserDiscovery):
    def __init__(self) -> None:
        self.time_limit_seconds = None
        self.budget = None
        self.seen_limit: float | None = None

    async def run(self, start_url, sessions, allowed_hosts) -> BrowserDiscoveryResult:
        self.seen_limit = self.time_limit_seconds
        return BrowserDiscoveryResult()


@pytest.mark.asyncio
async def test_scanner_gives_browser_a_share_of_remaining_time(monkeypatch):
    discovery = _RecordingDiscovery()
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_total_requests=50, max_wall_clock_sec=400),
                      browser_discovery=discovery)

    async def fake_generate(endpoints: list[Endpoint]) -> list:
        return []

    monkeypatch.setattr(scanner.planner, "generate", fake_generate)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={})))
    try:
        await scanner.run_recon_scan(
            _sessions(store), [], bootstrap=False, exposure_scan=False, info_leak_scan=False,
            rate_limit_scan=False, cve_scan=False, tls_scan=False, template_scan=False,
            rbac_policy=RbacPolicy(default="allow"))
    finally:
        await store.aclose_all()
    assert discovery.seen_limit is not None
    assert 0 < discovery.seen_limit <= 400 * BROWSER_TIME_SHARE
    assert discovery.seen_limit > 400 * BROWSER_TIME_SHARE - 10
