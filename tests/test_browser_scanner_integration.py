"""Faz 2 / T4 — Scanner ↔ tarayıcı keşfi glue testi (tarayıcı YOK, ağ YOK).

`BrowserDiscovery` alt sınıfı sabit sonuç döner; recon akışında yüzey kaydı, test scope
kapısı, own-id önceliği ve RBAC politika kaynağı doğrulanır. Diğer fazlar kapalıdır.
"""
from __future__ import annotations

import httpx
import pytest

from pentestai.models import (
    Actor,
    AuthState,
    BudgetConfig,
    Endpoint,
    RbacPolicy,
    RbacRule,
    Scope,
)
from pentestai.net import Session, SessionStore
from pentestai.recon.browser import CapturedCall, TrafficToEndpoints, VisibilityMap
from pentestai.recon.browser.discovery import BrowserDiscovery, BrowserDiscoveryResult
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
CONVERTER = TrafficToEndpoints(["localhost"])


def _call(method: str, path: str) -> CapturedCall:
    return CapturedCall(method=method, url=BASE + path, status=200,
                        content_type="application/json")


def _result() -> BrowserDiscoveryResult:
    visibility = VisibilityMap()
    visibility.add("admin", [_call("GET", "/api/admin/users")], CONVERTER)
    visibility.add("user", [_call("GET", "/api/orders/9")], CONVERTER)
    return BrowserDiscoveryResult(
        endpoints=[
            Endpoint(method="GET", path_template="/api/admin/users"),
            Endpoint(method="GET", path_template="/api/orders/{id}"),
            Endpoint(method="GET", path_template="/api/existing",
                     body_template={"from": "browser"}),
            Endpoint(method="GET", path_template="/outside/secret"),
        ],
        visibility=visibility,
        own_ids={"admin": {"order": "hasat-id", "basket": "b-1"}},
        blocked_count=3,
        skipped_actions=["Delete account"],
        pages_visited=5,
    )


class _FakeDiscovery(BrowserDiscovery):
    """Gerçek tarayıcı açmadan sabit sonuç veren test çifti."""

    def __init__(self, result: BrowserDiscoveryResult) -> None:
        self.result = result
        self.runs: list[tuple[str, list[str]]] = []

    async def run(self, start_url: str, sessions: list[Session],
                  allowed_hosts: list[str]) -> BrowserDiscoveryResult:
        self.runs.append((start_url, list(allowed_hosts)))
        return self.result


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                 allowed_path_prefixes=["/api/"])


def _store() -> SessionStore:
    return SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"ok": True})))


async def _sessions(store: SessionStore) -> tuple[Session, Session]:
    admin = store.create(Actor(
        name="admin", role="admin", own_object_ids={"order": "config-id"},
        auth=AuthState(headers={"Authorization": "Bearer ADMIN"})))
    user = store.create(Actor(
        name="user_A", role="user",
        auth=AuthState(headers={"Authorization": "Bearer USER"})))
    return admin, user


@pytest.mark.asyncio
async def test_browser_endpoints_enter_surface_own_ids_and_auto_rbac(monkeypatch, capsys):
    discovery = _FakeDiscovery(_result())
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_total_requests=50, max_rps_per_host=1000),
                      browser_discovery=discovery)
    planned: list[list[Endpoint]] = []
    rbac_seen: list[RbacPolicy] = []

    async def fake_generate(endpoints: list[Endpoint]) -> list:
        planned.append([e.model_copy(deep=True) for e in endpoints])
        return []

    async def fake_rbac(sessions: list[Session], endpoints: list[Endpoint],
                        policy: RbacPolicy) -> list:
        rbac_seen.append(policy)
        return []

    monkeypatch.setattr(scanner.planner, "generate", fake_generate)
    monkeypatch.setattr(scanner, "run_rbac_scan", fake_rbac)
    store = _store()
    try:
        admin, user = await _sessions(store)
        findings = await scanner.run_recon_scan(
            [admin, user], [Endpoint(method="GET", path_template="/api/existing")],
            bootstrap=False, exposure_scan=False, info_leak_scan=False,
            rate_limit_scan=False, cve_scan=False, tls_scan=False, template_scan=False)
    finally:
        await store.aclose_all()

    assert findings == []
    assert discovery.runs == [(BASE, ["localhost"])]
    paths = {(e.method, e.path_template) for e in planned[0]}
    assert paths == {("GET", "/api/existing"), ("GET", "/api/admin/users"),
                     ("GET", "/api/orders/{id}")}
    assert ("/outside/secret" not in {e.path_template for e in planned[0]})
    existing = next(e for e in planned[0] if e.path_template == "/api/existing")
    assert existing.body_template == {"from": "browser"}

    sources = scanner.surface_sources
    assert "browser" in sources[("GET", "/api/admin/users")]
    assert "browser" in sources[("GET", "/api/existing")]
    assert ("GET", "/outside/secret") not in sources

    # Config id'si korunur, yalnız eksik kaynak eklenir.
    assert admin.actor.own_object_ids["order"] == "config-id"
    assert admin.actor.own_object_ids["basket"] == "b-1"
    assert "order" not in user.actor.own_object_ids

    assert len(rbac_seen) == 1
    assert rbac_seen[0].default == "allow"
    assert ("GET", "/api/admin/users") in {
        (r.method, r.path) for r in rbac_seen[0].rules}
    assert ("GET", "/api/admin/users") in [
        (c.method, c.path_template) for c in scanner.browser_rbac_candidates]
    out = capsys.readouterr().out
    assert "[tarayıcı] 5 sayfa, 3 uç (2 yeni), 3 yazma isteği" in out
    assert "1 yıkıcı eylem atlandı" in out

    lines = scanner.blocked_write_warnings()
    assert any("tarayıcı keşfi" in line and "Delete account" in line for line in lines)


@pytest.mark.asyncio
async def test_user_rbac_policy_is_not_overridden(monkeypatch, capsys):
    discovery = _FakeDiscovery(_result())
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_total_requests=50, max_rps_per_host=1000),
                      browser_discovery=discovery)
    user_policy = RbacPolicy(default="deny", rules=[
        RbacRule(method="GET", path="/api/custom", allow=["user"])])
    rbac_seen: list[RbacPolicy] = []

    async def fake_generate(endpoints: list[Endpoint]) -> list:
        return []

    async def fake_rbac(sessions: list[Session], endpoints: list[Endpoint],
                        policy: RbacPolicy) -> list:
        rbac_seen.append(policy)
        return []

    monkeypatch.setattr(scanner.planner, "generate", fake_generate)
    monkeypatch.setattr(scanner, "run_rbac_scan", fake_rbac)
    store = _store()
    try:
        sessions = await _sessions(store)
        await scanner.run_recon_scan(
            list(sessions), [], bootstrap=False, exposure_scan=False, info_leak_scan=False,
            rate_limit_scan=False, cve_scan=False, tls_scan=False, template_scan=False,
            rbac_policy=user_policy)
    finally:
        await store.aclose_all()

    assert rbac_seen == [user_policy]
    assert scanner.browser_rbac_candidates == []
    assert "kullanıcı --rbac politikası korundu" in capsys.readouterr().out
