"""Faz 5 / T4 — Scanner ↔ InventoryTracker glue testi (ağsız).

Amaç: recon akışında profil/plan'ın ``planner.generate``'den ÖNCE çalıştığını ve
planın daralttığı uç listesinin sonraki fazlara geçtiğini kanıtlamak. Diğer fazlar
kapatılır; hiçbir gerçek hedefe istek atılmaz.
"""
from __future__ import annotations

import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


class _FakeInventory:
    """Gerçek profil trafiğine girmeden cephe çağrılarını kaydeden test çifti."""

    def __init__(self, keep_path: str) -> None:
        self.keep_path = keep_path
        self.observe_calls: list = []

    async def observe(self, replayer, endpoints, sessions, anon, sources) -> None:
        self.observe_calls.append((list(endpoints), dict(sources), anon, replayer))

    def plan(self, endpoints: list[Endpoint]) -> list[Endpoint]:
        return [endpoint for endpoint in endpoints if endpoint.path_template == self.keep_path]


@pytest.mark.asyncio
async def test_scanner_observes_before_planning_and_uses_reduced_endpoint_list(monkeypatch):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    inventory = _FakeInventory("/api/b")
    scanner = Scanner(
        BASE, scope, BudgetConfig(max_total_requests=50, max_rps_per_host=1000),
        inventory=inventory,  # type: ignore[arg-type]
    )
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"ok": True})))
    session = store.create(Actor(name="user_A", role="user",
                                 auth=AuthState(headers={"Authorization": "Bearer A"})))
    endpoints = [
        Endpoint(method="GET", path_template="/api/a"),
        Endpoint(method="GET", path_template="/api/b"),
    ]
    planned: list[list[Endpoint]] = []

    async def fake_generate(received: list[Endpoint]) -> list:
        planned.append(list(received))
        return []

    monkeypatch.setattr(scanner.planner, "generate", fake_generate)
    try:
        findings = await scanner.run_recon_scan(
            [session], endpoints, bootstrap=False, exposure_scan=False,
            info_leak_scan=False, rate_limit_scan=False, cve_scan=False,
            tls_scan=False, template_scan=False)
    finally:
        await store.aclose_all()

    assert findings == []
    assert len(inventory.observe_calls) == 1
    observed_endpoints, sources, anon, replayer = inventory.observe_calls[0]
    assert observed_endpoints == endpoints
    assert sources == {}
    assert anon is scanner.anon     # mevcut yardımcı anonim oturumu kurdu
    assert replayer is scanner.replayer   # tek choke point (PolicyEngine kapısı)
    assert planned == [[endpoints[1]]]
