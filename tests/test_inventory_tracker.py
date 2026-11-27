"""Faz 5 / T4 — InventoryTracker uçtan-uca testi (gerçek store, sahte ağ).

İki koşum: ilk koşumda tüm uçlar planlanır ve kaydedilir; ikinci koşumda hedefe yeni
uç eklenince yalnız o uç delta planına girer. Tüm istekler httpx.MockTransport üzerinden
Replayer → PolicyEngine kapısından geçer; gerçek hedefe istek ATILMAZ.
"""
from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from pentestai.inventory.diff import InventoryDiff
from pentestai.inventory.models import ChangeCategory
from pentestai.inventory.store import InventoryStore
from pentestai.inventory.tracker import InventoryTracker
from pentestai.models import Actor, AuthState, Endpoint, Finding, Scope
from pentestai.net import BudgetTracker, Replayer, Session, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)


def _handler(request: httpx.Request) -> httpx.Response:
    # Ham yanıt DEĞERİ hiçbir envanter kaydına girmemeli; yalnızca alan adı/tipi saklanır.
    return httpx.Response(200, json={"id": 7, "email": "pii-secret@example.com"})


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                 allowed_path_prefixes=["/"], allowed_methods=["GET"])


def _sessions(store: SessionStore) -> tuple[Session, Session]:
    actor = store.create(Actor(name="user_A", role="user",
                               auth=AuthState(headers={"Authorization": "Bearer A"})))
    anon = store.create(Actor(name="anonymous", role="anonymous"))
    return actor, anon


def _findings() -> list[Finding]:
    return [
        Finding(id="F-1", type="idor", endpoint="/api/orders", method="GET", verdict="LIKELY"),
        Finding(id="F-2", type="idor", endpoint="/api/orders", method="GET", verdict="CONFIRMED"),
        Finding(id="F-3", type="excessive_data_exposure", endpoint="/api/settings",
                method="GET", verdict="REJECTED"),
    ]


@pytest.mark.asyncio
async def test_two_runs_new_endpoint_delta_and_finish(tmp_path):
    db_path = tmp_path / "inventory.sqlite"
    store = InventoryStore(db_path)
    net_store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_handler))
    replayer = Replayer(PolicyEngine(_scope()), budget=BudgetTracker(100))
    actor, anon = _sessions(net_store)
    endpoints = [
        Endpoint(method="GET", path_template="/api/orders"),
        Endpoint(method="GET", path_template="/api/settings"),
    ]
    tested = {("GET", "/api/orders"): {"idor"}, ("GET", "/api/settings"): {"bopla"}}
    sources = {("GET", "/api/orders"): ["openapi", "har"]}

    try:
        first = InventoryTracker(store, BASE, mode="delta", clock=lambda: NOW,
                                 profile_max_requests=50, diff=InventoryDiff())
        first_result = await first.observe(
            replayer, endpoints, [actor], anon, sources=sources)

        assert first_result.first_run is True
        assert first_result.changes == []
        assert first.plan(endpoints) == endpoints   # ilk koşumda delta bile tam tarama
        first.finish(tested, _findings())

        records = store.load(BASE)
        assert set(records) == {"GET /api/orders", "GET /api/settings"}
        assert records["GET /api/orders"].last_tested == NOW
        assert records["GET /api/orders"].last_results == {"idor": "CONFIRMED"}
        assert records["GET /api/settings"].last_results == {"excessive_data_exposure": "REJECTED"}
        assert records["GET /api/orders"].sources == ["har", "openapi"]
        assert first.summary_lines()[0] == (
            "Bu koşum: 2 uç (0 yeni, 0 değişti, 0 kayboldu) · 2 test edildi")
        assert len(first.summary_lines()) == 1

        run = store.last_run(BASE)
        assert run is not None and run["mode"] == "delta"
        assert run["summary"] == {"endpoints": 2, "tested": 2}

        # İkinci koşum: hedefe YENİ uç eklendi, saat sabit → STALE uyarısı yok.
        expanded = endpoints + [Endpoint(method="GET", path_template="/api/admin")]
        second = InventoryTracker(store, BASE, mode="delta", clock=lambda: NOW)
        result = await second.observe(replayer, expanded, [actor], anon, sources={})

        assert [change.category for change in result.changes] == [ChangeCategory.NEW]
        assert result.changes[0].key == "GET /api/admin"
        assert "yeni uç nokta" in result.changes[0].detail
        assert second.plan(expanded) == [expanded[2]]
        lines = second.summary_lines()
        assert lines[0].startswith("Bu koşum: 3 uç (1 yeni, 0 değişti, 0 kayboldu)")
        assert lines[1].startswith("🆕 GET /api/admin:")

        second.finish({("GET", "/api/admin"): set()}, [])
        updated = store.load(BASE)
        assert updated["GET /api/admin"].last_tested == NOW
        assert updated["GET /api/orders"].last_tested == NOW   # eski kayıt korundu
        assert b"pii-secret@example.com" not in db_path.read_bytes()
    finally:
        await net_store.aclose_all()
        store.close()


@pytest.mark.asyncio
async def test_observe_without_result_keeps_full_plan_and_turkish_summary(tmp_path):
    store = InventoryStore(tmp_path / "other.sqlite")
    tracker = InventoryTracker(store, BASE, clock=lambda: NOW)
    endpoints = [Endpoint(method="GET", path_template="/api/orders")]
    try:
        assert tracker.plan(endpoints) == endpoints
        assert tracker.summary_lines() == ["Bu koşum: envanter gözlemi yok · 0 test edildi"]
        tracker.finish({("GET", "/api/orders"): {"idor"}}, _findings())
        assert store.last_run(BASE) is None   # gözlem yoksa yarım koşum kaydı yazılmaz
    finally:
        store.close()


@pytest.mark.asyncio
async def test_profile_truncation_is_exposed_and_unprofiled_enter_delta_plan(tmp_path):
    store = InventoryStore(tmp_path / "truncated.sqlite")
    net_store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_handler))
    replayer = Replayer(PolicyEngine(_scope()), budget=BudgetTracker(100))
    actor, anon = _sessions(net_store)
    endpoints = [
        Endpoint(method="GET", path_template="/api/orders"),
        Endpoint(method="GET", path_template="/api/settings"),
    ]
    try:
        first = InventoryTracker(store, BASE, mode="delta", clock=lambda: NOW,
                                 profile_max_requests=50)
        await first.observe(replayer, endpoints, [actor], anon, sources={})
        first.finish({("GET", "/api/orders"): set(), ("GET", "/api/settings"): set()}, [])

        # 3 istek: /api/orders (actor + anon) tam, /api/settings yarıda kesilir.
        second = InventoryTracker(store, BASE, mode="delta", clock=lambda: NOW,
                                  profile_max_requests=3)
        result = await second.observe(replayer, endpoints, [actor], anon, sources={})

        assert result.changes == []                       # değişiklik yok gibi görünür
        assert second.profile_truncated is True
        assert second.unprofiled_keys == {"GET /api/settings"}
        # Değişiklik bilinmediği için profillenemeyen uç delta planına girer.
        assert second.plan(endpoints) == [endpoints[1]]
    finally:
        await net_store.aclose_all()
        store.close()


@pytest.mark.asyncio
async def test_partial_finish_rolls_back_missing_streak_and_marks_line(tmp_path):
    store = InventoryStore(tmp_path / "partial.sqlite")
    net_store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_handler))
    replayer = Replayer(PolicyEngine(_scope()), budget=BudgetTracker(100))
    actor, anon = _sessions(net_store)
    endpoints = [
        Endpoint(method="GET", path_template="/api/orders"),
        Endpoint(method="GET", path_template="/api/legacy"),
    ]
    try:
        first = InventoryTracker(store, BASE, mode="delta", clock=lambda: NOW)
        await first.observe(replayer, endpoints, [actor], anon, sources={})
        first.finish({("GET", "/api/orders"): set(), ("GET", "/api/legacy"): set()}, [])

        # Kısmi koşum: /api/legacy görülmedi ama yokluk kanıt sayılmamalı.
        partial = InventoryTracker(store, BASE, mode="delta", clock=lambda: NOW)
        result = await partial.observe(replayer, endpoints[:1], [actor], anon, sources={})
        assert [c.category for c in result.changes] == [ChangeCategory.MISSING]

        partial.finish({}, [], partial=True)
        record = store.load(BASE)["GET /api/legacy"]
        assert record.missing_streak == 0 and record.removed is False
        assert "(koşum kısmi — sayılmadı)" in partial.result.changes[0].detail

        # Sonraki tam koşumda sayaç normal artar.
        complete = InventoryTracker(store, BASE, mode="delta", clock=lambda: NOW)
        complete_result = await complete.observe(replayer, endpoints[:1], [actor], anon, sources={})
        complete.finish({}, [])
        assert [c.category for c in complete_result.changes] == [ChangeCategory.MISSING]
        assert store.load(BASE)["GET /api/legacy"].missing_streak == 1
    finally:
        await net_store.aclose_all()
        store.close()
