"""AuthProfiler testleri — yalnızca MockTransport; gerçek hedefe istek atılmaz.

Kapsam: rol/anon profili, id'li uçlarda aktör izolasyonu, yazma methodlarına istek
atılmaması, scope reddi, yanıt şekli (değer sızdırmadan), istek tavanı ve aktör
kimlik durumunun değişmemesi.
"""
from __future__ import annotations

from typing import Optional

import httpx
import pytest

from pentestai.inventory.profiler import AuthProfiler
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import BudgetExceeded, BudgetTracker, Replayer, Session, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def _scope(prefixes: Optional[list[str]] = None) -> Scope:
    return Scope(
        allowed_hosts=["localhost"],
        allowed_ports=[3000],
        allowed_path_prefixes=prefixes or ["/"],
        allowed_methods=["GET"],
    )


def _replayer(
    scope: Optional[Scope] = None,
    budget: Optional[BudgetTracker] = None,
) -> Replayer:
    return Replayer(PolicyEngine(scope or _scope()), budget=budget)


def _store(handler) -> SessionStore:
    return SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))


def _session(
    store: SessionStore,
    name: str,
    *,
    role: str = "user",
    headers: Optional[dict[str, str]] = None,
    own_ids: Optional[dict[str, str]] = None,
) -> Session:
    return store.create(Actor(
        name=name,
        role=role,
        auth=AuthState(headers=headers or {}),
        own_object_ids=own_ids or {},
    ))


def _json_ok(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


@pytest.mark.asyncio
async def test_profile_roles_and_anon_status_without_touching_auth_state():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.headers.get("authorization") in ("Bearer A", "Bearer B"):
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(401, json={"error": "unauthorized"})

    store = _store(handler)
    actor_a = _session(store, "user_A", headers={"Authorization": "Bearer A"})
    actor_b = _session(store, "user_B", headers={"Authorization": "Bearer B"})
    anon = _session(store, "guest")
    before = [s.actor.auth.model_dump() for s in (actor_a, actor_b, anon)]

    profiler = AuthProfiler(_replayer(), BASE, max_requests=50)
    try:
        observations = await profiler.profile(
            [Endpoint(method="GET", path_template="/api/orders")],
            [actor_a, actor_b],
            anon,
            sources={("get", "/api/orders"): ["openapi", "har"]},
        )
    finally:
        await store.aclose_all()

    assert len(observations) == 1
    assert observations[0].auth_profile == {"user_A": 200, "user_B": 200, "anonymous": 401}
    assert observations[0].sources == ["openapi", "har"]
    assert profiler.requests_used == 3
    assert profiler.truncated is False
    assert [request.method for request in seen] == ["GET", "GET", "GET"]
    # İzolasyon: profiler aktörlerin auth durumuna HİÇBİR şey yazmaz.
    assert [s.actor.auth.model_dump() for s in (actor_a, actor_b, anon)] == before


@pytest.mark.asyncio
async def test_distinct_roles_use_role_names_as_profile_keys():
    store = _store(_json_ok)
    user = _session(store, "user_A", role="user")
    admin = _session(store, "admin_A", role="admin")
    profiler = AuthProfiler(_replayer(), BASE)
    try:
        observations = await profiler.profile(
            [Endpoint(method="GET", path_template="/api/orders")], [user, admin], None)
    finally:
        await store.aclose_all()

    assert observations[0].auth_profile == {"user": 200, "admin": 200}


@pytest.mark.asyncio
async def test_id_endpoint_uses_each_actors_own_id_and_anon_uses_first_actor():
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json={"id": 1})

    store = _store(handler)
    actor_a = _session(store, "user_A", own_ids={"orders": "101"})
    actor_b = _session(store, "user_B", own_ids={"orders": "202"})
    anon = _session(store, "guest")

    profiler = AuthProfiler(_replayer(), BASE)
    try:
        observations = await profiler.profile(
            [Endpoint(method="GET", path_template="/api/orders/{id}")],
            [actor_a, actor_b],
            anon,
        )
    finally:
        await store.aclose_all()

    assert paths == ["/api/orders/101", "/api/orders/202", "/api/orders/101"]
    assert observations[0].params == ["id"]
    assert observations[0].auth_profile == {
        "user_A": 200, "user_B": 200, "anonymous": 200}


@pytest.mark.asyncio
async def test_id_endpoint_without_first_actor_id_is_skipped():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    store = _store(handler)
    actor = _session(store, "user_A")
    profiler = AuthProfiler(_replayer(), BASE)
    try:
        observations = await profiler.profile(
            [Endpoint(method="GET", path_template="/api/orders/{id}")], [actor], None)
    finally:
        await store.aclose_all()

    assert seen == []
    assert observations[0].auth_profile == {}
    assert observations[0].response_shape is None


@pytest.mark.asyncio
async def test_write_methods_are_never_requested_but_still_observed():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    store = _store(handler)
    session = _session(store, "user_A")
    endpoints = [
        Endpoint(method="POST", path_template="/api/orders"),
        Endpoint(method="PUT", path_template="/api/orders/{id}"),
        Endpoint(method="PATCH", path_template="/api/orders/{id}"),
        Endpoint(method="DELETE", path_template="/api/orders/{id}"),
    ]
    profiler = AuthProfiler(_replayer(), BASE)
    try:
        observations = await profiler.profile(endpoints, [session], None)
    finally:
        await store.aclose_all()

    assert seen == []
    assert len(observations) == 4
    assert all(obs.auth_profile == {} for obs in observations)
    assert all(obs.response_shape is None for obs in observations)
    assert observations[0].params == []
    assert observations[1].params == ["id"]


@pytest.mark.asyncio
async def test_out_of_scope_endpoint_does_not_crash_and_stays_unprofiled():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    store = _store(handler)
    session = _session(store, "user_A")
    anon = _session(store, "guest")
    profiler = AuthProfiler(_replayer(_scope(prefixes=["/api"])), BASE)
    try:
        observations = await profiler.profile(
            [Endpoint(method="GET", path_template="/admin/secret")], [session], anon)
    finally:
        await store.aclose_all()

    assert seen == []
    assert observations[0].auth_profile == {}
    assert observations[0].response_shape is None


@pytest.mark.asyncio
async def test_json_shape_has_no_values_and_non_json_has_no_shape():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/me":
            return httpx.Response(
                200,
                json={"id": 7, "email": "victim@example.com", "roles": ["admin"]},
            )
        return httpx.Response(200, text="OK")

    store = _store(handler)
    session = _session(store, "user_A")
    profiler = AuthProfiler(_replayer(), BASE)
    try:
        observations = await profiler.profile(
            [Endpoint(method="GET", path_template="/api/me"),
             Endpoint(method="GET", path_template="/health")],
            [session],
            None,
        )
    finally:
        await store.aclose_all()

    me, health = observations
    assert me.response_shape is not None
    assert "id:int" in me.response_fields
    assert "email:str" in me.response_fields
    assert "roles[]:str" in me.response_fields
    assert health.response_shape is None
    assert health.response_fields == []
    # Değerler (e-posta, rol adı) gözleme ASLA girmez; yalnızca alan adı + tip vardır.
    dumped = f"{me.model_dump()} {health.model_dump()}"
    assert "victim@example.com" not in dumped


@pytest.mark.asyncio
async def test_max_requests_truncates_and_caps_sent_requests():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    store = _store(handler)
    actor_a = _session(store, "user_A")
    actor_b = _session(store, "user_B")
    anon = _session(store, "guest")
    profiler = AuthProfiler(_replayer(), BASE, max_requests=3)
    try:
        observations = await profiler.profile(
            [Endpoint(method="GET", path_template="/api/a"),
             Endpoint(method="GET", path_template="/api/b")],
            [actor_a, actor_b],
            anon,
        )
    finally:
        await store.aclose_all()

    assert profiler.truncated is True
    assert profiler.requests_used == 3
    assert len(seen) == 3
    assert observations[0].auth_profile == {
        "user_A": 200, "user_B": 200, "anonymous": 200}
    assert observations[1].auth_profile == {}
    assert observations[1].response_shape is None
    # Bütçe yüzünden hiç profillenemeyen uç sessizce boş bırakılmaz.
    assert profiler.unprofiled_keys == {"GET /api/b"}


@pytest.mark.asyncio
async def test_truncation_midway_marks_partial_endpoint_as_unprofiled():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    store = _store(handler)
    actor_a = _session(store, "user_A")
    actor_b = _session(store, "user_B")
    anon = _session(store, "guest")
    profiler = AuthProfiler(_replayer(), BASE, max_requests=2)
    try:
        observations = await profiler.profile(
            [Endpoint(method="GET", path_template="/api/a"),
             Endpoint(method="GET", path_template="/api/b")],
            [actor_a, actor_b],
            anon,
        )
    finally:
        await store.aclose_all()

    assert profiler.truncated is True
    # İlk uç yarıda kesildi (anon denenemedi), ikinci uca hiç gidilmedi.
    assert observations[0].auth_profile == {"user_A": 200, "user_B": 200}
    assert observations[1].auth_profile == {}
    assert profiler.unprofiled_keys == {"GET /api/a", "GET /api/b"}


@pytest.mark.asyncio
async def test_transport_errors_are_skipped_per_role():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("bağlantı yok", request=request)

    store = _store(handler)
    actor_a = _session(store, "user_A")
    actor_b = _session(store, "user_B")
    profiler = AuthProfiler(_replayer(), BASE)
    try:
        observations = await profiler.profile(
            [Endpoint(method="GET", path_template="/api/orders")], [actor_a, actor_b], None)
    finally:
        await store.aclose_all()

    assert observations[0].auth_profile == {}
    assert profiler.requests_used == 2


def test_anon_role_matches_scanner_anonymous_session_role():
    """Anonim profil anahtarı Scanner'ın kurduğu anonim oturum rolüyle aynı olmalı."""
    from pentestai.inventory.profiler import ANON_ROLE

    assert ANON_ROLE == "anonymous"


@pytest.mark.asyncio
async def test_budget_exceeded_is_not_swallowed():
    store = _store(_json_ok)
    actor_a = _session(store, "user_A")
    actor_b = _session(store, "user_B")
    budget = BudgetTracker(max_total_requests=1, max_wall_clock_sec=60)
    profiler = AuthProfiler(_replayer(budget=budget), BASE)
    try:
        with pytest.raises(BudgetExceeded):
            await profiler.profile(
                [Endpoint(method="GET", path_template="/api/orders")], [actor_a, actor_b], None)
    finally:
        await store.aclose_all()
