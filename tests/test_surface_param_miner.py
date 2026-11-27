"""Faz 3 / T4 — gizli parametre keşfi (param-miner). Ağsız: httpx.MockTransport."""
import itertools

import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Param, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import (
    ParamMinerSource,
    SurfaceContext,
    SurfaceDiscovery,
    default_sources,
)
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


def _make(handler):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    return scanner, store, session


async def _discover(handler, known, source=None):
    scanner, store, session = _make(handler)
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session, known=list(known))
        endpoints = await (source or ParamMinerSource()).discover(ctx)
        return endpoints, ctx
    finally:
        await store.aclose_all()


@pytest.mark.asyncio
async def test_hidden_param_that_changes_body_is_found():
    """Yalnız `debug=1` gövdeyi değiştiriyor: adı yansımadan işlenen parametre bulunur."""
    def handler(request):
        if request.url.path != "/api/items":
            return httpx.Response(404, json={"error": "yok"})
        if request.url.params.get("debug") == "1":
            return httpx.Response(200, json={"ok": True, "detail": "x" * 200})
        return httpx.Response(200, json={"ok": True})

    endpoints, _ctx = await _discover(
        handler, [Endpoint(method="GET", path_template="/api/items")])
    assert len(endpoints) == 1
    params = endpoints[0].params
    assert [p.name for p in params] == ["debug"]
    assert params[0].location == "query"
    assert params[0].sources == ["param-miner"]
    assert params[0].example is None          # değer kopyalanmaz


@pytest.mark.asyncio
async def test_echoing_endpoint_does_not_produce_params():
    """Adı gövdeye basan ama işlemeyen uç: yansıma 'var' sayılmaz."""
    def handler(request):
        if request.url.path != "/api/echo":
            return httpx.Response(404, json={"error": "yok"})
        return httpx.Response(200, text="query=" + request.url.query.decode() + "&" + "x" * 200)

    endpoints, _ctx = await _discover(
        handler, [Endpoint(method="GET", path_template="/api/echo")])
    assert endpoints == []


@pytest.mark.asyncio
async def test_unstable_endpoint_is_skipped():
    """Her istekte farklı gövde → kontroller tutarsız → hiçbir parametre üretilmez."""
    counter = itertools.count()

    def handler(request):
        if request.url.path != "/api/flaky":
            return httpx.Response(404, json={"error": "yok"})
        return httpx.Response(200, text="x" * (100 + next(counter) * 50))

    endpoints, _ctx = await _discover(
        handler, [Endpoint(method="GET", path_template="/api/flaky")])
    assert endpoints == []


@pytest.mark.asyncio
async def test_catch_all_same_response_yields_no_params():
    """Parametreden bağımsız aynı yanıt: catch-all/aynı yanıt uçta parametre UYDURULMAZ."""
    methods: list[str] = []

    def handler(request):
        methods.append(request.method)
        return httpx.Response(200, text="same-response" * 50)

    endpoints, _ctx = await _discover(
        handler, [Endpoint(method="GET", path_template="/api/anything")])
    assert endpoints == []
    assert methods and set(methods) == {"GET"}


@pytest.mark.asyncio
async def test_binary_search_finds_multiple_real_params():
    """Aynı grupta iki gerçek parametre: ikili arama ikisini de daraltır."""
    def handler(request):
        if request.url.path != "/api/things":
            return httpx.Response(404, json={"error": "yok"})
        body = {"ok": True}
        if request.url.params.get("role") == "1":
            body["role_detail"] = "A" * 200
        if request.url.params.get("format") == "1":
            body["format_detail"] = "B" * 200
        return httpx.Response(200, json=body)

    endpoints, _ctx = await _discover(
        handler, [Endpoint(method="GET", path_template="/api/things")])
    assert len(endpoints) == 1
    assert {p.name for p in endpoints[0].params} == {"role", "format"}


@pytest.mark.asyncio
async def test_only_get_is_sent_and_request_cap_is_not_exceeded():
    """Yalnız GET; kaynak başına istek tavanı aşılmaz."""
    methods: list[str] = []

    def handler(request):
        methods.append(request.method)
        return httpx.Response(200, text="same-response" * 50)

    source = ParamMinerSource(max_requests=5, group_size=2)
    endpoints, ctx = await _discover(
        handler, [Endpoint(method="GET", path_template="/api/capped")], source=source)
    assert endpoints == []
    assert methods and set(methods) == {"GET"}
    assert len(methods) <= 5
    assert ctx.requests_used <= 5


@pytest.mark.asyncio
async def test_path_placeholder_without_concrete_value_is_skipped():
    """`{id}` için somut değer yoksa uç atlanır: uydurma id ile istek atılmaz."""
    calls: list[str] = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    endpoints, _ctx = await _discover(
        handler, [Endpoint(method="GET", path_template="/api/users/{id}")])
    assert endpoints == []
    assert calls == []


@pytest.mark.asyncio
async def test_known_query_params_are_not_retried_as_candidates():
    """Uçta zaten bilinen parametre adı aday listesinden düşülür (boşa istek yok)."""
    def handler(request):
        return httpx.Response(200, json={"ok": True})

    endpoint = Endpoint(
        method="GET", path_template="/api/items",
        params=[Param(name="debug", location="query", sources=["openapi"])])
    source = ParamMinerSource(candidates=("debug",))
    endpoints, ctx = await _discover(handler, [endpoint], source=source)
    assert endpoints == []
    assert ctx.requests_used == 0          # aday kalmadı: kontrol bile atılmaz


def test_default_sources_places_param_miner_after_smart_wordlist():
    names = [source.name for source in default_sources()]
    assert names[-2:] == ["smart-wordlist", "param-miner"]


@pytest.mark.asyncio
async def test_discovery_merges_mined_params_into_known_endpoint():
    """Bulunan parametreler seed uca kaybolmadan birleşir (T2 `_merge_known` deseni)."""
    def handler(request):
        if request.url.path != "/api/items":
            return httpx.Response(404, json={"error": "yok"})
        if request.url.params.get("debug") == "1":
            return httpx.Response(200, json={"ok": True, "detail": "x" * 200})
        return httpx.Response(200, json={"ok": True})

    scanner, store, session = _make(handler)
    endpoint = Endpoint(method="GET", path_template="/api/items")
    discovery = SurfaceDiscovery([ParamMinerSource()])
    try:
        found = await discovery.run(scanner.replayer, BASE, session, [endpoint])
    finally:
        await store.aclose_all()
    assert found == []
    updates = discovery.known_param_updates[("GET", "/api/items")]
    assert [p.name for p in updates] == ["debug"]
    assert updates[0].sources == ["param-miner"]
