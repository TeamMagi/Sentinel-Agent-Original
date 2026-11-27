"""HeaderBypassOracle — proxy/edge header'ı ile erişim-kontrolü atlatma. Faz 3 / T5.

Saldırgan header'sız kurbanın kaynağına gerçekten reddediliyor mu (negatif kontrol) — sonra
`X-Original-URL` gibi header'larla GÜVENLİ (GET/HEAD) istekler denenir. Kanıt: yapısal AYNI
2xx + kurbana özgü marker (`secret`) sızıntısı → CONFIRMED. Yalnız 2xx (marker yok) → LIKELY.
Header'sız da erişiliyorsa (public/IDOR) ya da tüm varyantlar reddedilirse → REJECTED.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.header_bypass import HeaderBypassOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="GET", path_template="/api/private/{id}", id_param="id")

_DB = {
    "V-1": {"id": "V-1", "secret": "victim-secret-aa11bb22"},
    "A-1": {"id": "A-1", "secret": "attacker-secret-cc33dd44"},
}
_OWNERS = {"V-1": "victim", "A-1": "attacker"}
_TOKENS = {"TOKEN_V": "victim", "TOKEN_A": "attacker"}


def _actor_of(request: httpx.Request) -> str:
    return _TOKENS.get(request.headers.get("authorization", "").replace("Bearer ", ""), "")


def _oid_of_path(request: httpx.Request) -> str:
    return request.url.path.rsplit("/", 1)[-1]


def _direct_owner_checked(request: httpx.Request) -> httpx.Response:
    oid = _oid_of_path(request)
    obj = _DB.get(oid)
    if obj is None:
        return httpx.Response(404, json={"error": "not found"})
    if _actor_of(request) != _OWNERS.get(oid):
        return httpx.Response(403, json={"error": "forbidden"})
    return httpx.Response(200, json=obj)


def make_vulnerable_app(calls: list[str]):
    """`X-Original-URL` sunucuda yolu yeniden yazar, sahiplik kontrolü hiç çalışmaz."""

    def handler(request):
        calls.append(request.method.upper())
        original = request.headers.get("x-original-url")
        if original is not None:
            oid = original.split("?", 1)[0].rsplit("/", 1)[-1]
            obj = _DB.get(oid)
            if obj is None:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json=obj)
        return _direct_owner_checked(request)

    return handler


def make_hardened_app(calls: list[str]):
    """Header'lar tamamen yoksayılır — tüm varyantlar sahiplik kontrolüne çarpar."""

    def handler(request):
        calls.append(request.method.upper())
        return _direct_owner_checked(request)

    return handler


def make_near_miss_app(calls: list[str]):
    """Header honored (200, aynı şekil) ama veri maskeli — kurbana özgü marker yok."""

    def handler(request):
        calls.append(request.method.upper())
        original = request.headers.get("x-original-url")
        if original is not None:
            oid = original.split("?", 1)[0].rsplit("/", 1)[-1]
            if oid not in _DB:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json={"id": oid, "secret": "***redacted***"})
        return _direct_owner_checked(request)

    return handler


def make_public_app(calls: list[str]):
    """Header'sız da erişiliyor — header bypass değil (IDOR/public-by-design)."""

    def handler(request):
        calls.append(request.method.upper())
        oid = _oid_of_path(request)
        obj = _DB.get(oid)
        return httpx.Response(200, json=obj) if obj else httpx.Response(404, json={"error": "nf"})

    return handler


def make_catch_all_app(calls: list[str]):
    """SPA/catch-all fallback: `X-Original-URL` HEDEF NE OLURSA OLSUN aynı genel içeriği döner —
    gerçek bir yol-tabanlı bypass değil, her isteğe aynı cevap (var-olmayan yol da 200 alır)."""

    def handler(request):
        calls.append(request.method.upper())
        if "x-original-url" in {k.lower() for k in request.headers}:
            return httpx.Response(200, json=_DB["V-1"])   # her header değeri için AYNI cevap
        return _direct_owner_checked(request)

    return handler


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    victim = Actor(name="victim", auth=AuthState(headers={"Authorization": "Bearer TOKEN_V"}),
                   own_object_ids={"id": "V-1"})
    attacker = Actor(name="attacker", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
                     own_object_ids={"id": "A-1"})
    oracle = HeaderBypassOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(victim), store.create(attacker)


@pytest.mark.asyncio
async def test_confirmed_proxy_rewrite_bypass():
    calls: list[str] = []
    store, oracle, victim, attacker = _setup(make_vulnerable_app(calls))
    f = await oracle.run(EP, victim, attacker, resource_key="id")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.positive_control and f.evidence.negative_control
    assert "victim-secret-aa11bb22" in f.evidence.leaked_markers
    assert "X-Original-URL" in f.evidence.leaked_markers[0]
    assert all(m in ("GET", "HEAD") for m in calls)   # yalnız güvenli method
    await store.aclose_all()


@pytest.mark.asyncio
async def test_likely_when_structurally_same_but_no_marker():
    store, oracle, victim, attacker = _setup(make_near_miss_app([]))
    f = await oracle.run(EP, victim, attacker, resource_key="id")
    assert f.verdict == base.LIKELY and f.confidence == "medium"
    assert f.verdict != base.CONFIRMED
    assert f.triage_note
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_hardened_ignores_all_headers():
    store, oracle, victim, attacker = _setup(make_hardened_app([]))
    f = await oracle.run(EP, victim, attacker, resource_key="id")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_header_less_access_already_works():
    """Saldırgan header'SIZ da 2xx alıyorsa bu header bypass değildir (public/IDOR)."""
    store, oracle, victim, attacker = _setup(make_public_app([]))
    f = await oracle.run(EP, victim, attacker, resource_key="id")
    assert f.verdict == base.REJECTED
    assert "header'sız" in (f.triage_note or "")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_victim_has_no_own_id():
    store, oracle, victim, attacker = _setup(make_vulnerable_app([]))
    victim.actor.own_object_ids.clear()
    f = await oracle.run(EP, victim, attacker, resource_key="id")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_on_catch_all_spa_fallback():
    """Header'lı rastgele var-olmayan yol da aynı 2xx'i dönüyorsa (SPA fallback) CONFIRMED değil
    INCONCLUSIVE olmalı."""
    store, oracle, victim, attacker = _setup(make_catch_all_app([]))
    f = await oracle.run(EP, victim, attacker, resource_key="id")
    assert f.verdict == base.INCONCLUSIVE
    assert "catch-all" in (f.triage_note or "")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_only_safe_methods_sent():
    """Endpoint güvenli method değilse (POST/PUT/...) oracle hiç istek göndermeden INCONCLUSIVE döner."""
    calls: list[str] = []
    store, oracle, victim, attacker = _setup(make_vulnerable_app(calls))
    ep_post = Endpoint(method="POST", path_template="/api/private/{id}", id_param="id")
    f = await oracle.run(ep_post, victim, attacker, resource_key="id")
    assert f.verdict == base.INCONCLUSIVE
    assert calls == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_actor_headers_not_permanently_mutated():
    """Varyant header'ları (X-Role, X-Forwarded-For, ...) aktörün KALICI auth header'larına
    sızmamalı — izolasyon (CLAUDE.md §5 kural 3)."""
    store, oracle, victim, attacker = _setup(make_vulnerable_app([]))
    before = dict(attacker.actor.auth.headers)
    await oracle.run(EP, victim, attacker, resource_key="id")
    assert attacker.actor.auth.headers == before
    assert "X-Role" not in attacker.actor.auth.headers
    assert "X-Forwarded-For" not in attacker.actor.auth.headers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_repro_curl_has_no_raw_token():
    store, oracle, victim, attacker = _setup(make_vulnerable_app([]))
    f = await oracle.run(EP, victim, attacker, resource_key="id")
    assert "TOKEN_A" not in f.evidence.repro_curl
    assert "<ATTACKER_TOKEN>" in f.evidence.repro_curl
    await store.aclose_all()
