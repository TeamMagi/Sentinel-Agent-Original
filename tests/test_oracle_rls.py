"""RlsMisconfigOracle birim testleri — ağsız (httpx.MockTransport).

RLS kapalı/anonymous sızıntı, doğru policy, 401, eksik own-id, başarısız pozitif kontrol,
kararsız baseline, paylaşılan id ve JSON-liste-olmayan gövde senaryolarını kapsar.
"""
from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from pentestai.models import (
    Actor,
    AuthState,
    BudgetConfig,
    Endpoint,
    NormalizedResponse,
    Scope,
)
from pentestai.net import Replayer, SessionStore
from pentestai.oracle.rls import RlsMisconfigOracle
from pentestai.policy import PolicyEngine
from pentestai.recon.providers import ProviderEvidence
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
EP = Endpoint(method="GET", path_template="/rest/v1/orders", id_param="id")
A_ID = "ORD-A-1001"
B_ID = "ORD-B-2002"


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET"])


def _token(request: httpx.Request) -> str:
    return request.headers.get("authorization", "").replace("Bearer ", "")


def _rows(*ids: str) -> list[dict]:
    return [{"id": oid, "address": f"{oid}-adres"} for oid in ids]


def _actor(name: str, token: str, own: dict[str, str] | None = None) -> Actor:
    return Actor(name=name, auth=AuthState(headers={"Authorization": f"Bearer {token}"}),
                 own_object_ids=own or {})


async def _run(
    handler: Callable[[httpx.Request], httpx.Response], *,
    victim_own: str | None = A_ID, attacker_own: str | None = B_ID,
    with_anon: bool = False, id_column: str = "id",
):
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    victim = store.create(_actor("user_A", "TOKEN_A",
                                 {} if victim_own is None else {"orders": victim_own}))
    attacker = store.create(_actor("user_B", "TOKEN_B",
                                   {} if attacker_own is None else {"orders": attacker_own}))
    anon = store.create(Actor(name="anonymous", role="anonymous")) if with_anon else None
    oracle = RlsMisconfigOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        return await oracle.run(EP, victim, attacker, resource_key="orders", anon=anon,
                                id_column=id_column)
    finally:
        await store.aclose_all()


@pytest.mark.asyncio
async def test_rls_disabled_leaks_victim_row_to_attacker():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_rows(A_ID, B_ID))

    finding = await _run(handler)
    assert finding.verdict == "CONFIRMED"
    assert finding.confidence == "high"
    assert finding.parameter == "(rls)"
    assert finding.evidence.negative_control is True
    assert any(A_ID in marker for marker in finding.evidence.leaked_markers)
    # Redaction: yalnız id yazılır, ham satır alanı (address) marker'a girmez.
    assert not any("address" in marker for marker in finding.evidence.leaked_markers)


@pytest.mark.asyncio
async def test_anon_role_leaks_victim_row():
    def handler(request: httpx.Request) -> httpx.Response:
        token = _token(request)
        if token == "TOKEN_A":
            return httpx.Response(200, json=_rows(A_ID))
        if token == "TOKEN_B":
            return httpx.Response(200, json=_rows(B_ID))
        return httpx.Response(200, json=_rows(A_ID, B_ID))

    finding = await _run(handler, with_anon=True)
    assert finding.verdict == "CONFIRMED"
    assert finding.parameter == "(rls:anon)"
    assert any("anonim rol" in marker for marker in finding.evidence.leaked_markers)
    # Yalnız anon sızdı → repro kullanıcı token'ı değil anon key yer tutucusu taşır.
    assert "<ANON_KEY>" in finding.evidence.repro_curl
    assert "_TOKEN>" not in finding.evidence.repro_curl


@pytest.mark.asyncio
async def test_correct_rls_rejects():
    def handler(request: httpx.Request) -> httpx.Response:
        token = _token(request)
        return httpx.Response(200, json=_rows(A_ID if token == "TOKEN_A" else B_ID))

    finding = await _run(handler, with_anon=True)
    assert finding.verdict == "REJECTED"
    assert finding.evidence.negative_control is True
    assert finding.triage_note == "RLS satırları sahibine göre filtreliyor"


@pytest.mark.asyncio
async def test_attacker_401_is_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        if _token(request) == "TOKEN_B":
            return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(200, json=_rows(A_ID))

    finding = await _run(handler)
    assert finding.verdict == "REJECTED"


@pytest.mark.asyncio
async def test_missing_victim_own_id_is_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:   # istek beklenmez
        raise AssertionError("own id yokken istek atılmamalıydı")

    finding = await _run(handler, victim_own=None)
    assert finding.verdict == "INCONCLUSIVE"
    assert "kendi satır id'si yok" in (finding.triage_note or "")


@pytest.mark.asyncio
async def test_victim_cannot_see_own_row_is_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_rows(B_ID))

    finding = await _run(handler)
    assert finding.verdict == "INCONCLUSIVE"
    assert "pozitif kontrol" in (finding.triage_note or "")


@pytest.mark.asyncio
async def test_unstable_baseline_is_inconclusive():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if _token(request) == "TOKEN_A":
            calls["n"] += 1
            return httpx.Response(200, json=_rows(A_ID) if calls["n"] == 1 else _rows())
        return httpx.Response(200, json=_rows(A_ID, B_ID))

    finding = await _run(handler)
    assert finding.evidence.baseline_stable is False
    assert finding.verdict == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_shared_actor_id_is_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:   # istek beklenmez
        raise AssertionError("paylaşılan id'de istek atılmamalıydı")

    finding = await _run(handler, attacker_own=A_ID)
    assert finding.verdict == "INCONCLUSIVE"
    assert "aynı satırı paylaşıyor" in (finding.triage_note or "")


@pytest.mark.asyncio
async def test_non_list_json_body_is_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"id": A_ID}]})

    assert RlsMisconfigOracle._row_ids(
        NormalizedResponse(status=200, json_body={"data": [{"id": A_ID}]}), "id") == set()
    finding = await _run(handler)
    assert finding.verdict == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_scanner_supabase_anon_session_cached_and_apikey_only():
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    victim = scanner.sessions.create(Actor(
        name="user_A",
        auth=AuthState(headers={"Authorization": "Bearer TOKEN", "apikey": "anon-key"})))
    ev = ProviderEvidence(kind="supabase", signal="GoTrue", root="/rest/v1/",
                          tables=["orders"])

    first = scanner._rls_anon_session(ev, victim)
    second = scanner._rls_anon_session(ev, victim)
    assert first is not None and first is second
    assert first.actor.name == "supabase_anon"
    assert first.actor.role == "anonymous"
    assert first.actor.auth.headers == {"apikey": "anon-key"}

    scanner.anon = scanner.sessions.create(Actor(name="anonymous", role="anonymous"))
    no_key = scanner.sessions.create(Actor(
        name="user_C", auth=AuthState(headers={"Authorization": "Bearer TOKEN"})))
    assert scanner._rls_anon_session(ev, no_key) is scanner.anon
    postgrest = ProviderEvidence(kind="postgrest", signal="OpenAPI", root="/rest/v1/",
                                 tables=["orders"])
    assert scanner._rls_anon_session(postgrest, victim) is scanner.anon
    await scanner.aclose()
