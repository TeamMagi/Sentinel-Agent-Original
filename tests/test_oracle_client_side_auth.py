"""ClientSideAuthOracle — yalnız istemcide gizlenen ayrıcalıklı uç nokta testi (ağsız)."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.client_side_auth import ClientSideAuthOracle
from pentestai.policy import PolicyEngine
from pentestai.recon.js_bundle import ClientGatedEndpoint
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
REPORT = {"report": "export", "rows": [{"id": 1}, {"id": 2}]}
GATED = ClientGatedEndpoint(
    endpoint=Endpoint(method="GET", path_template="/api/reports/export", id_param="id"),
    signal="user.role === 'admin'",
    bundle_url=f"{BASE}/static/app.js",
)


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])


def _is_admin(request: httpx.Request) -> bool:
    return request.headers.get("authorization") == "Bearer ADMIN"


def vulnerable_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/api/reports/export":
        return httpx.Response(200, json=REPORT)          # rol kontrolü YOK
    return httpx.Response(404, json={"error": "not found"})


def hardened_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/api/reports/export":
        if _is_admin(request):
            return httpx.Response(200, json=REPORT)
        return httpx.Response(403, json={"error": "forbidden"})
    return httpx.Response(404, json={"error": "not found"})


def catch_all_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.startswith("/api/"):
        return httpx.Response(200, json=REPORT)          # SPA fallback — her yol aynı
    return httpx.Response(404, json={"error": "not found"})


def _setup(handler):
    store = SessionStore(transport=httpx.MockTransport(handler))
    admin = store.create(Actor(
        name="admin", role="admin",
        auth=AuthState(headers={"Authorization": "Bearer ADMIN"})))
    user = store.create(Actor(
        name="user_low", role="user",
        auth=AuthState(headers={"Authorization": "Bearer RAW-USER-SECRET"})))
    oracle = ClientSideAuthOracle(Replayer(PolicyEngine(_scope())), BASE)
    return store, oracle, admin, user


@pytest.mark.asyncio
async def test_confirmed_on_path_without_admin_keyword():
    store, oracle, admin, user = _setup(vulnerable_handler)
    try:
        f = await oracle.run(GATED.endpoint, admin, user, resource_key="export", gated=GATED)
    finally:
        await store.aclose_all()
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.type == "client_side_auth" and f.parameter == "(client-side)"
    assert f.evidence.positive_control is True


@pytest.mark.asyncio
async def test_rejected_when_server_enforces_role():
    store, oracle, admin, user = _setup(hardened_handler)
    try:
        f = await oracle.run(GATED.endpoint, admin, user, resource_key="export", gated=GATED)
    finally:
        await store.aclose_all()
    assert f.verdict == base.REJECTED
    assert "sunucu da yetkiyi denetliyor" in (f.triage_note or "")


@pytest.mark.asyncio
async def test_catch_all_spa_fallback_downgrades_to_inconclusive():
    store, oracle, admin, user = _setup(catch_all_handler)
    try:
        f = await oracle.run(GATED.endpoint, admin, user, resource_key="export", gated=GATED)
    finally:
        await store.aclose_all()
    assert f.verdict == base.INCONCLUSIVE
    assert "catch-all" in (f.triage_note or "")


@pytest.mark.asyncio
async def test_missing_gated_signal_is_inconclusive():
    store, oracle, admin, user = _setup(vulnerable_handler)
    try:
        f = await oracle.run(GATED.endpoint, admin, user, resource_key="export")
    finally:
        await store.aclose_all()
    assert f.verdict == base.INCONCLUSIVE
    assert "istemci-tarafı kontrol sinyali yok" in (f.triage_note or "")


@pytest.mark.asyncio
async def test_marker_contains_signal_and_bundle_url():
    store, oracle, admin, user = _setup(vulnerable_handler)
    try:
        f = await oracle.run(GATED.endpoint, admin, user, resource_key="export", gated=GATED)
    finally:
        await store.aclose_all()
    markers = " ".join(f.evidence.leaked_markers)
    assert GATED.signal in markers and GATED.bundle_url in markers


@pytest.mark.asyncio
async def test_repro_curl_has_no_raw_token():
    store, oracle, admin, user = _setup(vulnerable_handler)
    try:
        f = await oracle.run(GATED.endpoint, admin, user, resource_key="export", gated=GATED)
    finally:
        await store.aclose_all()
    assert "RAW-USER-SECRET" not in f.evidence.repro_curl
    assert "USER_LOW_TOKEN" in f.evidence.repro_curl


@pytest.mark.asyncio
async def test_id_endpoint_without_own_id_is_inconclusive():
    ep = Endpoint(method="GET", path_template="/api/reports/{id}", id_param="id")
    gated = ClientGatedEndpoint(endpoint=ep, signal="isAdmin", bundle_url=f"{BASE}/static/app.js")
    store, oracle, admin, user = _setup(vulnerable_handler)
    try:
        f = await oracle.run(ep, admin, user, resource_key="reports", gated=gated)
    finally:
        await store.aclose_all()
    assert f.verdict == base.INCONCLUSIVE
    assert "obje id'si yok" in (f.triage_note or "")


@pytest.mark.asyncio
async def test_run_client_side_auth_scan_returns_empty_without_admin():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "not found"})

    store = SessionStore(transport=httpx.MockTransport(handler))
    user = store.create(Actor(name="user", role="user"))
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    try:
        assert await scanner.run_client_side_auth_scan([user]) == []
    finally:
        await scanner.aclose()
        await store.aclose_all()


@pytest.mark.asyncio
async def test_run_client_side_auth_scan_returns_empty_without_attacker():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "not found"})

    store = SessionStore(transport=httpx.MockTransport(handler))
    admin = store.create(Actor(name="admin", role="admin"))
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    try:
        assert await scanner.run_client_side_auth_scan([admin]) == []
    finally:
        await scanner.aclose()
        await store.aclose_all()
