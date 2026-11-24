"""Login yanıtından own-id bootstrap'i (R-B3 artığı): `own_ids_from` ipucu → `AuthState.login_ids`.

Juice Shop'ta sepet id'si yalnız login yanıtındaki `authentication.bid` alanında gelir; genel
kural (`<ad>Id`) bunu çıkaramaz. Config'te aktöre özel DEĞER yerine, her aktörde aynı olan YOL
(`basket: json:authentication.bid`) verilir. Network'süz (httpx.MockTransport).
"""
import httpx
import pytest

from pentestai.auth.provider import TokenAuthProvider, build_auth_provider
from pentestai.models import Actor, AuthState, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine
from pentestai.recon.crawl import CrawlRecon

BASE = "http://localhost:3000"
SCOPE = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
LOGIN = f"{BASE}/rest/user/login"
TOKEN_FROM = {"kind": "bearer", "from": "json:authentication.token"}


def _login_app(body: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)
    return handler


def _provider(body: dict, hints: dict | None) -> TokenAuthProvider:
    return TokenAuthProvider(LOGIN, {"email": "a@test.local", "password": "x"}, TOKEN_FROM,
                             transport=httpx.MockTransport(_login_app(body)),
                             own_ids_from=hints)


JUICE_LOGIN = {"authentication": {"token": "tok-1", "bid": 6, "umail": "a@test.local"}}


@pytest.mark.asyncio
async def test_hint_extracts_basket_id_from_login_response():
    state = await _provider(JUICE_LOGIN, {"basket": "json:authentication.bid"}).acquire()
    assert state.login_ids == {"basket": "6"}
    assert state.headers == {"Authorization": "Bearer tok-1"}


@pytest.mark.asyncio
async def test_without_hints_login_ids_stay_empty():
    state = await _provider(JUICE_LOGIN, None).acquire()
    assert state.login_ids == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "json:authentication.missing",       # yol yok
    "json:authentication",               # skaler değil (dict)
    "json:authentication.token.deeper",  # ara düğüm skaler
    "header:x-basket",                   # desteklenmeyen kaynak
])
async def test_bad_or_missing_hint_is_ignored_without_breaking_login(path):
    state = await _provider(JUICE_LOGIN, {"basket": path}).acquire()
    assert state.login_ids == {}
    assert state.headers == {"Authorization": "Bearer tok-1"}


@pytest.mark.asyncio
async def test_unsafe_id_values_are_rejected():
    body = {"authentication": {"token": "t", "bid": "6/../../admin", "flag": True}}
    state = await _provider(body, {"basket": "json:authentication.bid",
                                   "flag": "json:authentication.flag"}).acquire()
    assert state.login_ids == {}


@pytest.mark.asyncio
async def test_hint_never_exposes_token_as_object_id():
    # Yanlış yapılandırma: ipucu token alanını gösteriyor → sır own-id olarak taşınmamalı.
    state = await _provider(JUICE_LOGIN, {"basket": "json:authentication.token"}).acquire()
    assert state.login_ids == {}


@pytest.mark.asyncio
async def test_factory_passes_own_ids_from():
    provider = build_auth_provider({
        "type": "token", "login_url": LOGIN, "credentials": {},
        "token_location": TOKEN_FROM, "own_ids_from": {"basket": "json:authentication.bid"},
    }, transport=httpx.MockTransport(_login_app(JUICE_LOGIN)))
    assert (await provider.acquire()).login_ids == {"basket": "6"}


@pytest.mark.asyncio
async def test_feedback_bootstrap_includes_login_ids():
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda r: httpx.Response(404, json={})))
    s = store.create(Actor(name="victim", auth=AuthState(
        headers={"Authorization": "Bearer opaque"}, login_ids={"basket": "6"})))
    crawl = CrawlRecon(Replayer(PolicyEngine(SCOPE)), BASE)
    found = await crawl.feedback_bootstrap(s)
    await store.aclose_all()
    assert found == {"basket": "6"}
    assert "6" in crawl.id_pool.get("basket")
