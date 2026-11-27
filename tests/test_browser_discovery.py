"""Faz 2 / T4 — BrowserDiscovery: gerçek headless Chromium, sahte SPA (context.route), ağ YOK.

`http://app.test.local` yalnızca yerel route handler'larıyla sunulur; her aktörün AYRI
context'i vardır ve sunucu Authorization başlığına göre farklı menü döner. Gerçek hedefe
tek istek atılmaz.
"""
from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

import httpx
import pytest
import pytest_asyncio
from playwright.async_api import Browser, BrowserContext, async_playwright

from pentestai.models import Actor, AuthState, Scope
from pentestai.net import BudgetExceeded, Session, SessionStore
from pentestai.policy import PolicyEngine
from pentestai.recon.browser import BrowserCrawler, SafeActionPolicy
from pentestai.recon.browser.discovery import BrowserDiscovery

ORIGIN = "http://app.test.local"
HOST = "app.test.local"
Seen = list[tuple[str, str, dict[str, str]]]

ADMIN_HTML = """<html><body>
<script>
fetch('/api/admin/users');
fetch('/api/orders/7');
fetch('/api/me', {headers: {'X-Token': localStorage.getItem('sentinel_token') || '',
                            'X-Sid': localStorage.getItem('sid') || ''}});
</script>
<button id="del" onclick="fetch('/api/users/1',{method:'DELETE'})">Delete account</button>
<form id="feedback" method="post" action="/api/feedback">
  <input name="q"><button type="submit">Send</button>
</form>
</body></html>"""
USER_HTML = """<html><body><script>fetch('/api/orders/8');</script></body></html>"""
ANON_HTML = """<html><body><script>fetch('/api/public/health');</script></body></html>"""


@pytest_asyncio.fixture
async def browser() -> Browser:
    async with async_playwright() as pw:
        launched = await pw.chromium.launch()
        yield launched
        await launched.close()


async def _context(
    browser: Browser, html_for_role: Callable[[str], str], seen: Seen,
) -> BrowserContext:
    context = await browser.new_context()

    async def _handle(route) -> None:
        request = route.request
        path = urlsplit(request.url).path
        auth = request.headers.get("authorization", "")
        role = "admin" if "ADMIN-TOKEN" in auth else "user" if "USER-TOKEN" in auth else "anon"
        seen.append((request.method.upper(), path, dict(request.headers)))
        if path.startswith("/api/"):
            await route.fulfill(status=200, content_type="application/json", body="{}")
        else:
            await route.fulfill(status=200, content_type="text/html",
                                body=html_for_role(role))

    await context.route(f"{ORIGIN}/**", _handle)
    return context


def _crawler(context: BrowserContext) -> BrowserCrawler:
    scope = Scope(allowed_hosts=[HOST], allowed_ports=[80], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD"])
    policy = PolicyEngine(scope)
    return BrowserCrawler(policy, SafeActionPolicy(policy), context=context,
                          settle_ms=200, timeout_ms=3_000, max_pages=2, max_depth=1)


def _store() -> SessionStore:
    return SessionStore(base_url=ORIGIN, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"ok": True})))


async def _sessions(store: SessionStore) -> list[Session]:
    return [
        store.create(Actor(name="admin", role="admin",
                           auth=AuthState(headers={"Authorization": "Bearer ADMIN-TOKEN"},
                                          cookies={"session": "admin-cookie"}))),
        store.create(Actor(name="user_A", role="user",
                           auth=AuthState(headers={"Authorization": "Bearer USER-TOKEN"}))),
    ]


@pytest.mark.asyncio
async def test_role_specific_menus_unified_endpoints_rbac_and_local_storage(browser):
    seen: Seen = []
    html = {"admin": ADMIN_HTML, "user": USER_HTML, "anon": ANON_HTML}
    contexts = [await _context(browser, lambda role: html[role], seen) for _ in range(3)]
    pending = iter(contexts)

    def factory() -> BrowserCrawler:
        return _crawler(next(pending))

    store = _store()
    try:
        sessions = await _sessions(store)
        discovery = BrowserDiscovery(
            PolicyEngine(Scope(allowed_hosts=[HOST], allowed_ports=[80])),
            crawler_factory=factory,
            local_storage={"admin": {"sentinel_token": "{bearer}", "sid": "{cookie:session}"}},
        )
        result = await discovery.run(f"{ORIGIN}/", sessions, [HOST])
    finally:
        await store.aclose_all()
        for context in contexts:
            await context.close()

    keys = {(e.method, e.path_template) for e in result.endpoints}
    assert ("GET", "/api/admin/users") in keys          # yalnız admin menüsü
    assert ("GET", "/api/orders/{id}") in keys          # iki aktörün birleşimi, tekil
    assert ("GET", "/api/public/health") in keys        # anon menüsü
    assert ("GET", "/api/me") in keys
    assert sum(1 for e in result.endpoints if
               (e.method, e.path_template) == ("GET", "/api/orders/{id}")) == 1

    # Görünürlük ROL anahtarlı; own_ids ise AKTÖR adı anahtarlı.
    assert result.visibility.roles() == ["admin", "anon", "user"]
    candidates = result.visibility.rbac_candidates()
    admin_only = next(c for c in candidates if c.path_template == "/api/admin/users")
    assert admin_only.visible_to == ["admin"]
    assert "user" in admin_only.hidden_from
    assert ("GET", "/api/admin/users") in result.visibility.exclusive_to("admin")

    # Kendi id'leri rol bazlı; anon own-id ÜRETMEZ.
    assert result.own_ids == {"admin": {"order": "7"}, "user_A": {"order": "8"}}

    # localStorage şablonu yalnız admin bağlamında, kendi token/cookie'siyle doldu.
    me = [h for method, path, h in seen if path == "/api/me"]
    assert me and me[0].get("x-token") == "ADMIN-TOKEN"
    assert me[0].get("x-sid") == "admin-cookie"

    assert result.blocked_count >= 1                   # POST form gönderilmeden kesildi
    assert any("Delete account" in s for s in result.skipped_actions)
    assert result.pages_visited >= 3
    assert not any(method == "DELETE" for method, _, _ in seen)


@pytest.mark.asyncio
async def test_one_actor_failure_does_not_stop_others(capsys, browser):
    seen: Seen = []
    good_context = await _context(browser, lambda role: USER_HTML, seen)

    class _Broken:
        async def crawl(self, *args: object, **kwargs: object):
            raise RuntimeError("sahte tarayıcı hatası")

    broken = _Broken()
    factories: list[Callable[[], object]] = [lambda: broken, lambda: _crawler(good_context)]
    pending = iter(factories)

    store = _store()
    try:
        sessions = await _sessions(store)
        result = await BrowserDiscovery(
            PolicyEngine(Scope(allowed_hosts=[HOST], allowed_ports=[80])),
            crawler_factory=lambda: next(pending)(),  # type: ignore[return-value]
            include_anonymous=False,
        ).run(f"{ORIGIN}/", sessions, [HOST])
    finally:
        await store.aclose_all()
        await good_context.close()

    assert {(e.method, e.path_template) for e in result.endpoints} == {
        ("GET", "/api/orders/{id}")}
    assert result.own_ids == {"user_A": {"order": "8"}}
    assert "UYARI" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_budget_exceeded_propagates(browser):
    seen: Seen = []
    context = await _context(browser, lambda role: USER_HTML, seen)

    class _OutOfBudget:
        async def crawl(self, *args: object, **kwargs: object):
            raise BudgetExceeded("bütçe doldu")

    store = _store()
    try:
        sessions = await _sessions(store)
        with pytest.raises(BudgetExceeded):
            await BrowserDiscovery(
                PolicyEngine(Scope(allowed_hosts=[HOST], allowed_ports=[80])),
                crawler_factory=lambda: _OutOfBudget(),  # type: ignore[return-value]
                include_anonymous=False,
            ).run(f"{ORIGIN}/", sessions, [HOST])
    finally:
        await store.aclose_all()
        await context.close()


def test_resolve_ignores_unknown_cookie_and_keeps_plain_value():
    actor = Actor(name="a", auth=AuthState(headers={"Authorization": "Bearer X"}))
    assert BrowserDiscovery._resolve("{bearer}", actor) == "X"
    assert BrowserDiscovery._resolve("pre-{cookie:missing}", actor) is None
    assert BrowserDiscovery._resolve("plain", actor) == "plain"
