"""T5b — gerçek form login, adım dayanıklılığı ve görünürlük koruması.

Gerçek headless Chromium kullanılır ama origin TAMAMEN `context.route()` ile sahte sunulur;
gerçek ağ/hedef yoktur. Parola yalnız test içinde bellekte tutulur, stdout'a SIZMAZ.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import pytest
import pytest_asyncio
from playwright.async_api import Browser, BrowserContext, async_playwright

from pentestai.models import Scope
from pentestai.policy import PolicyEngine
from pentestai.recon.browser import BrowserCrawler, SafeActionPolicy
from pentestai.recon.browser.discovery import BrowserDiscovery, BrowserDiscoveryResult
from pentestai.recon.browser.login import BrowserLogin

ORIGIN = "http://login.test.local"
HOST = "login.test.local"
PASSWORD = "SUPER-SECRET-123"
USERNAME = "secret-user@example.com"

LOGIN_HTML = """<html><body>
<form id="login" method="post" action="/api/login" onsubmit="event.preventDefault();
 fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},
 body:JSON.stringify({email:this.email.value,password:this.password.value})})
 .then(() => { localStorage.setItem('sentinel_token','SNT-TOKEN');
               location.href='/dashboard'; }); return false;">
<input type="email" name="email"><input type="password" name="password">
<button type="submit">Sign in</button></form></body></html>"""

DASH_HTML = """<html><body>
<button id="noop" onclick="fetch('/api/noop',{method:'POST',
 headers:{'content-type':'application/json'},body:JSON.stringify({q:'x'})})">Send</button>
<script>fetch('/api/me',{headers:{'X-Token':localStorage.getItem('sentinel_token')||''}});
</script></body></html>"""

HANG_HTML = """<html><body>
<a href="/hang2">Next</a>
<button id="hang" onclick="fetch('/api/hang')">Wait</button>
<button id="ok" onclick="fetch('/api/ok')">Load</button>
</body></html>"""


@dataclass
class ServerLog:
    """Sahte sunucuya ULAŞAN istekler (yalnız method/path/gövde tutulur)."""

    calls: list[tuple[str, str, str]] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)


def _count(log: ServerLog, method: str, path: str) -> int:
    return sum(1 for m, p, _ in log.calls if m == method and p == path)


@pytest_asyncio.fixture
async def browser() -> Browser:
    async with async_playwright() as pw:
        launched = await pw.chromium.launch()
        yield launched
        await launched.close()


@pytest_asyncio.fixture
async def context(browser: Browser) -> BrowserContext:
    opened = await browser.new_context()
    yield opened
    await opened.close()


async def _install(context: BrowserContext, log: ServerLog, *, hang: bool = False) -> None:
    async def _handle(route) -> None:
        request = route.request
        path = urlsplit(request.url).path
        log.calls.append((request.method.upper(), path, request.post_data or ""))
        if path == "/api/login":
            await context.add_cookies([
                {"name": "sentinel_session", "value": "ok", "domain": HOST, "path": "/"}])
            await route.fulfill(status=200, content_type="application/json", body='{"ok":true}')
        elif path == "/api/me":
            log.tokens.append(request.headers.get("x-token", ""))
            await route.fulfill(status=200, content_type="application/json", body='{"id":"u-1"}')
        elif path == "/dashboard":
            logged_in = "sentinel_session=ok" in request.headers.get("cookie", "")
            await route.fulfill(status=200, content_type="text/html",
                                body=DASH_HTML if logged_in else "<html><body></body></html>")
        elif path == "/login":
            await route.fulfill(status=200, content_type="text/html", body=LOGIN_HTML)
        elif hang and path == "/api/hang":
            await asyncio.Event().wait()   # asla yanıt vermez: asılı kalan fetch
        elif hang and path == "/api/slow":
            await asyncio.sleep(3)
            await route.fulfill(status=200, content_type="application/json", body="{}")
        elif path.startswith("/api/"):
            await route.fulfill(status=200, content_type="application/json", body="{}")
        else:
            await route.fulfill(status=200, content_type="text/html", body=HANG_HTML if hang else "")

    await context.route(f"{ORIGIN}/**", _handle)


def _crawler(context: BrowserContext, **kwargs: object) -> BrowserCrawler:
    scope = Scope(allowed_hosts=[HOST], allowed_ports=[80], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"])
    policy = PolicyEngine(scope)
    return BrowserCrawler(policy, SafeActionPolicy(policy), context=context,
                          settle_ms=120, timeout_ms=2_000, **kwargs)  # type: ignore[arg-type]


def _login(**overrides: object) -> BrowserLogin:
    values: dict[str, object] = {
        "url": "/login",
        "username_selector": 'input[name="email"]',
        "password_selector": 'input[name="password"]',
        "submit_selector": 'button[type="submit"]',
        "success_url_contains": "/dashboard",
        "timeout_ms": 1_500,
        "credentials": {"username": USERNAME, "password": PASSWORD},
    }
    values.update(overrides)
    return BrowserLogin(**values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_real_login_captures_authenticated_api_and_blocks_later_writes(context, capsys):
    log = ServerLog()
    await _install(context, log)
    result = await _crawler(context).crawl(
        f"{ORIGIN}/dashboard", role="user_A", login=_login())

    assert result.login_succeeded is True
    assert _count(log, "POST", "/api/login") == 1   # tek istisna: login formu GÖNDERİLDİ
    captured = {(c.method, urlsplit(c.url).path): c for c in result.calls}
    me = captured[("GET", "/api/me")]
    assert me.status == 200 and log.tokens and all(t == "SNT-TOKEN" for t in log.tokens)
    # Gezinti sırasındaki diğer POST'lar kapıda kesilir — sahte sunucuya hiç ulaşmaz.
    assert _count(log, "POST", "/api/noop") == 0
    assert any(c.aborted and urlsplit(c.url).path == "/api/noop" for c in result.calls)
    out = capsys.readouterr().out
    assert PASSWORD not in out and USERNAME not in out


@pytest.mark.asyncio
async def test_without_login_dashboard_data_is_not_captured(context):
    log = ServerLog()
    await _install(context, log)
    result = await _crawler(context).crawl(f"{ORIGIN}/dashboard", role="user_A")
    assert result.login_succeeded is None
    assert not any(urlsplit(c.url).path == "/api/me" for c in result.calls)
    assert _count(log, "POST", "/api/login") == 0


@pytest.mark.asyncio
async def test_bad_selector_warns_but_crawl_continues(context, capsys):
    log = ServerLog()
    await _install(context, log)
    result = await _crawler(context).crawl(
        f"{ORIGIN}/dashboard", role="user_A",
        login=_login(username_selector="#yok-boyle-bir-alan", timeout_ms=700))

    assert result.login_succeeded is False
    assert result.pages_visited >= 1
    assert _count(log, "POST", "/api/login") == 0
    out = capsys.readouterr().out
    assert "UYARI" in out and PASSWORD not in out and USERNAME not in out


@pytest.mark.asyncio
async def test_hanging_fetch_and_tiny_time_budget_do_not_kill_crawl(context):
    log = ServerLog()
    await _install(context, log, hang=True)
    result = await _crawler(context).crawl(f"{ORIGIN}/hang")
    keys = {(c.method, urlsplit(c.url).path) for c in result.calls}
    assert ("GET", "/api/ok") in keys       # asılı buton yüzünden diğer uç KAYBOLMADI
    assert result.pages_visited >= 2   # asılı istek yüzünden sonraki sayfa da gezildi

    truncated = await _crawler(context, max_crawl_seconds=0.01).crawl(f"{ORIGIN}/hang")
    assert truncated.truncated is True


@pytest.mark.asyncio
async def test_closed_page_is_replaced_and_crawl_continues(context, monkeypatch):
    log = ServerLog()
    await _install(context, log, hang=True)

    async def _close_page(self, page, *args: object, **kwargs: object) -> None:
        await page.close()

    monkeypatch.setattr(BrowserCrawler, "_click_actions", _close_page)
    result = await _crawler(context).crawl(f"{ORIGIN}/hang")
    assert result.pages_visited == 2   # ilk sayfa kapandı → YENİ sayfa açılıp /hang2 gezildi


def test_failed_login_actor_is_not_added_to_visibility():
    from pentestai.recon.browser import CapturedCall, TrafficToEndpoints
    from pentestai.recon.browser.crawler import CrawlResult

    converter = TrafficToEndpoints([HOST])
    crawl = CrawlResult(login_succeeded=False, calls=[CapturedCall(
        method="GET", url=f"{ORIGIN}/api/public", status=200,
        content_type="application/json")])
    result = BrowserDiscoveryResult()
    endpoints: dict[tuple[str, str], object] = {}
    BrowserDiscovery._absorb(crawl, "user_A", converter, endpoints, {}, result,
                             actor_name="user_A")
    assert result.visibility.roles() == []      # başarısız aktör ANONİM sayılmaz
    assert ("GET", "/api/public") in endpoints


def test_login_credentials_never_appear_in_repr_or_config_error():
    login = _login()
    assert PASSWORD not in repr(login) and USERNAME not in repr(login)
    assert PASSWORD not in json.dumps(login.model_dump())
    with pytest.raises(ValueError) as exc:
        BrowserLogin.from_config({"url": "/login"}, {"email": USERNAME})
    assert PASSWORD not in str(exc.value) and USERNAME not in str(exc.value)


SPA_LOGIN_HTML = """<html><body><div id="app">
<input type="email" name="email"><input type="password" name="password">
<button type="submit" onclick="fetch('/api/session',{method:'POST',
 headers:{'content-type':'application/json'},
 body:JSON.stringify({email:document.querySelector('[name=email]').value})})
 .then(() => { location.href='/dashboard'; });">Sign in</button></div></body></html>"""


@pytest.mark.asyncio
async def test_spa_login_without_form_action_under_discovery_prefix(context):
    """Canlı crAPI deseni: login sayfası yalnız `discovery_path_prefixes` altında (test scope'u
    `/api/`), formda action yok, giriş JS ile bir API ucuna POST edilir. Login GET'leri keşif
    kapısından, API POST'u (aktörün `login_url`'i) auth kapısından geçmeli; başka POST geçmemeli."""
    log = ServerLog()

    async def _handle(route) -> None:
        request = route.request
        path = urlsplit(request.url).path
        log.calls.append((request.method.upper(), path, request.post_data or ""))
        if path == "/api/session":
            await context.add_cookies([
                {"name": "sentinel_session", "value": "ok", "domain": HOST, "path": "/"}])
            await route.fulfill(status=200, content_type="application/json", body='{"ok":true}')
        elif path == "/api/me":
            await route.fulfill(status=200, content_type="application/json", body='{"id":"u-1"}')
        elif path == "/dashboard":
            logged_in = "sentinel_session=ok" in request.headers.get("cookie", "")
            await route.fulfill(status=200, content_type="text/html",
                                body=DASH_HTML if logged_in else "<html><body></body></html>")
        elif path == "/login":
            await route.fulfill(status=200, content_type="text/html", body=SPA_LOGIN_HTML)
        else:
            await route.fulfill(status=200, content_type="application/json", body="{}")

    await context.route(f"{ORIGIN}/**", _handle)
    scope = Scope(allowed_hosts=[HOST], allowed_ports=[80], allowed_path_prefixes=["/api/"],
                  discovery_path_prefixes=["/"], allowed_methods=["GET", "HEAD"])
    policy = PolicyEngine(scope)
    crawler = BrowserCrawler(policy, SafeActionPolicy(policy), context=context,
                             settle_ms=120, timeout_ms=2_000)
    result = await crawler.crawl(
        f"{ORIGIN}/dashboard", role="user_A",
        login=_login(api_login_url="/api/session"))

    assert result.login_succeeded is True
    assert _count(log, "GET", "/login") >= 1        # login sayfası keşif önekinden açıldı
    assert _count(log, "POST", "/api/session") == 1  # yalnız login API POST'u gönderildi
    assert _count(log, "POST", "/api/noop") == 0     # gezinti sırasındaki POST yine kesildi
    assert any(urlsplit(c.url).path == "/api/me" and c.status == 200 for c in result.calls)
