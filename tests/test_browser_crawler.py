"""T2 — BrowserCrawler: gerçek headless Chromium, sahte origin (context.route), ağ YOK.

`http://app.test.local` tamamen yerel route handler'larıyla sunulur; scope kapısı dışındaki
host'lara (evil.test) hiçbir istek ulaşmaz. Gerçek hedefe istek atılmaz.
"""
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import pytest
import pytest_asyncio
from playwright.async_api import async_playwright

from pentestai.models import AuthState, Scope
from pentestai.net.limits import BudgetExceeded, BudgetTracker
from pentestai.net.replay import ScopeError
from pentestai.policy import PolicyEngine
from pentestai.recon.browser import BrowserCrawler, SafeActionPolicy

ORIGIN = "http://app.test.local"
HOST = "app.test.local"
EVIL_URL = "http://evil.test/x"
CDN = "http://cdn.test.local"

SPA_HTML = """<html><body>
<a href="/#/products">Products</a>
<button id="load-orders" onclick="fetch('/api/orders/12')">Load orders</button>
<button id="delete-account" onclick="fetch('/api/users/1',{method:'DELETE'})">Delete account</button>
<button id="external" onclick="fetch('http://evil.test/x')">External</button>
<form id="feedback" method="post" action="/api/feedback"
      onsubmit="event.preventDefault(); fetch('/api/feedback',
        {method:'POST', headers:{'content-type':'application/json'},
         body:JSON.stringify({email:this.email.value, comment:this.comment.value})});">
  <input type="email" name="email"><textarea name="comment"></textarea>
  <button type="submit">Send</button>
</form>
<form id="search" method="post" action="/api/search"
      onsubmit="event.preventDefault(); fetch('/api/search',
        {method:'POST', headers:{'content-type':'application/json'},
         body:JSON.stringify({q:this.q.value})});">
  <input type="text" name="q"><button type="submit">Search</button>
</form>
<script>
function load() { if (location.hash === '#/products') fetch('/api/products'); }
window.addEventListener('hashchange', load); load();
</script>
</body></html>"""


@dataclass
class ServerLog:
    """Sahte sunucuya ULAŞAN istekler (method, path, ham gövde) ve başlıklar."""

    calls: list[tuple[str, str, str]] = field(default_factory=list)
    headers: list[dict[str, str]] = field(default_factory=list)


def _count(log: ServerLog, method: str, path: str) -> int:
    return sum(1 for m, p, _ in log.calls if m == method and p == path)


def _headers_for(log: ServerLog, path: str) -> list[dict[str, str]]:
    """Sahte sunucuya belirli yolda gelen isteklerin başlıklarını döndürür."""
    return [h for (_, p, _), h in zip(log.calls, log.headers, strict=False) if p == path]


async def _install_app(context, log: ServerLog, html: str = SPA_HTML) -> None:
    async def _handle(route) -> None:
        request = route.request
        path = urlsplit(request.url).path
        log.calls.append((request.method.upper(), path, request.post_data or ""))
        log.headers.append(dict(request.headers))
        if path.startswith("/api/"):
            await route.fulfill(
                status=200, content_type="application/json",
                body=json.dumps({"ok": True, "path": path}),
            )
        else:
            await route.fulfill(status=200, content_type="text/html", body=html)

    await context.route(f"{ORIGIN}/**", _handle)


def _crawler(context, *, hosts: list[str] | None = None, **kwargs: object) -> BrowserCrawler:
    scope = Scope(
        allowed_hosts=hosts if hosts is not None else [HOST],
        allowed_ports=[80],
        allowed_path_prefixes=["/api/"],
        discovery_path_prefixes=["/"],
        allowed_methods=["GET", "HEAD", "POST"],
        safe_write_paths=["/api/search"],
    )
    policy = PolicyEngine(scope)
    return BrowserCrawler(
        policy, SafeActionPolicy(policy), context=context,
        settle_ms=150, timeout_ms=3_000, **kwargs,  # type: ignore[arg-type]
    )


@pytest_asyncio.fixture
async def browser():
    async with async_playwright() as pw:
        launched = await pw.chromium.launch()
        yield launched
        await launched.close()


@pytest_asyncio.fixture
async def context(browser):
    opened = await browser.new_context()
    yield opened
    await opened.close()


@pytest.mark.asyncio
async def test_captures_api_calls_and_blocks_destructive_actions(context):
    log = ServerLog()
    await _install_app(context, log)
    evil_hits: list[str] = []

    async def _evil(route) -> None:
        evil_hits.append(route.request.url)
        await route.fulfill(status=200, content_type="application/json", body="{}")

    await context.route("http://evil.test/**", _evil)
    result = await _crawler(context).crawl(f"{ORIGIN}/", role="user_A")

    captured = {(c.method, urlsplit(c.url).path): c for c in result.calls}
    for key in (("GET", "/api/orders/12"), ("GET", "/api/products")):
        assert key in captured
        assert captured[key].status == 200
        assert captured[key].response_json is not None
        assert captured[key].role == "user_A"

    assert any("Delete account" in label for label in result.skipped_actions)
    assert _count(log, "DELETE", "/api/users/1") == 0
    assert _count(log, "POST", "/api/feedback") == 0

    blocked = [c for c in result.calls
               if c.aborted and urlsplit(c.url).path == "/api/feedback"]
    assert blocked and blocked[0].request_json is not None
    assert any(str(v).startswith("snt_") for v in blocked[0].request_json.values())
    assert any(method == "POST" and path.endswith("/api/feedback")
               for method, path, _ in result.blocked)

    assert _count(log, "POST", "/api/search") >= 1
    assert evil_hits == []
    assert any("evil.test" in url for _, url, _ in result.blocked)


@pytest.mark.asyncio
async def test_out_of_scope_start_url_raises_scope_error(context):
    with pytest.raises(ScopeError):
        await _crawler(context).crawl(EVIL_URL)


@pytest.mark.asyncio
async def test_dom_fingerprint_prevents_second_identical_page_expansion(context):
    html = """<html><body>
    <a href="/same2">Next</a>
    <button id="ping" onclick="fetch('/api/fingerprint')">Ping</button>
    </body></html>"""
    log = ServerLog()
    await _install_app(context, log, html)
    result = await _crawler(context, max_pages=2, max_depth=2).crawl(f"{ORIGIN}/same1")
    assert result.pages_visited == 2
    assert _count(log, "GET", "/api/fingerprint") == 1


@pytest.mark.asyncio
async def test_max_pages_marks_result_truncated(context):
    log = ServerLog()
    await _install_app(context, log)
    result = await _crawler(context, max_pages=1).crawl(f"{ORIGIN}/")
    assert result.pages_visited == 1
    assert result.truncated is True


@pytest.mark.asyncio
async def test_confirm_dialog_is_dismissed_never_accepted(context):
    html = """<html><body>
    <button id="check" onclick="if (confirm('Emin misiniz?'))
      fetch('/api/users/1',{method:'DELETE'})">Check</button>
    <button id="notify" onclick="alert('bilgi')">Notify</button>
    </body></html>"""
    log = ServerLog()
    await _install_app(context, log, html)
    result = await _crawler(context).crawl(f"{ORIGIN}/")
    assert result.pages_visited == 1
    assert _count(log, "DELETE", "/api/users/1") == 0


@pytest.mark.asyncio
async def test_local_storage_init_script_runs_only_on_target_origin(context):
    html = """<html><body><script>
    fetch('/api/me', {headers: {'X-Token': localStorage.getItem('sentinel_token') || ''}});
    </script></body></html>"""
    log = ServerLog()
    await _install_app(context, log, html)
    token = "SNT-LOCAL-123"
    await _crawler(context).crawl(
        f"{ORIGIN}/", local_storage={"sentinel_token": token})
    me_headers = _headers_for(log, "/api/me")
    assert me_headers and me_headers[0].get("x-token") == token


@pytest.mark.asyncio
async def test_auth_header_goes_only_to_target_host(context):
    html = f"""<html><body><script>
    fetch('/api/me'); fetch('{CDN}/api/ping');
    </script></body></html>"""
    log = ServerLog()
    await _install_app(context, log, html)
    cdn_log = ServerLog()

    async def _cdn(route) -> None:
        request = route.request
        cdn_log.calls.append(("GET", urlsplit(request.url).path, ""))
        cdn_log.headers.append(dict(request.headers))
        await route.fulfill(status=200, content_type="application/json", body="{}")

    await context.route(f"{CDN}/**", _cdn)
    auth = AuthState(headers={"Authorization": "Bearer VICTIM"},
                     cookies={"session": "abc"})
    await _crawler(context, hosts=[HOST, "cdn.test.local"]).crawl(
        f"{ORIGIN}/", role="user_A", auth=auth)

    me = _headers_for(log, "/api/me")
    ping = _headers_for(cdn_log, "/api/ping")
    assert me and me[0].get("authorization") == "Bearer VICTIM"
    assert "session=abc" in me[0].get("cookie", "")
    assert ping and ping[0].get("authorization") is None
    assert "cookie" not in ping[0]


@pytest.mark.asyncio
async def test_budget_exceeded_propagates_from_navigation_gate(context):
    await _install_app(context, ServerLog())
    crawler = _crawler(context, budget=BudgetTracker(max_total_requests=0))
    with pytest.raises(BudgetExceeded):
        await crawler.crawl(f"{ORIGIN}/")
