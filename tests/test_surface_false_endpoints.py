"""Faz 1 / T10 — yanlış uç düzeltmeleri: parametreli route'a düşen türevler, yol yansıtan hata
sayfaları, SPA kabuğu, keşif istek tavanı ve scope önek uyarısı. Ağsız."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, NormalizedResponse, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import (
    JsBundleSource,
    SmartWordlistSource,
    SurfaceContext,
    SurfaceDiscovery,
    SurfaceSource,
    derive_request_cap,
    probe,
    scope_prefix_warning,
)
from pentestai.recon.surface.base import param_route_match, same_template
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _scope(prefixes=("/",)) -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                 allowed_path_prefixes=list(prefixes),
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


async def _run(handler, known, source=None):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session, known=list(known))
        return await (source or SmartWordlistSource()).discover(ctx)
    finally:
        await store.aclose_all()


def _known(*paths):
    return [Endpoint(method="GET", path_template=p) for p in paths]


def _paths(eps):
    return {e.path_template for e in eps}


def _param_route_site(extra=None):
    """`/api/v2/videos/{video_id}`: sayısal olmayan her değere 400 + değeri yansıtan JSON (uzunluk
    değere göre değişir); sayısal değere 404. `extra`: gerçek ayrı route'lar."""
    extra = extra or {}

    def handler(request):
        path = request.url.path
        if path in extra:
            return extra[path]
        if path == "/api/v2/videos":
            return httpx.Response(200, json={"videos": []})
        if path.startswith("/api/v2/videos/"):
            value = path.rsplit("/", 1)[-1]
            if value.isdigit():
                return httpx.Response(404, json={"message": "Video not found.", "status": 404})
            return httpx.Response(400, json={
                "type": "about:blank", "title": "Bad Request", "status": 400,
                "detail": f"Failed to convert '{value}' to type Long: " + "x" * len(value) * 3,
                "instance": path})
        return httpx.Response(404, text="Not Found")
    return handler


@pytest.mark.asyncio
async def test_derivative_falling_into_param_route_is_not_taken():
    known = _known("/api/v2/videos", "/api/v2/videos/{id}")
    got = _paths(await _run(_param_route_site(), known))
    assert not {p for p in got if p.startswith("/api/v2/videos/")}


@pytest.mark.asyncio
async def test_param_route_without_known_template_caught_by_shape():
    """`{id}` şablonu bilinmese bile 400 JSON şekli rastgele-kelime baseline'ıyla aynıdır."""
    known = _known("/api/v2/videos")
    got = _paths(await _run(_param_route_site(), known))
    assert not {p for p in got if p.startswith("/api/v2/videos/")}


@pytest.mark.asyncio
async def test_real_separate_route_under_collection_is_taken():
    extra = {"/api/v2/videos/export": httpx.Response(200, json={"file": "a.csv", "rows": 3})}
    # `{id}` şablonu bilinmiyor: yalnız yanıt şekli farkı (200 + farklı anahtarlar) kanıt
    got = _paths(await _run(_param_route_site(extra), _known("/api/v2/videos")))
    assert "/api/v2/videos/export" in got


@pytest.mark.asyncio
async def test_known_param_sibling_blocks_single_segment_derivative():
    """VAmPI deseni: `/users/v1/{username}` bilinirken `/users/v1/admin` (200, kayıt var) ayrı uç
    değil, parametre değeridir."""
    def handler(request):
        path = request.url.path
        if path == "/users/v1/admin":
            return httpx.Response(200, json={"username": "admin", "email": "a@x"})
        if path == "/users/v1":
            return httpx.Response(200, json={"users": [{"username": "admin"}]})
        if path.startswith("/users/v1/"):
            return httpx.Response(404, json={"status": "fail", "message": "User not found"})
        return httpx.Response(404, text="nf")
    known = _known("/users/v1", "/users/v1/{username}")
    got = _paths(await _run(handler, known))
    assert "/users/v1/admin" not in got


@pytest.mark.asyncio
async def test_path_echoing_error_page_is_not_endpoint():
    """Express tarzı 500 'Unexpected path: <yol>' sayfası yola göre uzar; baseline'dan >48
    bayt farklı olsa da aynı şablondur."""
    def handler(request):
        p = request.url.path
        if p == "/rest/user":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(500, text="<html><title>Error: Unexpected path: "
                              + p + "</title>" + "pad" * 300 + p * 6 + "</html>")
    got = _paths(await _run(handler, _known("/rest/user", "/rest/languages")))
    assert got == set()


@pytest.mark.asyncio
async def test_spa_shell_fallback_not_taken():
    shell = "<html>" + "app " * 500 + "</html>"

    def handler(request):
        p = request.url.path
        if p.startswith("/rest/"):
            return httpx.Response(404, text="nf")
        return httpx.Response(200, text=shell)   # kök + her kök-dışı yol aynı kabuk
    got = _paths(await _run(handler, _known("/rest/products", "/rest/products/{id}")))
    assert got == set()


def test_param_route_match_helper():
    known = _known("/users/v1/{username}", "/a/b")
    assert param_route_match("/users/v1/admin", known) == "/users/v1/{username}"
    assert param_route_match("/users/v2/admin", known) is None
    assert param_route_match("/users/v1/admin/x", known) is None


def test_same_template_json_keys_and_echo():
    def resp(status, body):
        return NormalizedResponse(status=status, headers={}, body_text=body, body_normalized=body)
    a = resp(400, '{"detail": "a", "status": 400}')
    b = resp(400, '{"detail": "' + "z" * 200 + '", "status": 400}')
    assert same_template(a, "/p/me", b, "/p/zzzz")
    assert not same_template(a, "/p/me", resp(400, '{"other": 1}'), "/p/zzzz")
    assert not same_template(a, "/p/me", resp(200, a.body_text), "/p/zzzz")


@pytest.mark.asyncio
async def test_js_get_on_id_path_with_405_becomes_real_method():
    bundle = "this.http.get(`/community/api/posts/${id}/comment`);"

    def handler(request):
        p = request.url.path
        if p == "/":
            return httpx.Response(200, text='<script src="/main.js"></script>')
        if p == "/main.js":
            return httpx.Response(200, text=bundle)
        if p == "/community/api/posts/1/comment":
            return httpx.Response(405, headers={"Allow": "POST"}, text="")
        return httpx.Response(404, text="nf")
    got = {(e.method, e.path_template) for e in await _run(handler, [], JsBundleSource())}
    assert ("POST", "/community/api/posts/{id}/comment") in got
    assert ("GET", "/community/api/posts/{id}/comment") not in got


# ---- keşif istek tavanı ----
class _ProbeSource(SurfaceSource):
    def __init__(self, name: str, n: int) -> None:
        self.name = name
        self.n = n

    async def discover(self, ctx):
        for i in range(self.n):
            await probe(ctx, f"/{self.name}/{i}")
        return [Endpoint(method="GET", path_template=f"/{self.name}")]


@pytest.mark.asyncio
async def test_discovery_cap_skips_remaining_sources(capsys):
    sent = []

    def handler(request):
        sent.append(request.url.path)
        return httpx.Response(404, text="nf")
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        disc = SurfaceDiscovery([_ProbeSource("a", 8), _ProbeSource("b", 8), _ProbeSource("c", 8)],
                                max_total_requests=10)
        found = await disc.run(scanner.replayer, BASE, session, [])
    finally:
        await store.aclose_all()
    assert len(sent) == 10                      # tavan mutlak: b yarıda kesilir
    assert disc.requests_used == 10
    assert [src for _, src in found] == ["a", "b"]   # c atlandı
    err = capsys.readouterr().err
    assert "[keşif]" in err and "tavan" in err and "c" in err


def test_derive_request_cap():
    assert derive_request_cap(2000) == 600          # %30 = 600
    assert derive_request_cap(1000) == 300
    assert derive_request_cap(10_000) == 600        # mutlak tavan
    assert derive_request_cap(10) == 20             # taban


def test_scanner_derives_discovery_cap_from_budget():
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_total_requests=500))
    assert scanner.surface_discovery.max_total_requests == 150


# ---- scope önek uyarısı ----
def test_scope_prefix_warning_when_root_missing():
    msg = scope_prefix_warning(_scope(("/identity/", "/workshop/")))
    assert msg is not None and msg.startswith("[keşif]") and "/identity/" in msg


def test_no_scope_warning_with_root_prefix():
    assert scope_prefix_warning(_scope(("/",))) is None
    assert scope_prefix_warning(_scope(("/api/", "/"))) is None


@pytest.mark.asyncio
async def test_discover_more_prints_warning_and_does_not_widen_scope(capsys):
    scope = _scope(("/api/",))
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda r: httpx.Response(404, text="nf")))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        await scanner.discover_more(session, [])
    finally:
        await store.aclose_all()
    assert "[keşif]" in capsys.readouterr().err
    assert scanner.scope.allowed_path_prefixes == ["/api/"]
