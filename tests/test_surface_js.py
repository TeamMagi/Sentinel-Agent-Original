"""Faz 1 / T3 — JS bundle → genel envanter kaynağı. Ağsız."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Scope
from pentestai.net import SessionStore
from pentestai.recon.js_bundle import JsBundleRecon
from pentestai.recon.surface import JsBundleSource, SurfaceContext, default_sources
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
INDEX = ('<html><script src="/main.js"></script><script src="//evil.example/x.js"></script>'
         '<script src="http://other.example/y.js"></script></html>')
BUNDLE = r'''
fetch("/identity/api/auth/login", {method: "POST", body: x});
this.http.get(`${this.base}/community/api/v2/community/posts/recent`);
http.get("/rest/products/search");
axios.get(`/api/users/${id}/profile`);
http.get("/api/orders/" + orderId);
var a = "/workshop/api/shop/products", b = "//cdn.example/api/leak", c = "/api/logo.png";
var route = "/admin/dashboard-fake";
var junk = "/api/ghost";
var plain = ["/api/never-called/${x}"];
'''
LIVE = {"/identity/api/auth/login", "/community/api/v2/community/posts/recent",
        "/rest/products/search", "/workshop/api/shop/products"}


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


async def _run(handler, known=None):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session, known=list(known or []))
        return await JsBundleSource().discover(ctx)
    finally:
        await store.aclose_all()


def _site(seen=None):
    def handler(request):
        if seen is not None:
            seen.append((request.method, str(request.url)))
        p = request.url.path
        if p == "/":
            return httpx.Response(200, text=INDEX)
        if p == "/main.js":
            return httpx.Response(200, text=BUNDLE)
        if p in LIVE:
            return httpx.Response(200, json={"ok": True, "items": list(range(30))})
        return httpx.Response(404, json={"error": "nf"})
    return handler


@pytest.mark.asyncio
async def test_positive_extracts_prefixed_and_microservice_paths():
    eps = {(e.method, e.path_template): e for e in await _run(_site())}
    assert ("POST", "/identity/api/auth/login") in eps          # fetch POST → method POST
    assert ("GET", "/community/api/v2/community/posts/recent") in eps
    assert ("GET", "/rest/products/search") in eps
    assert ("GET", "/workshop/api/shop/products") in eps
    assert ("GET", "/api/users/{id}/profile") in eps            # ${id} → {id}
    assert ("GET", "/api/orders/{id}") in eps                   # "/api/orders/" + id
    assert eps[("GET", "/api/orders/{id}")].id_param == "id"


@pytest.mark.asyncio
async def test_unverified_and_static_candidates_are_dropped():
    paths = {e.path_template for e in await _run(_site())}
    assert "/api/ghost" not in paths             # GET probe 404 → alınmaz
    assert "/admin/dashboard-fake" not in paths
    assert not any("logo.png" in p for p in paths)
    assert not any("cdn.example" in p or "leak" in p for p in paths)
    assert "/api/never-called/{id}" not in paths  # çağrı bağlamı yok + id'li → alınmaz


@pytest.mark.asyncio
async def test_catch_all_spa_invents_no_parameterless_get():
    spa = "<html><body>" + "x" * 400 + "</body></html>"

    def handler(request):
        if request.url.path == "/main.js":
            return httpx.Response(200, text=BUNDLE)
        if request.url.path == "/":
            return httpx.Response(200, text=INDEX.replace("</html>", "x" * 400 + "</html>"))
        return httpx.Response(200, text=spa)

    eps = {(e.method, e.path_template) for e in await _run(handler)}
    assert ("GET", "/rest/products/search") not in eps
    assert ("GET", "/workshop/api/shop/products") not in eps
    assert ("POST", "/identity/api/auth/login") in eps   # çağrı bağlamlı yazma methodu taşınır


@pytest.mark.asyncio
async def test_other_origin_scripts_are_never_fetched_and_only_safe_methods_sent():
    seen: list[tuple[str, str]] = []
    await _run(_site(seen))
    assert seen and {m for m, _ in seen} <= {"GET", "HEAD", "OPTIONS"}
    assert not any("evil.example" in u or "other.example" in u for _, u in seen)
    # yazma methodlu aday probe edilmedi
    assert not any(u.endswith("/identity/api/auth/login") for _, u in seen)


@pytest.mark.asyncio
async def test_known_endpoints_are_not_reprobed():
    from pentestai.models import Endpoint
    seen: list[tuple[str, str]] = []
    await _run(_site(seen), known=[Endpoint(method="GET", path_template="/rest/products/search")])
    assert not any(u.endswith("/rest/products/search") for _, u in seen)


def test_default_sources_order_js_before_sourcemap():
    assert [s.name for s in default_sources()].index("js") < [s.name for s in default_sources()].index("sourcemap")
    assert [s.name for s in default_sources()].index("robots") < [
        s.name for s in default_sources()].index("js")


def test_client_side_recon_regex_unchanged_for_microservice_prefix():
    js = 'a("/identity/api/auth/login"); b("/api/x"); c("/admin/users");'
    paths = {p for p, _ in JsBundleRecon.extract_api_paths(js)}
    assert paths == {"/api/x", "/admin/users"}          # oracle regex'i genişlemedi


@pytest.mark.asyncio
async def test_js_bundle_recon_discover_old_behavior_kept():
    js = ('http.get("/api/public");' + " " * 400
          + 'if (user.isAdmin) { http.get("/api/admin/users"); }')

    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text='<script src="/a.js"></script>')
        if request.url.path == "/a.js":
            return httpx.Response(200, text=js)
        return httpx.Response(404)

    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        got = await JsBundleRecon(scanner.replayer, BASE).discover(session)
    finally:
        await store.aclose_all()
    assert [g.endpoint.path_template for g in got] == ["/api/admin/users"]


# --- göreli sabitler + servis önekleri (crAPI benzeri) ---
REL_BUNDLE = '''
var og="identity/",ig="workshop/",ag="chatbot/",lg="community/",
sg={LOGIN:"api/auth/login",GET_VEHICLES:"api/v2/vehicle/vehicles",
GET_VIDEO:"api/v2/user/videos/<videoId>",MECH:"api/mechanic",
MECH_ONE:"api/mechanic/<mid>",GHOST:"api/ghost/thing",LONELY:"api/lonely/<x>",
STATIC:"api/x/logo.png"};
'''
REL_INDEX = '<html><script src="/m.js"></script></html>'


def _rel_site(seen=None, catch_all=False):
    spa = "<html><body>" + "x" * 400 + "</body></html>"

    def handler(request):
        if seen is not None:
            seen.append((request.method, request.url.path))
        p = request.url.path
        if p == "/":
            return httpx.Response(200, text=REL_INDEX + ("x" * 400 if catch_all else ""))
        if p == "/m.js":
            return httpx.Response(200, text=REL_BUNDLE)
        if catch_all:
            return httpx.Response(200, text=spa)
        if p == "/identity/api/auth/login":
            return httpx.Response(405, json={"error": "method"})
        if p == "/workshop/api/mechanic":
            return httpx.Response(200, json={"mechanics": list(range(30))})
        if p == "/identity/api/v2/user/dashboard":
            return httpx.Response(200, json={"ok": 1})
        if p == "/identity/api/v2/vehicle/vehicles":
            return httpx.Response(200, json={"v": list(range(30))})
        return httpx.Response(404, json={})
    return handler


@pytest.mark.asyncio
async def test_relative_constants_resolved_with_service_prefixes():
    eps = {(e.method, e.path_template) for e in await _run(_rel_site())}
    assert ("POST", "/identity/api/auth/login") in eps      # GET→405 (Allow yok) → POST
    assert ("GET", "/workshop/api/mechanic") in eps
    assert ("GET", "/identity/api/v2/vehicle/vehicles") in eps
    assert ("GET", "/workshop/api/mechanic/{id}") in eps    # kardeşin önekiyle
    # yanlış önek kombinasyonları ve doğrulanamayanlar alınmaz
    assert not any(p.startswith(("/chatbot/", "/community/")) for _, p in eps)
    assert ("GET", "/api/auth/login") not in eps
    assert not any("ghost" in p or "logo.png" in p for _, p in eps)


@pytest.mark.asyncio
async def test_relative_angle_param_normalized_only_with_verified_sibling():
    eps = {e.path_template for e in await _run(_rel_site())}
    assert "/workshop/api/mechanic/{id}" in eps
    assert not any(p.endswith("/videos/{id}") for p in eps)   # kardeş doğrulanamadı (user/...)
    assert not any("lonely" in p for p in eps)                # kardeşsiz → alınmaz


@pytest.mark.asyncio
async def test_catch_all_spa_takes_no_relative_candidate():
    eps = await _run(_rel_site(catch_all=True))
    assert eps == []


@pytest.mark.asyncio
async def test_relative_discovery_sends_only_safe_methods_and_respects_cap():
    seen: list[tuple[str, str]] = []
    await _run(_rel_site(seen))
    assert {m for m, _ in seen} <= {"GET", "HEAD", "OPTIONS"}
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_rel_site()))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session)
        src = JsBundleSource(max_requests=2)
        await src.discover(ctx)
        assert src._used <= 2
    finally:
        await store.aclose_all()


def test_extract_relative_and_angle_params_pure():
    rel = {(m, p) for m, p, _ in JsBundleSource.extract_relative(REL_BUNDLE)}
    assert ("GET", "api/v2/user/videos/{id}") in rel
    assert ("GET", "api/auth/login") in rel
    assert JsBundleSource.extract_prefixes(REL_BUNDLE) == [
        "identity", "workshop", "chatbot", "community"]
    absolute = {p for _, p, _ in JsBundleSource.extract_inventory('x("/api/videos/<videoId>")')}
    assert absolute == {"/api/videos/{id}"}


@pytest.mark.asyncio
async def test_405_resolves_real_methods_from_allow_header():
    bundle = 'var og="identity/";s={A:"api/auth/login",B:"api/auth/signup",C:"api/auth/ok"};'

    def handler(request):
        p = request.url.path
        if p == "/":
            return httpx.Response(200, text='<script src="/m.js"></script>')
        if p == "/m.js":
            return httpx.Response(200, text=bundle)
        if p == "/identity/api/auth/login":
            return httpx.Response(405, headers={"Allow": "POST, PUT, OPTIONS"}, json={})
        if p == "/identity/api/auth/signup":
            return httpx.Response(405, json={})
        if p == "/identity/api/auth/ok":
            return httpx.Response(200, json={"items": list(range(30))})
        return httpx.Response(404, json={})

    eps = {(e.method, e.path_template) for e in await _run(handler)}
    assert ("POST", "/identity/api/auth/login") in eps
    assert ("PUT", "/identity/api/auth/login") in eps
    assert ("GET", "/identity/api/auth/login") not in eps
    assert ("POST", "/identity/api/auth/signup") in eps      # Allow yok → POST
    assert ("GET", "/identity/api/auth/ok") in eps           # 200 → GET kalır
