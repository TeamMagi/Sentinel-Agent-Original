"""Faz 1 / T1 — robots.txt / sitemap.xml / .well-known kaynağı. Ağsız."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import RobotsSitemapSource, SurfaceContext
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /gone/
Disallow: /*.json$
Disallow: /files/*/private
Allow: /api/v1/
Sitemap: http://localhost:3000/sitemap.xml
Sitemap: http://evil.example/sitemap.xml
"""
SITEMAP = """<?xml version="1.0"?><urlset>
<url><loc>http://localhost:3000/shop/items/42</loc></url>
<url><loc>http://other.example/leak</loc></url>
</urlset>"""
OIDC = ('{"issuer":"http://localhost:3000","token_endpoint":"http://localhost:3000/oauth/token",'
        '"jwks_uri":"http://localhost:3000/oauth/jwks","userinfo_endpoint":"http://idp.example/ui"}')
INDEX_1 = ("<sitemapindex><sitemap><loc>http://localhost:3000/s1.xml</loc></sitemap>"
           "</sitemapindex>")
INDEX_2 = ("<sitemapindex><sitemap><loc>http://localhost:3000/s2.xml</loc></sitemap>"
           "</sitemapindex>")


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


async def _run(handler):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        return await RobotsSitemapSource().discover(SurfaceContext(scanner.replayer, BASE, session))
    finally:
        await store.aclose_all()


def _site(methods=None):
    def handler(request):
        if methods is not None:
            methods.append(request.method)
        path = request.url.path
        if path == "/robots.txt":
            return httpx.Response(200, text=ROBOTS)
        if path == "/sitemap.xml":
            return httpx.Response(200, text=SITEMAP)
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, text=OIDC)
        if path == "/.well-known/security.txt":
            return httpx.Response(200, text="Contact: mailto:sec@example.com")
        if path in ("/admin/", "/api/v1/", "/shop/items/42", "/oauth/token", "/oauth/jwks"):
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={})   # /gone/ dahil
    return handler


@pytest.mark.asyncio
async def test_positive_target_finds_verified_same_origin_endpoints():
    eps = await _run(_site())
    paths = {e.path_template for e in eps}
    assert {"/admin/", "/api/v1/", "/shop/items/{id}", "/oauth/token", "/oauth/jwks",
            "/.well-known/openid-configuration", "/.well-known/security.txt"} <= paths
    assert "/gone/" not in paths                    # 404 → alınmaz
    assert not any("leak" in p or "files" in p or p.endswith(".json") for p in paths)
    assert "/ui" not in paths                       # başka origin referansı
    item = next(e for e in eps if e.path_template == "/shop/items/{id}")
    assert item.id_type == "integer"


@pytest.mark.asyncio
async def test_catch_all_spa_yields_no_endpoints():
    spa = "<html><body>" + "x" * 400 + "</body></html>"
    eps = await _run(lambda request: httpx.Response(200, text=spa))
    assert eps == []


@pytest.mark.asyncio
async def test_out_of_origin_urls_are_never_requested():
    hosts = []
    inner = _site()

    def handler(request):
        hosts.append(request.url.host)
        return inner(request)

    await _run(handler)
    assert set(hosts) == {"localhost"}


@pytest.mark.asyncio
async def test_only_safe_methods_are_sent():
    methods: list[str] = []
    await _run(_site(methods))
    assert methods and set(methods) <= {"GET", "HEAD", "OPTIONS"}


@pytest.mark.asyncio
async def test_sitemap_index_is_followed_one_level_only():
    asked = []

    def handler(request):
        asked.append(request.url.path)
        p = request.url.path
        if p == "/sitemap.xml":
            return httpx.Response(200, text=INDEX_1)
        if p == "/s1.xml":
            return httpx.Response(200, text=INDEX_2)
        return httpx.Response(404, json={})

    await _run(handler)
    assert "/s1.xml" in asked and "/s2.xml" not in asked


@pytest.mark.asyncio
async def test_scanner_discover_more_registers_robots_source():
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_site()))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        extra, _ = await scanner.discover_more(session, [])
    finally:
        await store.aclose_all()
    assert any(e.path_template == "/admin/" for e in extra)
    assert "robots" in scanner.surface_sources[("GET", "/admin/")]
