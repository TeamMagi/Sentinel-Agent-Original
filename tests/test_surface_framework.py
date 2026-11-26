"""Faz 1 / T6 — framework parmak izi + bilinen yollar (`FrameworkSource`). Ağsız."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, NormalizedResponse, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import (
    FrameworkFingerprinter,
    FrameworkSource,
    SurfaceContext,
    default_sources,
)
from pentestai.recon.surface.framework import SpringMappingsParser
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


async def _run(handler, known=None):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session, known=list(known or []))
        eps = await FrameworkSource().discover(ctx)
        return eps, ctx
    finally:
        await store.aclose_all()


def _site(pages, not_found, seen=None):
    def handler(request):
        if seen is not None:
            seen.append((request.method, request.url.path))
        resp = pages.get(request.url.path)
        return resp if resp is not None else not_found
    return handler


def _paths(eps):
    return {(e.method, e.path_template) for e in eps}


JSON_BODY = {"ok": True, "items": list(range(30))}

MAPPINGS = {"contexts": {"application": {"mappings": {"dispatcherServlets": {"dispatcherServlet": [
    {"handler": "x", "predicate": "{GET [/api/users/{id}]}", "details": {
        "requestMappingConditions": {"methods": ["GET"], "patterns": ["/api/users/{id}"]}}},
    {"handler": "y", "predicate": "{POST [/api/users]}", "details": {
        "requestMappingConditions": {"methods": ["POST"], "patterns": ["/api/users"]}}},
    {"handler": "z", "predicate": "{[/webjars/**]}", "details": {
        "requestMappingConditions": {"methods": [], "patterns": ["/webjars/**"]}}},
]}}}}}


@pytest.mark.asyncio
async def test_spring_detected_actuator_and_mappings_route_table():
    pages = {
        "/actuator": httpx.Response(200, json={"_links": {"self": {"href": "x"}}, **JSON_BODY}),
        "/actuator/health": httpx.Response(200, json={"status": "UP", "components": {}}),
        "/actuator/mappings": httpx.Response(200, json=MAPPINGS),
    }
    nf = httpx.Response(404, text="<html><h1>Whitelabel Error Page</h1></html>")
    eps, ctx = await _run(_site(pages, nf))
    got = _paths(eps)
    assert {("GET", "/actuator"), ("GET", "/actuator/health"), ("GET", "/actuator/mappings")} <= got
    assert ("GET", "/api/users/{id}") in got and ("POST", "/api/users") in got
    assert not any("webjars" in p or "env" in p for _, p in got)
    users = next(e for e in eps if e.path_template == "/api/users/{id}")
    assert users.id_param == "id"
    assert ctx.frameworks == {"spring"}


@pytest.mark.asyncio
async def test_django_detected_via_404_page_and_cookie():
    pages = {"/": httpx.Response(200, text="<html>hi</html>",
                                 headers={"set-cookie": "csrftoken=abc; Path=/"}),
             "/admin/": httpx.Response(302, headers={"location": "/admin/login/"}),
             "/api/": httpx.Response(200, json=JSON_BODY)}
    nf = httpx.Response(404, text="Page not found (404)\nUsing the URLconf defined in app.urls")
    eps, ctx = await _run(_site(pages, nf))
    assert {("GET", "/admin/"), ("GET", "/api/")} <= _paths(eps)
    assert "django" in ctx.frameworks


@pytest.mark.asyncio
async def test_express_detected_via_cannot_get_and_header():
    pages = {"/health": httpx.Response(200, json={"status": "ok", "uptime": 123456789}),
             "/api": httpx.Response(200, json=JSON_BODY)}
    nf = httpx.Response(404, text="<pre>Cannot GET /x</pre>", headers={"x-powered-by": "Express"})
    eps, ctx = await _run(_site(pages, nf))
    assert {("GET", "/health"), ("GET", "/api")} <= _paths(eps)
    assert ctx.frameworks == {"express"}


@pytest.mark.asyncio
async def test_nextjs_build_id_data_path_and_auth():
    html = ('<html><script id="__NEXT_DATA__" type="application/json">'
            '{"buildId":"AbC123xyz","page":"/"}</script></html>')
    pages = {"/": httpx.Response(200, text=html),
             "/api/auth/session": httpx.Response(200, json={"user": None, "pad": "x" * 80}),
             "/_next/data/AbC123xyz/index.json": httpx.Response(200, json={"pageProps": JSON_BODY})}
    nf = httpx.Response(404, text="not found")
    eps, ctx = await _run(_site(pages, nf))
    got = _paths(eps)
    assert ("GET", "/api/auth/session") in got
    assert ("GET", "/_next/data/AbC123xyz/index.json") in got
    assert "nextjs" in ctx.frameworks


@pytest.mark.asyncio
async def test_laravel_detected_via_session_cookie():
    pages = {"/": httpx.Response(200, text="welcome", headers={
                 "set-cookie": "laravel_session=eyJ; path=/; httponly"}),
             "/api/user": httpx.Response(401, json={"message": "Unauthenticated."}),
             "/sanctum/csrf-cookie": httpx.Response(204)}
    nf = httpx.Response(404, text="nf")
    eps, ctx = await _run(_site(pages, nf))
    assert ("GET", "/api/user") in _paths(eps)
    assert "laravel" in ctx.frameworks


@pytest.mark.asyncio
async def test_fastapi_detected_via_detail_not_found():
    pages = {"/docs": httpx.Response(200, text="<html>" + "swagger" * 30 + "</html>"),
             "/openapi.json": httpx.Response(200, json={"openapi": "3.0.0", "paths": {}})}
    nf = httpx.Response(404, json={"detail": "Not Found"})
    eps, ctx = await _run(_site(pages, nf))
    assert {("GET", "/docs"), ("GET", "/openapi.json")} <= _paths(eps)
    assert "fastapi" in ctx.frameworks


@pytest.mark.asyncio
async def test_no_framework_means_zero_known_path_probes():
    seen: list = []
    eps, ctx = await _run(_site({}, httpx.Response(404, text="nope"), seen))
    assert eps == [] and ctx.frameworks == set()
    assert len(seen) <= 3 + 5    # yalnız parmak izi örnekleri; bilinen yol denemesi yok
    assert not any(p.startswith(("/actuator", "/admin", "/docs")) for _, p in seen)


@pytest.mark.asyncio
async def test_single_weak_signal_not_enough():
    pages = {"/": httpx.Response(200, text="x", headers={"set-cookie": "PHPSESSID=1"})}
    seen: list = []
    eps, ctx = await _run(_site(pages, httpx.Response(404, text="nope"), seen))
    assert eps == [] and ctx.frameworks == set()


@pytest.mark.asyncio
async def test_catchall_spa_invents_no_endpoints():
    # Her yola aynı 200 (Express başlığıyla, güçlü sinyal): bilinen yollar uç sayılmaz.
    spa = httpx.Response(200, text="<html><div id=root></div></html>",
                         headers={"x-powered-by": "Express"})
    eps, ctx = await _run(lambda request: spa)
    assert eps == []
    assert ctx.frameworks == {"express"}


@pytest.mark.asyncio
async def test_only_safe_methods_sent():
    seen: list = []
    pages = {"/actuator/mappings": httpx.Response(200, json=MAPPINGS)}
    nf = httpx.Response(404, text="Whitelabel Error Page")
    await _run(_site(pages, nf, seen))
    assert seen and {m for m, _ in seen} <= {"GET", "HEAD", "OPTIONS"}
    assert ("GET", "/api/users") not in seen   # mappings'ten gelen uçlar çağrılmaz


@pytest.mark.asyncio
async def test_known_endpoints_not_duplicated():
    pages = {"/actuator/health": httpx.Response(200, json={"status": "UP", "components": {}})}
    nf = httpx.Response(404, text="Whitelabel Error Page")
    eps, _ = await _run(_site(pages, nf), known=[Endpoint(path_template="/actuator/health")])
    assert ("GET", "/actuator/health") not in _paths(eps)


def test_fingerprinter_pure_signals():
    fp = FrameworkFingerprinter()
    flask = NormalizedResponse(status=404, headers={"Server": "Werkzeug/3.0 Python/3.11"})
    assert fp.detect([flask]) == {"flask"}
    nuxt = NormalizedResponse(status=200, body_text="<script>window.__NUXT__={}</script>")
    assert fp.detect([nuxt]) == {"nuxt"}
    two_weak = [NormalizedResponse(status=200, headers={"set-cookie": "JSESSIONID=1"}),
                NormalizedResponse(status=200, headers={"set-cookie": "JSESSIONID=2"})]
    assert fp.detect(two_weak) == {"spring"}
    assert fp.detect([NormalizedResponse(status=200, headers={"Server": "nginx"})]) == set()


def test_spring_boot1_mappings_format():
    data = {"{[/health],methods=[GET]}": {"bean": "x"}, "{[/orders/{oid}]}": {"bean": "y"}}
    assert set(SpringMappingsParser.parse(data)) == {("GET", "/health"), ("GET", "/orders/{oid}")}


def test_default_sources_framework_between_sourcemap_and_links():
    names = [s.name for s in default_sources()]
    assert names.index("sourcemap") < names.index("framework") < names.index("links")
    assert names.index("links") < names.index("versions")


def test_fingerprinter_cookie_names():
    fp = FrameworkFingerprinter()
    assert fp.detect([], ["connect.sid"]) == {"express"}
    assert fp.detect([], ["XSRF-TOKEN"]) == set()      # tek zayıf sinyal (Angular da kullanır)
    assert fp.detect([], ["_myapp_session", "_session_id"]) == {"rails"}
