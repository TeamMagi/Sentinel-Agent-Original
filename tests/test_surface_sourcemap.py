"""Faz 1 / T4 — source map kaynağı. Ağsız."""
import base64
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import SourceMapSource, SurfaceContext, default_sources
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
INDEX = '<html><script src="/main.js"></script></html>'
SRC_APP = '''
this.http.post<User>("/api/users", body);
this.http.get(`/api/accounts/${id}/statement`);
axios.get("/rest/ping");
const ghost = "/api/ghost";
'''
SRC_NODE = 'axios.get("/api/from-node-modules");'
LIVE = {"/api/users", "/rest/ping"}


def _map(extra_sources=None) -> str:
    sources = ["webpack:///./src/app.ts", "webpack:///./node_modules/lib/index.js",
               "webpack:///webpack/bootstrap"]
    contents = [SRC_APP, SRC_NODE, 'fetch("/api/from-webpack-runtime");']
    return json.dumps({"version": 3, "sources": sources, "sourcesContent": contents,
                       "mappings": ""})


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


async def _run(handler):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session)
        return await SourceMapSource().discover(ctx)
    finally:
        await store.aclose_all()


def _site(bundle: str, *, map_path="/main.js.map", map_headers=None, head_headers=None,
          seen=None, map_text=None):
    def handler(request):
        if seen is not None:
            seen.append((request.method, str(request.url)))
        p = request.url.path
        if p == "/":
            return httpx.Response(200, text=INDEX)
        if p == "/main.js":
            return httpx.Response(200, text=bundle, headers=head_headers or {})
        if p == map_path:
            return httpx.Response(200, text=map_text or _map(), headers=map_headers or {})
        if p in LIVE:
            return httpx.Response(200, json={"ok": True, "items": list(range(30))})
        return httpx.Response(404, json={"error": "nf"})
    return handler


def _keys(eps):
    return {(e.method, e.path_template) for e in eps}


def _assert_found(eps):
    keys = _keys(eps)
    assert ("POST", "/api/users") in keys              # http.post<User>( → POST (jenerikli)
    assert ("GET", "/api/accounts/{id}/statement") in keys   # çağrı bağlamında {id}
    assert ("GET", "/rest/ping") in keys
    assert "/api/ghost" not in {p for _, p in keys}    # GET probe 404 → alınmaz
    assert not any("node-modules" in p or "webpack-runtime" in p for _, p in keys)


@pytest.mark.asyncio
async def test_follows_source_mapping_url_comment():
    bundle = 'var a=1;\n//# sourceMappingURL=main.js.map\n'
    _assert_found(await _run(_site(bundle)))


@pytest.mark.asyncio
async def test_follows_sourcemap_header():
    h = {"SourceMap": "/static/custom.map"}
    _assert_found(await _run(_site("var a=1;", map_path="/static/custom.map", head_headers=h)))


@pytest.mark.asyncio
async def test_follows_x_sourcemap_header():
    h = {"X-SourceMap": "/static/x.map"}
    _assert_found(await _run(_site("var a=1;", map_path="/static/x.map", head_headers=h)))


@pytest.mark.asyncio
async def test_guesses_dot_map():
    _assert_found(await _run(_site("var a=1;")))


@pytest.mark.asyncio
async def test_data_uri_map():
    b64 = base64.b64encode(_map().encode()).decode()
    bundle = f"var a=1;\n//# sourceMappingURL=data:application/json;base64,{b64}\n"
    seen: list = []
    _assert_found(await _run(_site(bundle, map_path="/none", seen=seen)))
    assert not any(u.endswith(".map") for _, u in seen)   # ağa map için gidilmedi


@pytest.mark.asyncio
async def test_oversized_data_uri_skipped():
    src = SourceMapSource(max_map_bytes=10)
    assert src.decode_data_uri("data:application/json;base64," + "A" * 100, 10) is None


@pytest.mark.asyncio
async def test_node_modules_and_webpack_skipped():
    keys = _keys(await _run(_site("var a=1;")))
    assert ("GET", "/api/from-node-modules") not in keys
    assert ("GET", "/api/from-webpack-runtime") not in keys


@pytest.mark.asyncio
async def test_sources_without_contents_yield_nothing():
    m = json.dumps({"version": 3, "sources": ["a.ts"], "mappings": ""})
    assert await _run(_site("var a=1;", map_text=m)) == []


@pytest.mark.asyncio
async def test_catch_all_spa_has_no_map_and_no_endpoints():
    def handler(request):
        return httpx.Response(200, text=INDEX if request.url.path == "/" else
                              '<html><script src="/main.js"></script></html>')
    assert await _run(handler) == []


@pytest.mark.asyncio
async def test_cross_origin_map_url_not_followed():
    bundle = "var a=1;\n//# sourceMappingURL=http://evil.example/main.js.map\n"
    seen: list = []
    eps = await _run(_site(bundle, seen=seen))
    assert eps == [] or all("evil" not in p for _, p in _keys(eps))
    assert not any("evil.example" in u for _, u in seen)


@pytest.mark.asyncio
async def test_only_safe_methods_sent():
    seen: list = []
    await _run(_site("var a=1;", seen=seen))
    assert seen and {m for m, _ in seen} <= {"GET", "HEAD", "OPTIONS"}


def test_default_sources_order_js_before_sourcemap():
    names = [s.name for s in default_sources()]
    assert names.index("js") < names.index("sourcemap")
