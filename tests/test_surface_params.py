"""Faz 3 / T2 — keşif kaynaklarından parametre ADI çıkarımı (JS, HTML form, birleştirme). Ağsız."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Param, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import (
    JsBundleSource,
    ResponseLinkSource,
    SurfaceContext,
    SurfaceDiscovery,
)
from pentestai.recon.surface.base import SurfaceSource
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _names(js: str, method: str, path: str) -> set[tuple[str, str]]:
    params = JsBundleSource.extract_params(js).get((method, path), [])
    return {(p.name, p.location) for p in params}


# --- JS desenleri ---

def test_literal_query_keys():
    js = 'http.get("/rest/products/search?q=")'
    assert _names(js, "GET", "/rest/products/search") == {("q", "query")}
    js = 'http.get("/api/items?limit=10&offset=")'
    assert _names(js, "GET", "/api/items") == {("limit", "query"), ("offset", "query")}


def test_string_concatenation_query_keys():
    js = 'this.http.get("/rest/products/search?q=" + e + "&page=" + p)'
    assert _names(js, "GET", "/rest/products/search") == {("q", "query"), ("page", "query")}


def test_template_literal_query_keys():
    js = 'http.get(`/api/items?id=${a}&sort=${b}`)'
    assert _names(js, "GET", "/api/items") == {("id", "query"), ("sort", "query")}


def test_params_object_and_urlsearchparams():
    js = 'this.http.get("/api/items", {params: {q: e, page: n}})'
    assert _names(js, "GET", "/api/items") == {("q", "query"), ("page", "query")}
    js = 'fetch("/api/items?" + new URLSearchParams({term: a, "sort-by": b}))'
    assert {("term", "query"), ("sort-by", "query")} <= _names(js, "GET", "/api/items")


def test_httpparams_set():
    js = 'this.http.get("/api/items", {params: new HttpParams().set("q", e).append("page", n)})'
    assert {("q", "query"), ("page", "query")} <= _names(js, "GET", "/api/items")
    js = 'let p = new HttpParams().set("flt", e); return this.http.get("/api/things", {params: p})'
    assert ("flt", "query") in _names(js, "GET", "/api/things")


def test_json_stringify_body_keys():
    js = 'fetch("/api/auth/login", {method: "POST", body: JSON.stringify({email: a, password: b})})'
    got = _names(js, "POST", "/api/auth/login")
    assert got == {("email", "body"), ("password", "body")}   # method/body seçenekleri sızmaz


def test_http_post_object_body_keys():
    js = 'this.http.post("/api/coupon", {coupon_code: e, "qty": n, shorthand})'
    assert _names(js, "POST", "/api/coupon") == {
        ("coupon_code", "body"), ("qty", "body"), ("shorthand", "body")}


def test_complex_expressions_do_not_invent_params():
    # Spread, hesaplanmış anahtar, çağrı sonucu: yalnız düz anahtarlar alınır.
    js = 'this.http.post("/api/x", {...base, [dyn]: 1, fn(): 2, ok: v})'
    got = _names(js, "POST", "/api/x")
    assert got == {("ok", "body")}
    # Dinamik URL parçası, bilinmeyen sorgu: param yok.
    assert _names('http.get("/api/items?" + qs)', "GET", "/api/items") == set()
    assert _names('http.get(`/api/items?${qs}`)', "GET", "/api/items") == set()
    # Seçenek nesnesi gövde sanılmaz.
    assert _names('fetch("/api/y", {method: "POST", headers: h})', "POST", "/api/y") == set()


def test_values_are_never_copied():
    js = ('this.http.post("/api/login", {email: "admin@x.com", password: "hunter2"});'
          'http.get("/api/items?token=abc123&q=secret")')
    for method, path in (("POST", "/api/login"), ("GET", "/api/items")):
        for param in JsBundleSource.extract_params(js)[(method, path)]:
            assert param.example is None
            assert "admin@x.com" not in param.model_dump_json()
            assert "hunter2" not in param.model_dump_json()
            assert "abc123" not in param.model_dump_json()
            assert param.sources == ["js"] and param.type == "unknown"


def test_params_do_not_leak_to_neighbouring_call():
    js = 'http.get("/api/a"); http.post("/api/b", {only_b: 1})'
    assert _names(js, "GET", "/api/a") == set()
    assert _names(js, "POST", "/api/b") == {("only_b", "body")}


def test_relative_constants_params():
    js = 'x = {SEARCH: "api/items/search?q="}'
    got = JsBundleSource.extract_relative_params(js)
    assert {(p.name, p.location) for p in got[("GET", "api/items/search")]} == {("q", "query")}


@pytest.mark.asyncio
async def test_infer_attaches_params_to_discovered_and_known_endpoints():
    scanner = Scanner(BASE, Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                                  allowed_path_prefixes=["/"], allowed_methods=["GET", "HEAD"]),
                      BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"ok": True, "n": list(range(30))})
        if r.url.path in ("/rest/products/search",) else httpx.Response(404, json={"e": 1})))
    session = store.create(Actor(name="a", auth=AuthState()))
    js = 'http.get("/rest/products/search?q="+e);http.get("/api/known?z=1")'
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session,
                             known=[Endpoint(method="GET", path_template="/api/known")])
        eps = await JsBundleSource().infer(ctx, [js])
    finally:
        await store.aclose_all()
    by_key = {(e.method, e.path_template): e for e in eps}
    assert [p.name for p in by_key[("GET", "/rest/products/search")].params] == ["q"]
    # Bilinen uç yeniden probe edilmez ama parametreler param-yalnız kopyayla döner.
    assert [p.name for p in by_key[("GET", "/api/known")].params] == ["z"]


# --- HTML formları ---

FORM_HTML = """
<html><body>
<form action="/search" method="get"><input name="q" type="text"><input name="limit" type="number">
<input type="submit" name="go" value="x"></form>
<form action="/api/signup" method="post">
<input name="email" type="email" value="victim@real.com"><input name="age" type="number">
<input name="terms" type="checkbox"><input name="csrf" type="hidden" value="SECRET-TOKEN">
<select name="plan"><option>a</option></select><textarea name="bio"></textarea>
<input type="file" name="avatar"></form>
</body></html>
"""


def test_html_form_fields_become_params_with_types_and_no_values():
    source = ResponseLinkSource()
    resp = httpx.Response(200, text=FORM_HTML)
    from pentestai.models import NormalizedResponse
    norm = NormalizedResponse(status=200, headers={}, body_text=resp.text)
    refs = {(r.method, r.path): r for r in source.extract(norm, BASE)}
    get_form = {(p.name, p.location, p.type) for p in refs[("GET", "/search")].params}
    assert get_form == {("q", "query", "string"), ("limit", "query", "integer")}
    post_form = {(p.name, p.location, p.type) for p in refs[("POST", "/api/signup")].params}
    assert post_form == {
        ("email", "body", "string"), ("age", "body", "integer"), ("terms", "body", "boolean"),
        ("csrf", "body", "string"), ("plan", "body", "string"), ("bio", "body", "string")}
    dump = "".join(p.model_dump_json() for r in refs.values() for p in r.params)
    assert "victim@real.com" not in dump and "SECRET-TOKEN" not in dump


@pytest.mark.asyncio
async def test_form_params_reach_discovered_and_known_endpoints():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text=FORM_HTML)
        if request.url.path in ("/search", "/api/signup"):
            return httpx.Response(200, json={"ok": True, "items": list(range(30))})
        return httpx.Response(404, json={"e": 1})

    scanner = Scanner(BASE, Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                                  allowed_path_prefixes=["/"], allowed_methods=["GET", "HEAD"]),
                      BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="a", auth=AuthState()))
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session, known=[
            Endpoint(method="GET", path_template="/search")])
        eps = {(e.method, e.path_template): e for e in await ResponseLinkSource().discover(ctx)}
    finally:
        await store.aclose_all()
    assert {p.name for p in eps[("POST", "/api/signup")].params} >= {"email", "age", "plan"}
    assert {p.name for p in eps[("GET", "/search")].params} == {"q", "limit"}


# --- birleştirme (SurfaceDiscovery + Scanner) ---

class _FixedSource(SurfaceSource):
    def __init__(self, name: str, endpoints: list[Endpoint]) -> None:
        self.name = name
        self._eps = endpoints

    async def discover(self, ctx: SurfaceContext) -> list[Endpoint]:
        return self._eps


def _ep(*names: str, loc: str = "query", src: str = "js") -> Endpoint:
    return Endpoint(method="GET", path_template="/api/x",
                    params=[Param(name=n, location=loc, sources=[src]) for n in names])  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_discovery_merges_params_of_same_endpoint_across_sources():
    discovery = SurfaceDiscovery([_FixedSource("a", [_ep("q")]), _FixedSource("b", [_ep("page", "q")])])
    found = await discovery.run(None, BASE, None, [])  # type: ignore[arg-type]
    assert len(found) == 1
    endpoint, source = found[0]
    assert source == "a" and {p.name for p in endpoint.params} == {"q", "page"}
    assert next(p for p in endpoint.params if p.name == "q").sources == ["js"]


@pytest.mark.asyncio
async def test_discovery_reports_params_for_seed_endpoints_and_scanner_merges_in_place():
    seed = Endpoint(method="GET", path_template="/api/x",
                    params=[Param(name="id", location="query", sources=["openapi"])])
    discovery = SurfaceDiscovery([_FixedSource("js", [_ep("q")])])
    found = await discovery.run(None, BASE, None, [seed])  # type: ignore[arg-type]
    assert found == []                                     # yeni uç yok
    assert [p.name for p in discovery.known_param_updates[("GET", "/api/x")]] == ["q"]

    scanner = Scanner(BASE, Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                                  allowed_path_prefixes=["/"], allowed_methods=["GET", "HEAD"]),
                      BudgetConfig(max_rps_per_host=1000))
    scanner.surface_discovery = _Stub(discovery)           # type: ignore[assignment]
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda r: httpx.Response(404, json={"e": 1})))
    session = store.create(Actor(name="a", auth=AuthState()))
    try:
        extra, _ = await scanner.discover_more(session, [seed])
    finally:
        await store.aclose_all()
    assert {p.name for p in seed.params} == {"id", "q"}    # openapi param'ı korundu, js eklendi
    assert extra == [] or all(e.path_template != "/api/x" for e in extra)


class _Stub:
    """discover_more'un kullandığı SurfaceDiscovery arayüzü (run + alanlar)."""
    def __init__(self, inner: SurfaceDiscovery) -> None:
        self._inner = inner
        self.frameworks: set[str] = set()
        self.found_so_far: list = []

    @property
    def known_param_updates(self):
        return self._inner.known_param_updates

    async def run(self, replayer, base_url, session, known):
        return await self._inner.run(replayer, base_url, session, known)
