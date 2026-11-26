"""Faz 1 / T7 — sürüm kardeşleri / zombi API (`VersionSiblingSource`). Ağsız."""
import httpx

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import SurfaceContext, VersionSiblingSource, default_sources
from pentestai.scanner import Scanner
from pentestai.versioning import parse_version_path

BASE = "http://localhost:3000"
NOT_FOUND = httpx.Response(404, text="Not Found")
JSON_BODY = {"ok": True, "items": list(range(30))}


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


async def _run(handler, known, source=None):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session, known=list(known))
        return await (source or VersionSiblingSource()).discover(ctx)
    finally:
        await store.aclose_all()


def _site(pages, seen=None):
    def handler(request):
        if seen is not None:
            seen.append((request.method, request.url.path))
        resp = pages.get(request.url.path)
        return resp if resp is not None else NOT_FOUND
    return handler


def _ok():
    return httpx.Response(200, json=JSON_BODY)


def _paths(eps):
    return {(e.method, e.path_template) for e in eps}


def test_parse_version_path():
    vp = parse_version_path("/identity/api/v2/user/dashboard")
    assert (vp.head, vp.major, vp.tail) == ("/identity/api/", 2, "/user/dashboard")
    assert parse_version_path("/api/v3.0/x") is None            # dedektör davranışı: yalnız vN
    assert parse_version_path("/api/v3.0/x", minor=True).minor == ".0"
    assert parse_version_path("/api/users") is None
    assert parse_version_path("/api/v1abc/x", minor=True) is None


async def test_integer_siblings_found():
    known = [Endpoint(method="GET", path_template="/identity/api/v2/user/dashboard")]
    pages = {"/identity/api/v1/user/dashboard": _ok(), "/identity/api/v3/user/dashboard": _ok()}
    got = _paths(await _run(_site(pages), known))
    assert got == {("GET", "/identity/api/v1/user/dashboard"),
                   ("GET", "/identity/api/v3/user/dashboard")}


async def test_internal_and_beta_segments():
    known = [Endpoint(method="GET", path_template="/identity/api/v2/user/dashboard")]
    pages = {"/identity/api/internal/user/dashboard": _ok(),
             "/identity/api/beta/v2/user/dashboard": _ok()}
    got = _paths(await _run(_site(pages), known))
    assert got == {("GET", "/identity/api/internal/user/dashboard"),
                   ("GET", "/identity/api/beta/v2/user/dashboard")}


async def test_write_endpoint_sibling_verified_by_405_and_method_copied():
    known = [Endpoint(method="POST", path_template="/api/v2/orders")]
    seen = []
    pages = {"/api/v1/orders": httpx.Response(405, text="Method Not Allowed " * 5)}
    got = await _run(_site(pages, seen), known)
    assert _paths(got) == {("POST", "/api/v1/orders")}
    assert {m for m, _ in seen} == {"GET"}


async def test_write_endpoint_sibling_200_is_not_accepted():
    known = [Endpoint(method="POST", path_template="/api/v2/orders")]
    pages = {"/api/v1/orders": _ok()}   # GET 200: yazma ucunun kanıtı değil
    assert await _run(_site(pages), known) == []


async def test_get_endpoint_405_uses_allow_header_methods():
    known = [Endpoint(method="GET", path_template="/api/v2/orders")]
    pages = {"/api/v1/orders": httpx.Response(405, headers={"Allow": "PUT, GET"}, text="x" * 80)}
    assert _paths(await _run(_site(pages), known)) == {("PUT", "/api/v1/orders")}


async def test_id_sibling_verified_directly():
    known = [Endpoint(method="GET", path_template="/api/v2/users/{id}")]
    pages = {"/api/v1/users/1": _ok()}
    assert _paths(await _run(_site(pages), known)) == {("GET", "/api/v1/users/{id}")}


async def test_id_sibling_falls_back_to_verified_parameterless_sibling():
    known = [Endpoint(method="GET", path_template="/api/v2/users"),
             Endpoint(method="GET", path_template="/api/v2/users/{id}")]
    # v1/users var; v1/users/1 yok (404) -> {id}'li uç yine de v1 ile alınır
    pages = {"/api/v1/users": _ok()}
    got = _paths(await _run(_site(pages), known))
    assert got == {("GET", "/api/v1/users"), ("GET", "/api/v1/users/{id}")}


async def test_id_sibling_without_verified_sibling_not_taken():
    known = [Endpoint(method="GET", path_template="/api/v2/users/{id}")]
    assert await _run(_site({}), known) == []


async def test_group_representative_budget_unverified_group_not_exhausted():
    known = [Endpoint(method="GET", path_template=f"/api/v2/items/r{i}") for i in range(6)]
    seen = []
    assert await _run(_site({}, seen), known) == []
    # yalnız temsilci denendi: tek uç için etiket sayısı kadar istek, 6 uç x etiket değil
    one_ep = len(VersionSiblingSource()._labels(parse_version_path("/api/v2/items/r0"), 2))
    probes = [p for _, p in seen if "sentinel-nonexistent" not in p]
    assert len(probes) == one_ep
    assert not any(p.endswith("/r3") for p in probes)


async def test_group_verified_representative_applies_to_others_each_verified():
    known = [Endpoint(method="GET", path_template="/api/v2/items/a"),
             Endpoint(method="GET", path_template="/api/v2/items/b"),
             Endpoint(method="GET", path_template="/api/v2/items/c")]
    pages = {"/api/v1/items/a": _ok(), "/api/v1/items/b": _ok()}   # c yok
    got = _paths(await _run(_site(pages), known))
    assert got == {("GET", "/api/v1/items/a"), ("GET", "/api/v1/items/b")}


async def test_max_requests_ceiling():
    known = [Endpoint(method="GET", path_template="/api/v2/items/a")]
    seen = []
    await _run(_site({}, seen), known, VersionSiblingSource(max_requests=5))
    assert len([p for _, p in seen if "sentinel-nonexistent" not in p]) <= 5


async def test_catch_all_spa_invents_nothing():
    known = [Endpoint(method="GET", path_template="/api/v2/users"),
             Endpoint(method="POST", path_template="/api/v2/orders"),
             Endpoint(method="GET", path_template="/api/v2/users/{id}")]
    spa = httpx.Response(200, text="<html>" + "spa " * 50 + "</html>")
    assert await _run(lambda request: spa, known) == []


async def test_redirect_to_original_not_taken():
    known = [Endpoint(method="GET", path_template="/api/v2/users")]
    pages = {"/api/v1/users": httpx.Response(301, headers={"Location": "/api/v2/users"},
                                             text="moved " * 10)}
    assert await _run(_site(pages), known) == []


async def test_redirect_elsewhere_is_taken():
    known = [Endpoint(method="GET", path_template="/api/v2/users")]
    pages = {"/api/v1/users": httpx.Response(302, headers={"Location": "/legacy/users"},
                                             text="moved " * 10)}
    assert _paths(await _run(_site(pages), known)) == {("GET", "/api/v1/users")}


async def test_minor_version_format():
    known = [Endpoint(method="GET", path_template="/api/v4.0/accounts")]
    pages = {"/api/v3.0/accounts": _ok()}
    assert _paths(await _run(_site(pages), known)) == {("GET", "/api/v3.0/accounts")}


async def test_known_sibling_not_reprobed_and_only_safe_methods():
    known = [Endpoint(method="GET", path_template="/api/v2/users"),
             Endpoint(method="GET", path_template="/api/v1/users"),
             Endpoint(method="DELETE", path_template="/api/v2/users/{id}")]
    seen = []
    await _run(_site({"/api/v3/users": _ok()}, seen), known)
    assert {m for m, _ in seen} <= {"GET", "HEAD", "OPTIONS"}
    assert "/api/v1/users" not in [p for _, p in seen]


async def test_endpoint_without_version_ignored():
    seen = []
    await _run(_site({}, seen), [Endpoint(method="GET", path_template="/api/users")])
    assert seen == []


def test_default_sources_versions_after_others():
    names = [s.name for s in default_sources()]
    for earlier in ("openapi-auto", "robots", "js", "sourcemap", "framework", "links"):
        assert names.index(earlier) < names.index("versions")
