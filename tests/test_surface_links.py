"""Faz 1 / T5 — yanıtlardan link keşfi (`ResponseLinkSource`). Ağsız."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import ResponseLinkSource, SurfaceContext, default_sources
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
BODY = {"ok": True, "items": list(range(30))}


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


async def _run(handler, known=None, source=None):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session, known=list(known or []))
        return await (source or ResponseLinkSource()).discover(ctx)
    finally:
        await store.aclose_all()


def _site(pages, seen=None):
    """pages: yol → Response ya da (status, kwargs); bilinmeyen yol 404."""
    def handler(request):
        if seen is not None:
            seen.append((request.method, str(request.url)))
        resp = pages.get(request.url.path)
        if resp is None:
            return httpx.Response(404, json={"error": "nf"})
        return resp
    return handler


def _paths(eps):
    return {(e.method, e.path_template) for e in eps}


@pytest.mark.asyncio
async def test_hal_links_and_jsonapi_next_with_query_stripped():
    pages = {
        "/": httpx.Response(200, json={"_links": {
            "self": {"href": "/"}, "orders": {"href": "/api/orders{?page,size}"},
            "ext": {"href": "http://evil.example/api/x"}}}),
        "/api/orders": httpx.Response(200, json={
            "data": [], "links": {"next": f"{BASE}/api/orders?page=2", "last": "/api/orders?page=9",
                                  "related": "/api/orders/meta"}, **BODY}),
        "/api/orders/meta": httpx.Response(200, json=BODY),
    }
    eps = _paths(await _run(_site(pages)))
    assert ("GET", "/api/orders") in eps
    assert ("GET", "/api/orders/meta") in eps
    assert not any("page" in p or "evil" in p for _, p in eps)


@pytest.mark.asyncio
async def test_location_and_link_headers():
    pages = {
        "/": httpx.Response(200, json=BODY, headers={
            "Location": "/api/session/new",
            "Link": '</api/items?page=2>; rel="next", <http://other.example/z>; rel="last"'}),
        "/api/session/new": httpx.Response(200, json=BODY),
        "/api/items": httpx.Response(200, json=BODY),
    }
    eps = _paths(await _run(_site(pages)))
    assert {("GET", "/api/session/new"), ("GET", "/api/items")} <= eps
    assert not any("other.example" in p for _, p in eps)


HTML_HOME = ('<html><head><link rel="stylesheet" href="/app.css">'
             '<link rel="alternate" href="/feed/rss"></head><body>'
             '<a href="/about-us">a</a><a href="/logo.png">i</a><a href="mailto:x@y.z">m</a>'
             '<a href="http://evil.example/steal">e</a>'
             '<form action="/submit-contact" method="post"><input name="q"></form>'
             '<form action="/search" method="get"></form></body></html>')


@pytest.mark.asyncio
async def test_html_anchors_and_forms_post_form_inventoried_not_submitted():
    seen: list[tuple[str, str]] = []
    pages = {
        "/": httpx.Response(200, text=HTML_HOME, headers={"content-type": "text/html"}),
        "/about-us": httpx.Response(200, text="<html>" + "a" * 300 + "</html>"),
        "/feed/rss": httpx.Response(200, text="<rss>" + "r" * 300 + "</rss>"),
        "/search": httpx.Response(200, text="<html>" + "s" * 300 + "</html>"),
        "/submit-contact": httpx.Response(405, headers={"Allow": "POST, OPTIONS"}),
    }
    eps = _paths(await _run(_site(pages, seen)))
    assert {("GET", "/about-us"), ("GET", "/feed/rss"), ("GET", "/search"),
            ("POST", "/submit-contact")} <= eps
    assert not any(p in ("/app.css", "/logo.png") or "evil" in p for _, p in eps)
    assert {m for m, _ in seen} <= {"GET", "HEAD", "OPTIONS"}
    assert not any("evil.example" in u for _, u in seen)


@pytest.mark.asyncio
async def test_error_body_leaked_path():
    pages = {
        "/": httpx.Response(200, json=BODY),
        "/api/boom": httpx.Response(
            500, text="Traceback: handler failed while serving /api/internal/reports/export now"),
        "/api/internal/reports/export": httpx.Response(200, json=BODY),
    }
    eps = _paths(await _run(_site(pages), known=[Endpoint(path_template="/api/boom")]))
    assert ("GET", "/api/internal/reports/export") in eps


@pytest.mark.asyncio
async def test_id_paths_templatized_after_concrete_probe_and_404_dropped():
    pages = {
        "/": httpx.Response(200, json={"users": [
            {"url": "/api/users/42"}, {"url": "/api/users/43"}, {"url": "/api/ghosts/77"}]}),
        "/api/users/42": httpx.Response(200, json=BODY),
        "/api/users/43": httpx.Response(200, json=BODY),
    }
    eps = await _run(_site(pages))
    got = _paths(eps)
    assert ("GET", "/api/users/{id}") in got
    assert not any("ghosts" in p or "42" in p for _, p in got)
    assert next(e for e in eps if e.path_template == "/api/users/{id}").id_type == "integer"


@pytest.mark.asyncio
async def test_bfs_depth_limit():
    pages = {
        "/": httpx.Response(200, json={"next": "/a1"}),
        "/a1": httpx.Response(200, json={"next": "/b2", **BODY}),
        "/b2": httpx.Response(200, json={"next": "/c3", **BODY}),
        "/c3": httpx.Response(200, json=BODY),
    }
    eps = _paths(await _run(_site(pages), source=ResponseLinkSource(max_depth=2)))
    assert {("GET", "/a1"), ("GET", "/b2")} <= eps
    assert ("GET", "/c3") not in eps


@pytest.mark.asyncio
async def test_random_strings_are_not_paths():
    pages = {
        "/": httpx.Response(200, json={
            "note": "/api/secret/thing", "items": ["/api/other/thing"],
            "description": "see /api/docs for more"}),
        "/api/secret/thing": httpx.Response(200, json=BODY),
        "/api/other/thing": httpx.Response(200, json=BODY),
    }
    assert await _run(_site(pages)) == []


@pytest.mark.asyncio
async def test_logout_and_delete_links_never_probed():
    seen: list[tuple[str, str]] = []
    pages = {
        "/": httpx.Response(200, text=(
            '<html><a href="/logout">x</a><a href="/api/auth/sign-out">y</a>'
            '<a href="/api/items/delete">z</a><a href="/profile-page">p</a></html>')),
        "/logout": httpx.Response(200, json=BODY),
        "/api/auth/sign-out": httpx.Response(200, json=BODY),
        "/api/items/delete": httpx.Response(200, json=BODY),
        "/profile-page": httpx.Response(200, json=BODY),
    }
    eps = _paths(await _run(_site(pages, seen),
                            known=[Endpoint(path_template="/logout")]))
    assert ("GET", "/profile-page") in eps
    assert not any(k in u for _, u in seen for k in ("logout", "sign-out", "delete"))
    assert not any(k in p for _, p in eps for k in ("logout", "sign-out", "delete"))


@pytest.mark.asyncio
async def test_catch_all_spa_invents_nothing():
    spa = ('<html><a href="/dashboard">d</a><a href="/api/users/5">u</a>'
           '<form action="/api/login" method="post"></form>' + "x" * 400 + "</html>")

    def handler(request):
        return httpx.Response(200, text=spa)

    assert await _run(handler) == []


@pytest.mark.asyncio
async def test_other_origin_not_fetched_and_only_safe_methods():
    seen: list[tuple[str, str]] = []
    pages = {
        "/": httpx.Response(200, json={"links": {
            "a": "http://evil.example/api/x", "b": "https://localhost:3000/api/tls",
            "c": "http://localhost:9999/api/port", "d": "/api/fine"}}),
        "/api/fine": httpx.Response(200, json=BODY),
    }
    eps = _paths(await _run(_site(pages, seen)))
    assert eps == {("GET", "/api/fine")}
    assert seen and {m for m, _ in seen} <= {"GET", "HEAD", "OPTIONS"}
    assert all(u.startswith(BASE) for _, u in seen)


@pytest.mark.asyncio
async def test_request_ceiling_respected():
    seen: list[tuple[str, str]] = []
    pages = {"/": httpx.Response(200, json={"links": [f"/api/n{i}" for i in range(50)]})}
    pages.update({f"/api/n{i}": httpx.Response(200, json=BODY) for i in range(50)})
    await _run(_site(pages, seen), source=ResponseLinkSource(max_requests=10))
    assert len(seen) <= 10 + 4   # tavan + baseline probe'ları


def test_default_sources_links_last():
    names = [s.name for s in default_sources()]
    assert names[-1] == "links"
    assert names.index("sourcemap") < names.index("links")
