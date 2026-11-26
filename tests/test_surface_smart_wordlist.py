"""Faz 1 / T8 — akıllı wordlist (`SmartWordlistSource`). Ağsız."""
import httpx

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import SmartWordlistSource, SurfaceContext, default_sources
from pentestai.scanner import Scanner

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
        return await (source or SmartWordlistSource()).discover(ctx)
    finally:
        await store.aclose_all()


def _site(pages, seen=None, insensitive=False):
    def handler(request):
        path = request.url.path
        if seen is not None:
            seen.append((request.method, path))
        if insensitive:
            path = next((k for k in pages if k.lower() == path.lower()), path)
        resp = pages.get(path)
        return resp if resp is not None else NOT_FOUND
    return handler


def _ok():
    return httpx.Response(200, json=JSON_BODY)


def _paths(eps):
    return {(e.method, e.path_template) for e in eps}


def _known(*paths):
    return [Endpoint(method="GET", path_template=p) for p in paths]


def test_learn_root():
    f = SmartWordlistSource.learn_root
    assert f("/identity/api/auth/login") == "/identity/api/"
    assert f("/community/api/v2/posts") == "/community/api/v2/"
    assert f("/api/v1/users") == "/api/v1/"
    assert f("/rest/products") == "/rest/"
    assert f("/health") is None


async def test_wordlist_on_learned_prefix():
    known = _known("/identity/api/auth/login", "/identity/api/v2/user/dashboard")
    pages = {"/identity/api/accounts": _ok(), "/identity/api/v2/orders": _ok()}
    got = _paths(await _run(_site(pages), known))
    assert ("GET", "/identity/api/accounts") in got
    assert ("GET", "/identity/api/v2/orders") in got


async def test_collection_derivative_me():
    known = _known("/api/v1/users")
    pages = {"/api/v1/users/me": _ok(), "/api/v1/users/export": _ok()}
    got = _paths(await _run(_site(pages), known))
    assert {("GET", "/api/v1/users/me"), ("GET", "/api/v1/users/export")} <= got
    assert ("GET", "/api/v1/users/search") not in got


async def test_admin_derivative():
    known = _known("/api/v1/users")
    pages = {"/api/v1/admin/users": _ok()}
    assert ("GET", "/api/v1/admin/users") in _paths(await _run(_site(pages), known))


async def test_singular_plural_sibling():
    known = _known("/api/v1/user")
    pages = {"/api/v1/users": _ok()}
    assert ("GET", "/api/v1/users") in _paths(await _run(_site(pages), known))
    known = _known("/api/v1/invoices")
    pages = {"/api/v1/invoice": _ok()}
    assert ("GET", "/api/v1/invoice") in _paths(await _run(_site(pages), known))


async def test_pascalcase_evidence_tries_pascal_names():
    known = _known("/api/Users")
    pages = {"/api/Products": _ok()}
    got = _paths(await _run(_site(pages), known))
    assert ("GET", "/api/Products") in got


async def test_pascalcase_not_tried_without_evidence():
    known = _known("/api/v1/users")
    seen = []
    pages = {"/api/Products": _ok()}
    got = _paths(await _run(_site(pages, seen), known))
    assert ("GET", "/api/Products") not in got
    assert all(p != "/api/Products" for _, p in seen)


async def test_case_insensitive_server_no_duplicate():
    known = _known("/api/Users")
    pages = {"/api/Products": _ok(), "/api/Cart": httpx.Response(200, json={"c": list(range(40))})}
    got = _paths(await _run(_site(pages, insensitive=True), known))
    assert ("GET", "/api/Products") in got
    assert ("GET", "/api/products") not in got
    assert ("GET", "/api/cart") not in got


async def test_known_case_form_preferred():
    # bilinen biçim küçük harf, sunucu duyarsız; PascalCase kanıtı başka kaynaktan
    known = _known("/api/Users", "/api/products")
    pages = {"/api/Products": _ok(), "/api/products": _ok()}
    got = _paths(await _run(_site(pages, insensitive=True), known))
    assert ("GET", "/api/Products") not in got


async def test_405_gives_real_method():
    known = _known("/api/v1/users")
    pages = {"/api/v1/users/search": httpx.Response(405, headers={"Allow": "POST"},
                                                    text="Method Not Allowed " * 5)}
    got = _paths(await _run(_site(pages), known))
    assert ("POST", "/api/v1/users/search") in got
    assert ("GET", "/api/v1/users/search") not in got


async def test_catch_all_spa_yields_nothing():
    known = _known("/identity/api/auth/login", "/api/Users", "/api/v1/users")
    spa = httpx.Response(200, text="<html>app</html>")

    def handler(request):
        return spa
    assert await _run(handler, known) == []


async def test_known_not_retried_and_unsafe_never():
    known = _known("/api/v1/users", "/api/v1/users/me", "/api/v1/logout")
    seen = []
    await _run(_site({}, seen), known)
    paths = [p for _, p in seen]
    assert "/api/v1/users/me" not in paths
    assert not any("logout" in p or "delete" in p for p in paths)


async def test_budget_cap():
    known = _known("/identity/api/auth/login", "/api/v1/users", "/api/Users")
    seen = []
    await _run(_site({}, seen), known, source=SmartWordlistSource(max_requests=10))
    assert len(seen) <= 10 + 6   # tavan + baseline probe'ları


async def test_only_safe_methods():
    known = _known("/identity/api/auth/login", "/api/v1/users", "/api/Users")
    seen = []
    await _run(_site({"/api/v1/users/me": _ok()}, seen), known)
    assert seen and {m for m, _ in seen} <= {"GET", "HEAD", "OPTIONS"}


def test_default_sources_smart_wordlist_last():
    names = [s.name for s in default_sources()]
    assert names.index("versions") < names.index("smart-wordlist")
    assert names[-1] == "smart-wordlist"
