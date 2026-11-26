"""JsBundleRecon — istemci-tarafı korumalı uç nokta çıkarımı (ağsız)."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine
from pentestai.recon.js_bundle import JsBundleRecon

BASE = "http://localhost:3000"


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])


def _setup(handler):
    store = SessionStore(transport=httpx.MockTransport(handler))
    session = store.create(Actor(
        name="admin", role="admin",
        auth=AuthState(headers={"Authorization": "Bearer ADMIN"})))
    recon = JsBundleRecon(Replayer(PolicyEngine(_scope())), BASE)
    return store, recon, session


def test_extract_script_srcs_handles_quotes_and_attribute_order():
    html = (
        '<script src="/a.js"></script>'
        "<script defer src='/b.js'></script>"
        '<script type="module" data-x="1" src=/c.js></script>'
    )
    assert JsBundleRecon.extract_script_srcs(html) == ["/a.js", "/b.js", "/c.js"]


def test_extract_api_paths_normalizes_params_and_skips_static():
    js = (
        "fetch(`/api/users/${user.id}/orders?x=1`);"
        "axios.get('/rest/basket/:id');"
        "const img = '/static/x.png';"
        "fetch('/admin/users#frag');"
        "fetch('/api/orders/{id}/${other}')"
    )
    paths = [p for p, _ in JsBundleRecon.extract_api_paths(js)]
    assert "/api/users/{id}/orders" in paths
    assert "/rest/basket/{id}" in paths
    assert "/admin/users" in paths
    assert "/api/orders/{id}/{id2}" in paths
    assert "/static/x.png" not in paths


def test_find_guard_signal_window():
    js = "if (user.role === 'admin') { fetch('/api/reports/export') }"
    pos = js.index("/api/reports/export")
    signal = JsBundleRecon.find_guard_signal(js, pos, 300)
    assert signal is not None and "admin" in signal.lower()
    assert JsBundleRecon.find_guard_signal(js, pos, 5) is None


def test_infer_method():
    assert JsBundleRecon.infer_method("axios.post('/api/x')", 12) == "POST"
    js = "fetch('/api/x', {method: 'DELETE'})"
    assert JsBundleRecon.infer_method(js, js.index("/api/x")) == "DELETE"
    js = "fetch('/api/x')"
    assert JsBundleRecon.infer_method(js, js.index("/api/x")) == "GET"


@pytest.mark.asyncio
async def test_discover_end_to_end_skips_unguarded_and_cross_origin():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(200, text=(
                '<html><script src="/static/app.js"></script>'
                '<script src="https://cdn.example/lib.js"></script></html>'))
        if request.url.path == "/static/app.js":
            return httpx.Response(200, text=(
                "if (user.role === 'admin') { fetch('/api/reports/export') }"
                + "/*" + ("x" * 400) + "*/"
                + "fetch('/api/public/status')"))
        return httpx.Response(404, json={"error": "not found"})

    store, recon, session = _setup(handler)
    try:
        gated = await recon.discover(session)
    finally:
        await store.aclose_all()

    assert len(gated) == 1
    assert gated[0].endpoint.path_template == "/api/reports/export"
    assert gated[0].endpoint.method == "GET"
    assert "admin" in gated[0].signal.lower()
    assert gated[0].bundle_url == f"{BASE}/static/app.js"
    assert "https://cdn.example/lib.js" not in seen
    assert "/api/public/status" not in seen   # guard sinyali yok → dönmez


@pytest.mark.asyncio
async def test_discover_respects_max_bundles_and_skips_404_bundle():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(200, text=(
                '<script src="/static/a.js"></script>'
                '<script src="/static/b.js"></script>'
                '<script src="/static/missing.js"></script>'))
        if request.url.path == "/static/a.js":
            return httpx.Response(200, text="if (isAdmin) { fetch('/api/a/export') }")
        if request.url.path == "/static/b.js":
            return httpx.Response(200, text="if (isAdmin) { fetch('/api/b/export') }")
        return httpx.Response(404, json={"error": "not found"})

    store = SessionStore(transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="admin", role="admin"))
    recon = JsBundleRecon(Replayer(PolicyEngine(_scope())), BASE, max_bundles=1)
    try:
        gated = await recon.discover(session)
    finally:
        await store.aclose_all()

    assert [g.endpoint.path_template for g in gated] == ["/api/a/export"]
    assert "/static/b.js" not in seen
    assert "/static/missing.js" not in seen


@pytest.mark.asyncio
async def test_discover_skips_404_bundle():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text='<script src="/static/missing.js"></script>')
        return httpx.Response(404, json={"error": "not found"})

    store, recon, session = _setup(handler)
    try:
        assert await recon.discover(session) == []
    finally:
        await store.aclose_all()


@pytest.mark.asyncio
async def test_discover_drops_path_with_any_unguarded_usage():
    """0-FP: path bir yerde isAdmin yanında, başka bir bundle'da koşulsuz kullanılıyorsa aday olmaz."""
    pad = ";" * 400   # iki kullanım pencereleri çakışmasın
    bundles = {
        "/a.js": "if (user.isAdmin) { fetch('/api/orders/export') }" + pad
                 + "if (user.isAdmin) { fetch('/api/admin/stats') }",
        "/b.js": pad + "fetch('/api/orders/export')",   # normal kullanıcı arayüzü de çağırıyor
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text='<script src="/a.js"></script><script src="/b.js"></script>')
        if request.url.path in bundles:
            return httpx.Response(200, text=bundles[request.url.path])
        return httpx.Response(404)

    store, recon, session = _setup(handler)
    found = await recon.discover(session)
    await store.aclose_all()
    paths = {g.endpoint.path_template for g in found}
    assert paths == {"/api/admin/stats"}


def test_generic_login_guards_are_not_privilege_signals():
    """Yalnız oturum denetleyen guard'lar ve ayrıcalıksız roller sinyal SAYILMAZ."""
    for js in ("canActivate: [AuthGuard], path: '/api/orders'",
               "if (hasRole('user')) fetch('/api/orders')",
               "if (user.permissions.includes('read')) fetch('/api/orders')"):
        pos = js.index("/api/orders")
        assert JsBundleRecon.find_guard_signal(js, pos, 200) is None, js
    js = "if (hasRole('admin')) fetch('/api/orders')"
    assert JsBundleRecon.find_guard_signal(js, js.index("/api/"), 200) == "hasRole('admin'"
