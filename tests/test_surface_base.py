"""Faz 1 / T1 — keşif yüzeyi altyapısı (probe, CatchAllGuard, SurfaceDiscovery). Ağsız."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import (
    CatchAllGuard,
    SurfaceContext,
    SurfaceDiscovery,
    SurfaceSource,
    probe,
    templatize_path,
)
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


def _make(handler):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    return scanner, store, session


@pytest.mark.asyncio
async def test_probe_rejects_non_safe_methods_and_sends_none():
    seen = []

    def handler(request):
        seen.append(request.method)
        return httpx.Response(200, text="ok")

    scanner, store, session = _make(handler)
    ctx = SurfaceContext(scanner.replayer, BASE, session)
    try:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with pytest.raises(ValueError):
                await probe(ctx, "/x", method)
        assert (await probe(ctx, "/x", "get")).status == 200
        assert await probe(ctx, "/x", "OPTIONS") is not None
    finally:
        await store.aclose_all()
    assert seen == ["GET", "OPTIONS"]


@pytest.mark.asyncio
async def test_probe_out_of_scope_url_returns_none():
    scanner, store, session = _make(lambda r: httpx.Response(200, text="ok"))
    ctx = SurfaceContext(scanner.replayer, BASE, session)
    try:
        assert await probe(ctx, "http://evil.example:3000/x") is None
    finally:
        await store.aclose_all()


@pytest.mark.asyncio
async def test_catch_all_guard_false_on_spa_true_on_real_path():
    spa = "<html>" + "x" * 300 + "</html>"

    scanner, store, session = _make(lambda request: httpx.Response(200, text=spa))
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session)
        assert await CatchAllGuard().exists(ctx, "/admin") is False
    finally:
        await store.aclose_all()

    def real_handler(request):
        if request.url.path == "/admin":
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(404, json={})

    scanner, store, session = _make(real_handler)
    try:
        ctx = SurfaceContext(scanner.replayer, BASE, session)
        guard = CatchAllGuard()
        assert await guard.exists(ctx, "/admin") is True
        assert await guard.exists(ctx, "/missing") is False
    finally:
        await store.aclose_all()


def test_templatize_path_replaces_last_id_segment():
    assert templatize_path("/api/users/42") == ("/api/users/{id}", "42")
    assert templatize_path("/api/users") == ("/api/users", None)


class _FakeSource(SurfaceSource):
    def __init__(self, name, paths, *, boom=False):
        self.name = name
        self.paths = paths
        self.boom = boom
        self.known_seen: list[str] = []

    async def discover(self, ctx):
        self.known_seen = [e.path_template for e in ctx.known]
        if self.boom:
            raise RuntimeError("kaynak coktu")
        return [Endpoint(method="GET", path_template=p) for p in self.paths]


@pytest.mark.asyncio
async def test_surface_discovery_dedupes_isolates_errors_and_passes_known_in_order():
    scanner, store, session = _make(lambda r: httpx.Response(404))
    first = _FakeSource("a", ["/one", "/dup", "/known"])
    broken = _FakeSource("boom", [], boom=True)
    second = _FakeSource("b", ["/dup", "/two"])
    discovery = SurfaceDiscovery([first, broken, second])
    try:
        found = await discovery.run(
            scanner.replayer, BASE, session, [Endpoint(method="GET", path_template="/known")])
    finally:
        await store.aclose_all()
    assert [(e.path_template, src) for e, src in found] == [
        ("/one", "a"), ("/dup", "a"), ("/two", "b")]
    assert first.known_seen == ["/known"]
    assert set(second.known_seen) == {"/known", "/one", "/dup"}   # önceki kaynakların bulguları
