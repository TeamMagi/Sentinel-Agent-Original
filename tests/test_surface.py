"""Faz 0 / A1 — keşif yüzeyi (surface.json) takibi. Ağsız (httpx.MockTransport)."""
import json

import httpx
import pytest

from pentestai.models import (
    Actor,
    AuthState,
    BudgetConfig,
    Endpoint,
    Evidence,
    Finding,
    Hypothesis,
    Param,
    Scope,
)
from pentestai.net import ScopeError, SessionStore
from pentestai.recon.wordlist import WordlistRecon
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])


def _finding(endpoint: str, type_: str = "cors") -> Finding:
    return Finding(id="F-001", type=type_, endpoint=endpoint, verdict="REJECTED",
                   evidence=Evidence())


class _OkDetector:
    async def run(self, endpoint, session, *, finding_id="F-001"):
        return [_finding(endpoint.path_template)]


class _ScopeFailDetector:
    async def run(self, endpoint, session, *, finding_id="F-001"):
        raise ScopeError("kapsam dışı")


@pytest.mark.asyncio
async def test_save_writes_surface_json_with_sources_and_tested_tests(tmp_path):
    """Kaynaklar + tested/tests doğru; ScopeError alan hipotez tests'e GİRMEZ."""
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000), out_dir=str(tmp_path))
    scanner.detectors["cors"] = _OkDetector()
    scanner.detectors["security_headers"] = _ScopeFailDetector()
    ep_a = Endpoint(method="GET", path_template="/a")
    ep_b = Endpoint(method="GET", path_template="/b")
    scanner.register_surface([ep_a, ep_b], "config")

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={})))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        await scanner.run_hypotheses([session], [
            Hypothesis(type="cors", endpoint=ep_a),
            Hypothesis(type="security_headers", endpoint=ep_b),
        ])
        _run_id, root = scanner.save([], "active", sessions=[session])
    finally:
        await store.aclose_all()

    surface = json.loads((root / "surface.json").read_text(encoding="utf-8"))
    by_path = {row["path_template"]: row for row in surface}
    assert by_path["/a"]["sources"] == ["config"]
    assert by_path["/a"]["tested"] is True and by_path["/a"]["tests"] == ["cors"]
    assert by_path["/b"]["tested"] is False and by_path["/b"]["tests"] == []
    # findings.json şeması DEĞİŞMEDİ: hâlâ düz liste.
    assert isinstance(json.loads((root / "findings.json").read_text(encoding="utf-8")), list)


def test_surface_params_only_when_id_is_really_used():
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    with_id = Endpoint(method="GET", path_template="/users/{id}")
    query_id = Endpoint(method="GET", path_template="/orders", id_param="orderId",
                        id_location="query")
    no_id = Endpoint(method="GET", path_template="/health")
    scanner.register_surface([with_id, query_id, no_id], "openapi")
    params = {(e.method, e.path_template): e.params for e in scanner._surface_entries()}
    assert params[("GET", "/users/{id}")] == ["id"]
    assert params[("GET", "/orders")] == ["orderId"]
    assert params[("GET", "/health")] == []


@pytest.mark.asyncio
async def test_discover_more_registers_wordlist_entries_with_wordlist_source():
    """Wordlist ile eklenen uçlar 'wordlist' kaynağıyla yüzeye yazılır (MockTransport)."""
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    scanner.wordlist = WordlistRecon(
        scanner.replayer, BASE, wordlist=("users",), prefixes=("/api/",))

    def handler(request):
        if request.url.path == "/api/users":
            return httpx.Response(200, json={"id": 1})
        return httpx.Response(404, json={})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        extra, _findings = await scanner.discover_more(session, [])
    finally:
        await store.aclose_all()

    assert any(ep.path_template == "/api/users" for ep in extra)
    assert "wordlist" in scanner.surface_sources[("GET", "/api/users")]


@pytest.mark.asyncio
async def test_hypothesis_that_runs_no_oracle_is_not_counted_as_tested():
    """IDOR dalı kurbanın bu kaynakta id'si yoksa hiçbir oracle koşturmadan geçer → uç 'test
    edildi' SAYILMAMALI (aksi halde test-kapsamı metriği şişer)."""
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    ep = Endpoint(method="GET", path_template="/orders/{id}")
    scanner.register_surface([ep], "config")
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={})))
    session = store.create(Actor(name="user_A", auth=AuthState()))   # own_object_ids BOŞ
    try:
        await scanner.run_hypotheses([session], [Hypothesis(type="idor", endpoint=ep)])
    finally:
        await store.aclose_all()
    entry = {e.path_template: e for e in scanner._surface_entries()}["/orders/{id}"]
    assert entry.tested is False and entry.tests == []


@pytest.mark.asyncio
async def test_tested_params_tracks_fuzzed_parameter_names(tmp_path):
    """Faz 3 / T3: `tested_params` yalnızca GERÇEKTEN koşan injection hipotezinin parametresini
    taşır; bilinen ama test edilmeyen parametreler `params`'ta kalır, `tested_params`'a girmez."""
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000), out_dir=str(tmp_path))
    ep = Endpoint(method="GET", path_template="/rest/search",
                 params=[Param(name="q", location="query", type="string")])
    scanner.register_surface([ep], "config")

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={})))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        await scanner.run_hypotheses([session], [
            Hypothesis(type="injection", endpoint=ep, param="q", param_location="query"),
        ])
    finally:
        await store.aclose_all()

    entries = {e.path_template: e for e in scanner._surface_entries()}
    entry = entries["/rest/search"]
    assert "q" in entry.tested_params
    assert "q" in entry.params
