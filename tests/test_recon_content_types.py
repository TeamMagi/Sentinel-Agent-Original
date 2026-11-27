"""Faz 3 / T6 — içerik tipi (parser farkı) keşfi. Ağsız: httpx.MockTransport."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.planner import HypothesisGenerator
from pentestai.prioritize import HypothesisPrioritizer
from pentestai.recon.content_types import ContentTypeProber, to_form, to_xml
from pentestai.recon.openapi import OpenApiRecon
from pentestai.report.input_coverage import InputCoverageReporter
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
TEMPLATE = {"username": "snt_{rand}", "password": "P{rand}!", "nested": {"a": 1}}


def _scope(*, destructive: bool = True, safe_write: list[str] | None = None) -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "POST"], destructive_tests=destructive,
                 safe_write_paths=safe_write or [])


def _endpoint() -> Endpoint:
    return Endpoint(method="POST", path_template="/api/register", id_location="body",
                    id_param="username", body_template=TEMPLATE)


async def _run(handler, endpoints, *, scope=None, max_requests=30):
    scanner = Scanner(BASE, scope or _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        prober = ContentTypeProber(scanner.replayer, BASE, max_requests=max_requests)
        return await prober.probe_all(endpoints, session), prober
    finally:
        await store.aclose_all()


def _echo_handler(accept: set[str]):
    """Kabul edilen tipte gövdeyi yansıtan 201; diğerlerinde 415."""
    def handler(request):
        ctype = request.headers.get("content-type", "").split(";")[0]
        if ctype not in accept:
            return httpx.Response(415, json={"error": "unsupported"})
        return httpx.Response(201, json={"ok": True, "echo": request.content.decode()})
    return handler


@pytest.mark.asyncio
async def test_json_and_form_accepted():
    out, prober = await _run(
        _echo_handler({"application/json", "application/x-www-form-urlencoded"}), [_endpoint()])
    assert out[0].accepted_content_types == [
        "application/json", "application/x-www-form-urlencoded"]
    assert prober.used == 3


@pytest.mark.asyncio
async def test_415_means_only_json():
    out, _ = await _run(_echo_handler({"application/json"}), [_endpoint()])
    assert out[0].accepted_content_types == ["application/json"]


@pytest.mark.asyncio
async def test_xml_accepted_and_value_not_stored():
    out, _ = await _run(_echo_handler({"application/json", "application/xml"}), [_endpoint()])
    assert out[0].accepted_content_types == ["application/json", "application/xml"]
    assert "snt_" not in str(out[0].accepted_content_types)
    assert "password" not in str(out[0].accepted_content_types)


@pytest.mark.asyncio
async def test_body_ignoring_server_is_not_accepted():
    """Gövdeyi yansıtan baseline'a karşı yansıtmayan 'her şeye 200' yanıtı kabul sayılmaz."""
    def handler(request):
        ctype = request.headers.get("content-type", "").split(";")[0]
        if ctype == "application/json":
            return httpx.Response(200, json={"echo": request.content.decode()})
        return httpx.Response(200, json={"echo": "yok"})

    out, _ = await _run(handler, [_endpoint()])
    assert out[0].accepted_content_types == ["application/json"]


@pytest.mark.asyncio
async def test_policy_denies_write_no_request_sent():
    calls: list[str] = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(201, json={"ok": True})

    out, prober = await _run(handler, [_endpoint()], scope=_scope(destructive=False))
    assert calls == []
    assert prober.used == 0
    assert out[0].accepted_content_types == []


@pytest.mark.asyncio
async def test_safe_write_path_allows_post():
    out, _ = await _run(_echo_handler({"application/json", "application/x-www-form-urlencoded"}),
                        [_endpoint()], scope=_scope(destructive=False, safe_write=["/api/register"]))
    assert "application/x-www-form-urlencoded" in out[0].accepted_content_types


@pytest.mark.asyncio
async def test_total_cap_and_ineligible_skipped():
    calls: list[str] = []

    def handler(request):
        calls.append(request.method + request.url.path)
        return httpx.Response(201, json={"ok": True, "e": request.content.decode()})

    endpoints = [Endpoint(method="GET", path_template="/api/list"),
                 Endpoint(method="POST", path_template="/api/x/{id}", body_template={"a": "b"}),
                 *[Endpoint(method="POST", path_template=f"/api/e{i}", body_template={"a": "b{rand}"})
                   for i in range(5)]]
    _out, prober = await _run(handler, endpoints, max_requests=4)
    assert len(calls) == 4 == prober.used
    assert all(c.startswith("POST/api/e") for c in calls)


def test_encoders_skip_nested_and_escape():
    assert to_form({"a": "x y", "n": {"z": 1}, "b": True}) == b"a=x+y&b=true"
    xml = to_xml({"a": "<&>", "bad key": "v", "n": {"z": 1}}).decode()
    assert "<a>&lt;&amp;&gt;</a>" in xml and "bad key" not in xml and "<n>" not in xml


def test_openapi_fills_content_types():
    spec = {"paths": {"/users": {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"type": "object", "properties": {"n": {"type": "string"}}}},
        "text/xml; charset=utf-8": {}, "image/png": {}}}}}}}
    eps = OpenApiRecon().parse(spec)
    assert eps[0].accepted_content_types == ["application/json", "application/xml"]


def test_planner_xml_endpoint_gets_priority_xxe():
    xml_ep = Endpoint(method="POST", path_template="/api/import", body_template={"a": "b"},
                      accepted_content_types=["application/json", "application/xml"])
    plain = Endpoint(method="GET", path_template="/api/ping")
    hyps = HypothesisGenerator().deterministic([plain, xml_ep])
    xxe = [h for h in hyps if h.type == "xxe"]
    assert any(h.endpoint.path_template == "/api/import" for h in xxe)
    ordered = HypothesisPrioritizer().order(hyps)
    first_xxe = next(h for h in ordered if h.type == "xxe")
    assert first_xxe.endpoint.path_template == "/api/import"


def test_report_line():
    from pentestai.models import SurfaceEntry
    entries = [SurfaceEntry(method="POST", path_template="/a")]
    md = InputCoverageReporter.render_markdown(entries, content_type_endpoints=2)
    assert "Farklı içerik tipi kabul eden uç:** 2" in md
    assert "içerik tipi" not in InputCoverageReporter.render_markdown(entries)
