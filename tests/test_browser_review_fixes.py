"""Bağımsız kod incelemesinin tarayıcı/RBAC bulguları için regresyon testleri (Faz 2).

Ağ YOK: oracle/HTTP yolları `httpx.MockTransport`, tarayıcı yolları gerçek headless
Chromium + `context.route()` ile sahte origin. Ham sır/PII değeri testlere yazılmaz.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx
import pytest
import pytest_asyncio
from playwright.async_api import Browser, BrowserContext, async_playwright

from pentestai.classify import assign_all
from pentestai.models import (
    Actor,
    AuthState,
    BudgetConfig,
    Endpoint,
    Scope,
)
from pentestai.net import BudgetExceeded, BudgetTracker, Replayer, SessionStore
from pentestai.oracle.rbac import RbacMatrixOracle
from pentestai.policy import PolicyEngine
from pentestai.recon.browser import CapturedCall, SafeActionPolicy, TrafficToEndpoints, VisibilityMap
from pentestai.recon.browser.discovery import BrowserDiscovery
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
ORIGIN = "http://app.test.local"
HOST = "app.test.local"
CONVERTER = TrafficToEndpoints(["localhost"])
PROBE = "sentinel-nonexistent-7f3a"


def _call(method: str, path: str, **kwargs: object) -> CapturedCall:
    return CapturedCall(method=method, url=BASE + path, **kwargs)  # type: ignore[arg-type]


# --- 1) inferred RBAC kuralı asla CONFIRMED üretmez ---

def test_inferred_rule_is_flagged_and_reaches_oracle_via_source():
    matrix = VisibilityMap()
    matrix.add("admin", [_call("GET", "/api/admin/users", status=200,
                              content_type="application/json")], CONVERTER)
    matrix.add("user", [_call("GET", "/api/orders", status=200,
                             content_type="application/json")], CONVERTER)
    policy = matrix.to_rbac_policy()
    rule = policy.rules[0]
    assert rule.inferred is True
    expected = policy.expected_roles("GET", "/api/admin/users")
    assert expected is not None and expected[1] == "inferred"


@pytest.mark.asyncio
async def test_inferred_rule_caps_verdict_to_likely_and_severity_to_medium():
    def handler(request: httpx.Request) -> httpx.Response:
        if PROBE in request.url.path:
            return httpx.Response(404, json={"error": "yok"})
        return httpx.Response(200, json={"reports": [{"id": 1}]})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_path_prefixes=["/"], allowed_methods=["GET"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    subject = store.create(Actor(name="user", role="user",
                                 auth=AuthState(headers={"Authorization": "Bearer U"})))
    reference = store.create(Actor(name="admin", role="admin",
                                   auth=AuthState(headers={"Authorization": "Bearer A"})))
    oracle = RbacMatrixOracle(Replayer(PolicyEngine(scope)), BASE)
    try:
        finding = await oracle.run(
            Endpoint(method="GET", path_template="/api/admin/reports"), subject,
            allowed_roles=frozenset({"admin"}), source="inferred",  # type: ignore[arg-type]
            reference=reference)
    finally:
        await store.aclose_all()

    assert finding.verdict == "LIKELY"
    assert finding.confidence == "medium"
    assert finding.parameter == "(rbac:inferred)"
    assert "UI görünürlüğünden çıkarılmış kural" in (finding.triage_note or "")
    assign_all([finding])
    assert finding.severity == "Medium"


@pytest.mark.asyncio
async def test_inferred_rule_without_reference_never_confirms():
    def handler(request: httpx.Request) -> httpx.Response:
        if PROBE in request.url.path:
            return httpx.Response(404, json={"error": "yok"})
        token = request.headers.get("authorization", "")
        return httpx.Response(200 if "Bearer U" in token else 401,
                              json={"reports": [{"id": 1}]})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_path_prefixes=["/"], allowed_methods=["GET"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    subject = store.create(Actor(name="user", role="user",
                                 auth=AuthState(headers={"Authorization": "Bearer U"})))
    anon = store.create(Actor(name="anonymous", role="anonymous"))
    oracle = RbacMatrixOracle(Replayer(PolicyEngine(scope)), BASE)
    try:
        finding = await oracle.run(
            Endpoint(method="GET", path_template="/api/admin/reports"), subject,
            allowed_roles=frozenset({"admin"}), source="inferred",  # type: ignore[arg-type]
            anon=anon)
    finally:
        await store.aclose_all()

    assert finding.verdict == "LIKELY"


def test_role_without_successful_api_call_is_not_in_visibility_map(capsys):
    matrix = VisibilityMap()
    matrix.add("user", [_call("POST", "/api/orders", aborted=True)], CONVERTER)
    matrix.add("anonymous", [_call("GET", "/api/orders", status=500,
                                  content_type="application/json")], CONVERTER)
    matrix.add("admin", [_call("GET", "/api/admin/users", status=200,
                              content_type="application/json")], CONVERTER)
    assert matrix.roles() == ["admin"]
    assert matrix.seen_by("user") == set() and matrix.seen_by("anonymous") == set()
    assert "UYARI" in capsys.readouterr().out


# --- 2) otomatik kurallar yalnız güvenli methodlar ---

def test_auto_policy_emits_only_safe_method_rules():
    matrix = VisibilityMap()
    matrix.add("admin", [
        _call("GET", "/api/admin/users", status=200, content_type="application/json"),
        _call("POST", "/api/admin/users/7", aborted=True),
        _call("DELETE", "/api/admin/users/7", aborted=True),
    ], CONVERTER)
    matrix.add("user", [_call("GET", "/api/orders", status=200,
                             content_type="application/json")], CONVERTER)
    assert {r.method for r in matrix.to_rbac_policy().rules} == {"GET"}
    # Görünürlük sayılır, kural yazılmaz.
    assert ("POST", "/api/admin/users/{id}") in matrix.seen_by("admin")


def test_anonymous_visible_endpoint_allows_anonymous_in_policy():
    matrix = VisibilityMap()
    matrix.add("admin", [_call("GET", "/api/admin/users", status=200,
                              content_type="application/json")], CONVERTER)
    matrix.add("anonymous", [
        _call("GET", "/api/admin/users", status=200, content_type="application/json"),
        _call("GET", "/api/me", status=200, content_type="application/json"),
    ], CONVERTER)
    matrix.add("user", [_call("GET", "/api/orders", status=200,
                             content_type="application/json")], CONVERTER)
    rule = matrix.to_rbac_policy().rules[0]
    assert "anonymous" in rule.allow and "admin" in rule.allow


@pytest.mark.asyncio
async def test_discovery_uses_anonymous_role_label(browser):
    """Anon gezinmenin rolü, Scanner oturumundaki 'anonymous' ile aynı olmalı."""
    context = await browser.new_context()

    async def handle(route) -> None:
        if urlsplit(route.request.url).path == "/api/me":
            await route.fulfill(status=200, content_type="application/json", body="{}")
        else:
            await route.fulfill(status=200, content_type="text/html",
                                body="<script>fetch('/api/me')</script>")

    await context.route(f"{ORIGIN}/**", handle)
    scope = Scope(allowed_hosts=[HOST], allowed_ports=[80], allowed_path_prefixes=["/"])
    policy = PolicyEngine(scope)
    try:
        discovery = BrowserDiscovery(
            policy, crawler_factory=lambda: _crawler(context, policy=policy))
        result = await discovery.run(f"{ORIGIN}/", [], [HOST])
    finally:
        await context.close()
    assert result.visibility.roles() == ["anonymous"]


# --- 3-5) kapının tüm sayfaları kapsaması + yazma asla gönderilmemesi ---

@dataclass
class Log:
    calls: list[tuple[str, str]] = field(default_factory=list)


@pytest_asyncio.fixture
async def browser() -> Browser:
    async with async_playwright() as pw:
        launched = await pw.chromium.launch()
        yield launched
        await launched.close()


async def _app(context: BrowserContext, log: Log, html: str) -> None:
    async def handle(route) -> None:
        path = urlsplit(route.request.url).path
        log.calls.append((route.request.method.upper(), path))
        if path.startswith("/api/"):
            await route.fulfill(status=200, content_type="application/json", body="{}")
        else:
            await route.fulfill(status=200, content_type="text/html", body=html)

    await context.route(f"{ORIGIN}/**", handle)


def _crawler(context: BrowserContext, *, budget: BudgetTracker | None = None,
             policy: PolicyEngine | None = None):
    from pentestai.recon.browser.crawler import BrowserCrawler

    scope = Scope(allowed_hosts=[HOST], allowed_ports=[80],
                  allowed_path_prefixes=["/"], allowed_methods=["GET", "HEAD", "POST"],
                  safe_write_paths=["/api/search"])
    engine = policy or PolicyEngine(scope)
    return BrowserCrawler(engine, SafeActionPolicy(engine), context=context, budget=budget,
                          settle_ms=120, timeout_ms=3_000)


@pytest.mark.asyncio
async def test_gate_covers_pages_opened_before_and_during_crawl(browser):
    log = Log()
    html = """<html><body><button id="open" onclick="window.open('/api/popup')">Open</button>
    </body></html>"""
    context = await browser.new_context()
    try:
        await _app(context, log, html)
        pre = await context.new_page()
        await pre.goto(f"{ORIGIN}/")
        await pre.evaluate(
            "() => setInterval(() => fetch('/api/users/1', {method: 'DELETE'}), 100)")
        await _crawler(context).crawl(f"{ORIGIN}/")
        await pre.wait_for_timeout(400)
        assert ("DELETE", "/api/users/1") not in log.calls
    finally:
        await context.close()


@pytest.mark.asyncio
async def test_no_write_request_is_sent_even_when_policy_allows_it(browser):
    """destructive_tests=True olsa bile keşif DELETE/PUT/PATCH ve beyan dışı POST göndermez; tek
    istisna operatörün `safe_write_paths` ile açıkça güvenli beyan ettiği yola POST."""
    log = Log()
    html = """<html><body><script>
    fetch('/api/search', {method:'POST', headers:{'content-type':'application/json'},
      body:JSON.stringify({q:'x'})});
    fetch('/api/feedback', {method:'POST', headers:{'content-type':'application/json'},
      body:JSON.stringify({c:'x'})});
    fetch('/api/users/1', {method:'DELETE'});
    fetch('/api/users/1', {method:'PUT', body:'{}'});
    </script></body></html>"""
    scope = Scope(allowed_hosts=[HOST], allowed_ports=[80], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST", "PUT", "DELETE"],
                  destructive_tests=True, safe_write_paths=["/api/search"])
    context = await browser.new_context()
    try:
        await _app(context, log, html)
        result = await _crawler(context, policy=PolicyEngine(scope)).crawl(f"{ORIGIN}/")
        sent_writes = {(m, p) for m, p in log.calls if m != "GET"}
        assert sent_writes == {("POST", "/api/search")}
        aborted = {(c.method, urlsplit(c.url).path) for c in result.calls if c.aborted}
        assert ("POST", "/api/feedback") in aborted
        assert ("DELETE", "/api/users/1") in aborted
        assert ("PUT", "/api/users/1") in aborted
    finally:
        await context.close()


@pytest.mark.asyncio
async def test_unlabeled_action_is_skipped(browser):
    log = Log()
    html = """<html><body>
    <button onclick="fetch('/api/clicked')"></button>
    <button id="ok" onclick="fetch('/api/ok')">OK</button>
    </body></html>"""
    context = await browser.new_context()
    try:
        await _app(context, log, html)
        result = await _crawler(context).crawl(f"{ORIGIN}/")
        assert ("GET", "/api/clicked") not in log.calls
        assert ("GET", "/api/ok") in log.calls
        assert "<etiketsiz eylem>" in result.skipped_actions
    finally:
        await context.close()


@pytest.mark.asyncio
async def test_every_submit_element_is_checked_for_destructive_label(browser):
    log = Log()
    html = """<html><body><form method="post" action="/api/search">
    <input name="q"><button type="submit">Gönder</button>
    <input type="submit" value="Delete">
    </form></body></html>"""
    context = await browser.new_context()
    try:
        await _app(context, log, html)
        result = await _crawler(context).crawl(f"{ORIGIN}/")
        assert ("POST", "/api/search") not in log.calls
        assert any(c.aborted and c.method == "POST" for c in result.calls)
    finally:
        await context.close()


# --- 4) yıkıcı etiket normalizasyonu ---

@pytest.mark.parametrize("label,destructive", [
    ("/api/delete_account", True),
    ("/rest/deleteUser", True),
    ("logoutUser", True),
    ("btnRemove", True),
    ("delete_btn", True),
    ("/user/reset_password", True),
    ("Address", False),
    ("silver", False),
    ("deleted_at_label", False),
    ("Paylaş", False),
])
def test_destructive_label_normalizes_camel_and_separators(label, destructive):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_path_prefixes=["/"], allowed_methods=["GET"])
    policy = SafeActionPolicy(PolicyEngine(scope))
    assert policy.is_destructive_label(label) is destructive


# --- 6) bütçe: xhr/fetch ve restore sayılır ---

def test_discovery_accepts_budget_and_scanner_binds_replayer_budget():
    budget = BudgetTracker(max_total_requests=5)
    policy = PolicyEngine(Scope(allowed_hosts=["localhost"], allowed_ports=[3000]))
    discovery = BrowserDiscovery(policy, budget=budget)
    assert discovery._factory().budget is budget
    scanner = Scanner(BASE, Scope(allowed_hosts=["localhost"], allowed_ports=[3000]),
                      BudgetConfig(max_total_requests=50, max_rps_per_host=1000),
                      browser_discovery=BrowserDiscovery(policy))
    assert scanner.browser_discovery is not None
    assert scanner.browser_discovery.budget is scanner.replayer.budget


@pytest.mark.asyncio
async def test_budget_counts_allowed_xhr_requests(browser):
    log = Log()
    html = """<html><body><script>
    fetch('/api/a'); fetch('/api/b');
    </script></body></html>"""
    context = await browser.new_context()
    try:
        await _app(context, log, html)
        with pytest.raises(BudgetExceeded):
            await _crawler(context, budget=BudgetTracker(max_total_requests=1)).crawl(
                f"{ORIGIN}/")
    finally:
        await context.close()


# --- 7) own-id yalnız id'siz tek nesne GET yanıtından ---

def test_path_id_is_not_own_id_anymore():
    calls = [_call("GET", "/api/orders/42", status=200, content_type="application/json")]
    from pentestai.recon.browser import OwnIdHarvester

    assert OwnIdHarvester().harvest(calls, CONVERTER) == {}


def test_own_id_from_single_object_identity_endpoint():
    calls = [
        _call("GET", "/api/me", status=200, content_type="application/json",
              response_json={"id": 17, "items": [{"id": 999}]}),
        _call("GET", "/identity/api/v2/user/dashboard", status=200,
              content_type="application/json", response_json={"userId": "u-1"}),
    ]
    from pentestai.recon.browser import OwnIdHarvester

    harvested = OwnIdHarvester().harvest(calls, CONVERTER)
    assert harvested["me"] == "17"
    assert harvested["dashboard"] == "u-1"
    assert "999" not in harvested.values()


# --- 8) gövde şablonu ek hassas anahtarlar ---

def test_extra_sensitive_keys_are_masked_by_type():
    call = _call("POST", "/api/profile", content_type="application/json", request_json={
        "email": "kisi@example.com", "firstName": "Ad", "lastName": "Soyad",
        "username": "kullanici", "phone": "5551112233", "address": "Adres",
        "jwt": "abc", "sid": "s", "session": "q", "csrf": "c", "xsrf": "x",
        "cookie": "c", "ssn": "123", "iban": "TR330006100519786457841326",
        "dob": "1990-01-01", "birthDate": "1990-01-01", "pin": 4321,
    })
    body = TrafficToEndpoints(["localhost"]).convert([call])[0].body_template
    assert body is not None
    assert body["email"] == "snt_{rand}@example.invalid"
    assert body["pin"] == 0
    for key in ("firstName", "lastName", "username", "phone", "address", "jwt", "sid",
                "session", "csrf", "xsrf", "cookie", "ssn", "iban", "dob", "birthDate"):
        assert str(body[key]).startswith("snt_")
    assert "Ad" not in json.dumps(body, ensure_ascii=False)


# --- 9) uyarı satırında redaction önce, kırpma sonra ---

def test_warning_line_redacts_before_truncation():
    scanner = Scanner(BASE, Scope(allowed_hosts=["localhost"], allowed_ports=[3000]),
                      BudgetConfig(max_total_requests=50, max_rps_per_host=1000))
    # E-posta 80. karakterin üstünden geçiyor: önce kesilirse parçası ham kalır.
    scanner.browser_skipped_actions = ["x" * 75 + "kisi@secret.test"]
    lines = scanner.blocked_write_warnings()
    assert lines
    assert "kisi@se" not in lines[0]
    assert "kisi@secret.test" not in lines[0]
    assert "<REDACTED>" in lines[0]
    assert len(lines[0]) <= 80


# --- ek kapı/kuyruk/kıyı senaryoları (madde 3, 5, 6, 9) ---

@pytest.mark.parametrize("scheme,expected", [
    ("http", "pass"), ("https", "pass"),
    ("about", "fallback"), ("data", "fallback"), ("blob", "fallback"),
    ("ws", "abort"), ("wss", "abort"), ("ftp", "abort"), ("file", "abort"),
    ("chrome-extension", "abort"),
])
def test_gate_scheme_policy(scheme, expected):
    from pentestai.recon.browser.crawler import BrowserCrawler

    assert BrowserCrawler._scheme_action(scheme) == expected


def test_start_url_normalization_keeps_query_and_fragment():
    from pentestai.recon.browser.crawler import BrowserCrawler

    assert BrowserCrawler._normalize_start_url(ORIGIN) == f"{ORIGIN}/"
    assert (BrowserCrawler._normalize_start_url(f"{ORIGIN}?q=1#frag")
            == f"{ORIGIN}/?q=1#frag")


def test_click_url_is_gated_before_enqueue():
    from pentestai.recon.browser.crawler import BrowserCrawler

    scope = Scope(allowed_hosts=[HOST], allowed_ports=[80],
                  allowed_path_prefixes=["/ok"], discovery_path_prefixes=[])
    engine = PolicyEngine(scope)
    crawler = BrowserCrawler(engine, SafeActionPolicy(engine))
    assert crawler._queueable_url(f"{ORIGIN}/ok", f"{ORIGIN}/") is True
    assert crawler._queueable_url("http://evil.test/ok", f"{ORIGIN}/") is False
    assert crawler._queueable_url(f"{ORIGIN}/api/delete", f"{ORIGIN}/") is False


@pytest.mark.asyncio
async def test_popup_opened_during_crawl_is_closed(browser):
    html = """<html><body><button id="open" onclick="window.open('/api/popup')">Open</button>
    </body></html>"""
    context = await browser.new_context()
    try:
        await _app(context, Log(), html)
        await _crawler(context).crawl(f"{ORIGIN}/")
        await asyncio.sleep(0.2)   # popup kapatma görevi tamamlansın
        assert len(context.pages) == 0   # gezginin kendi sayfası da kapanır, popup DA
    finally:
        await context.close()


@pytest.mark.asyncio
async def test_websocket_route_is_installed(browser, monkeypatch):
    log = Log()
    html = "<html><body><script>new WebSocket('ws://app.test.local/socket')</script></body></html>"
    context = await browser.new_context()
    try:
        await _app(context, log, html)
        installed: list[str] = []
        original = context.route_web_socket

        async def _spy(pattern, handler) -> None:
            installed.append(pattern)
            await original(pattern, handler)

        monkeypatch.setattr(context, "route_web_socket", _spy)
        await _crawler(context).crawl(f"{ORIGIN}/")
        assert installed == ["**/*"]
    finally:
        await context.close()


@pytest.mark.asyncio
async def test_image_submit_label_is_checked_for_destructive_hint(browser):
    log = Log()
    html = """<html><body><form method="post" action="/api/search">
    <input name="q"><input type="image" alt="Delete" src="/button.png">
    </form></body></html>"""
    context = await browser.new_context()
    try:
        await _app(context, log, html)
        result = await _crawler(context).crawl(f"{ORIGIN}/")
        assert not any(method == "POST" for method, _ in log.calls)
        assert "Delete" in result.skipped_actions
    finally:
        await context.close()
