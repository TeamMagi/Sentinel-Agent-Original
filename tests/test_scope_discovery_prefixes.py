"""Yalnız-keşif önekleri (`Scope.discovery_path_prefixes`): keşif dar scope'ta kök/JS'i okuyabilir,
test istekleri ve test yüzeyi genişlemez. Ağsız (httpx.MockTransport)."""
import httpx
import pytest

from pentestai.config import load_scope_config
from pentestai.models import Actor, AuthState, BudgetConfig, CapturedRequest, Scope
from pentestai.net import SessionStore
from pentestai.policy import Allow, Deny, PolicyEngine
from pentestai.recon.surface import scope_prefix_warning
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _scope(prefixes=("/api/",), discovery=("/",), methods=("GET", "HEAD"), denied=()) -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                 allowed_path_prefixes=list(prefixes), discovery_path_prefixes=list(discovery),
                 denied_path_patterns=list(denied), allowed_methods=list(methods))


def _auth(policy, path, method="GET", purpose="discovery"):
    return policy.authorize(CapturedRequest(method=method, url=BASE + path), purpose=purpose)


# ---- policy ----
def test_discovery_allows_get_on_discovery_prefix_but_test_denied():
    policy = PolicyEngine(_scope())
    assert isinstance(_auth(policy, "/static/main.js"), Allow)
    assert _auth(policy, "/static/main.js", purpose="test") == Deny("path out of scope")
    assert _auth(policy, "/static/main.js", purpose="auth") == Deny("path out of scope")


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_discovery_denies_write_methods(method):
    policy = PolicyEngine(_scope(methods=("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH")))
    assert _auth(policy, "/api/x", method) == Deny("discovery method not allowed")


def test_discovery_options_only_when_in_allowed_methods():
    assert _auth(PolicyEngine(_scope()), "/api/x", "OPTIONS") == Deny("discovery method not allowed")
    assert isinstance(_auth(PolicyEngine(_scope(methods=("GET", "OPTIONS"))), "/api/x", "OPTIONS"), Allow)
    assert isinstance(_auth(PolicyEngine(_scope()), "/api/x", "HEAD"), Allow)


def test_discovery_still_honors_denied_patterns():
    policy = PolicyEngine(_scope(denied=("*/reset*",)))
    assert _auth(policy, "/static/reset.js") == Deny("path out of scope")


@pytest.mark.parametrize("path", [
    "/static/%2e%2e/admin/reset", "/static/../admin/reset", "/static/%252e%252e/admin/reset",
    "/static/..%5cadmin/reset"])
def test_discovery_escape_into_denied_path_denied(path):
    policy = PolicyEngine(_scope(denied=("*/admin/*",)))
    assert isinstance(_auth(policy, path), Deny)


def test_discovery_prefix_escape_to_test_prefix_does_not_help_test_purpose():
    # keşif önekinden test önekine atlama: test purpose'u yine yalnız allowed_path_prefixes görür
    policy = PolicyEngine(_scope(discovery=("/pub/",)))
    assert isinstance(_auth(policy, "/pub/../api/x"), Allow)            # wire=/api/x → test önekinde
    assert _auth(policy, "/pub/x", purpose="test") == Deny("path out of scope")
    assert isinstance(_auth(policy, "/pub/%2e%2e/etc/passwd"), Deny)    # /etc/ hiçbir önekte değil


def test_empty_discovery_prefixes_keep_old_behavior():
    policy = PolicyEngine(_scope(discovery=()))
    assert _auth(policy, "/static/a.js") == Deny("path out of scope")
    assert isinstance(_auth(policy, "/api/a"), Allow)


def test_path_in_test_scope_templates_and_denied():
    policy = PolicyEngine(_scope(denied=("*/admin/*",)))
    assert policy.path_in_test_scope("/api/users/{id}")
    assert not policy.path_in_test_scope("/admin/panel")
    assert not policy.path_in_test_scope("/api/admin/{x}")
    assert not policy.path_in_test_scope("/static/app.js")   # yalnız keşif önekinde


# ---- config ----
def test_config_reads_discovery_prefixes(tmp_path):
    f = tmp_path / "s.yaml"
    f.write_text("scope:\n  allowed_hosts: [localhost]\n  allowed_ports: [3000]\n"
                 "  discovery_path_prefixes: ['/']\n", encoding="utf-8")
    assert load_scope_config(str(f))[1].discovery_path_prefixes == ["/"]
    f.write_text("scope:\n  allowed_hosts: [localhost]\n  allowed_ports: [3000]\n", encoding="utf-8")
    assert load_scope_config(str(f))[1].discovery_path_prefixes == []


# ---- uyarı ----
def test_warning_branches():
    assert scope_prefix_warning(_scope(discovery=("/",))) is None
    msg = scope_prefix_warning(_scope(discovery=()))
    assert msg is not None and "discovery_path_prefixes" in msg
    assert scope_prefix_warning(_scope(discovery=("/pub/",))) is not None
    assert scope_prefix_warning(_scope(prefixes=("/",), discovery=())) is None


# ---- uçtan uca ----
@pytest.mark.asyncio
async def test_discover_more_filters_out_of_test_scope(capsys):
    seen: list[tuple[str, str]] = []

    def handler(request):
        seen.append((request.method, request.url.path))
        p = request.url.path
        if p == "/":
            return httpx.Response(200, text='<html><script src="/static/app.js"></script></html>',
                                  headers={"content-type": "text/html"})
        if p == "/static/app.js":
            return httpx.Response(
                200, text='fetch("/api/users");fetch("/admin/panel");',
                headers={"content-type": "application/javascript"})
        if p in ("/api/users", "/admin/panel"):
            return httpx.Response(200, json={"ok": True, "path": p, "n": len(p)})
        return httpx.Response(404, text="nf")

    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        found = await scanner.surface_discovery.run(scanner.replayer, BASE, session, [])
        found_paths = {e.path_template for e, _ in found}
        assert "/api/users" in found_paths and "/admin/panel" in found_paths   # keşif ikisini de görür
        seen.clear()
        extra, _ = await scanner.discover_more(session, [])
    finally:
        await store.aclose_all()
    paths = {e.path_template for e in extra}
    assert "/api/users" in paths
    assert "/admin/panel" not in paths
    assert all(m in ("GET", "HEAD", "OPTIONS") for m, _ in seen)
    assert any(p == "/static/app.js" for _, p in seen)
    assert not any(p == "/admin/panel" for p in (k[1] for k in scanner.surface_sources))
    assert "test scope'u dışında" in capsys.readouterr().err
