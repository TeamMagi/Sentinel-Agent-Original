"""safe_write_paths — destructive_tests=false iken YALNIZ listedeki POST yolları açılır.

PUT/PATCH/DELETE asla açılmaz; eşleşme wire VE decoded formlarda yapılır (fail-closed).
Scanner tarafı: reddedilen yazma uçları kapsam uyarısı olarak raporlanır. Ağ yok: MockTransport.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, CapturedRequest, Endpoint, Hypothesis, Scope
from pentestai.net import SessionStore
from pentestai.policy import Allow, Deny, PolicyEngine
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
SAFE = "/api/coupon/validate"


def _scope(**kw):
    base = dict(
        allowed_hosts=["localhost"], allowed_ports=[3000],
        allowed_path_prefixes=["/api/"], denied_path_patterns=["*/reset*"],
        allowed_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
        safe_write_paths=[SAFE],
    )
    base.update(kw)
    return Scope(**base)


def _authz(path, method="POST", scope=None):
    req = CapturedRequest(method=method, url=f"{BASE}{path}")
    return PolicyEngine(scope or _scope()).authorize(req)


def test_listed_post_allowed():
    assert isinstance(_authz(SAFE), Allow)


def test_unlisted_post_denied_as_destructive():
    d = _authz("/api/orders")
    assert isinstance(d, Deny) and "destructive method blocked" in d.reason


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_other_write_methods_never_opened(method):
    d = _authz(SAFE, method=method)
    assert isinstance(d, Deny) and "destructive method blocked" in d.reason


def test_empty_list_opens_nothing():
    d = _authz(SAFE, scope=_scope(safe_write_paths=[]))
    assert isinstance(d, Deny) and "destructive method blocked" in d.reason


def test_post_not_in_allowed_methods_denied_first():
    d = _authz(SAFE, scope=_scope(allowed_methods=["GET", "HEAD"]))
    assert isinstance(d, Deny) and "method not allowed" in d.reason


def test_denied_path_pattern_beats_safe_list():
    scope = _scope(safe_write_paths=["/api/reset*"])
    d = _authz("/api/reset-all", scope=scope)
    assert isinstance(d, Deny) and d.reason == "path out of scope"


def test_destructive_true_behaviour_unchanged():
    scope = _scope(destructive_tests=True, safe_write_paths=[])
    assert isinstance(_authz("/api/orders", scope=scope), Allow)
    assert isinstance(_authz("/api/orders", method="DELETE", scope=scope), Allow)


def test_case_insensitive_match():
    scope = _scope(allowed_path_prefixes=["/"])
    assert isinstance(_authz("/API/Coupon/Validate", scope=scope), Allow)


@pytest.mark.parametrize("path", [
    "/api/coupon/../orders",                 # dot-segment ile başka yola kaçış
    "/api/coupon/%2e%2e/orders",             # kodlu traversal (wire'da kalır, decoded'da çözülür)
    "/api/coupon/%252e%252e/orders",         # çift kodlu traversal
    "/api/coupon/validate/../../orders",
    "/api/coupon\\validate\\..\\..\\orders",  # ters-eğik çizgi
    "/api/coupon/validate%2f..%2f..%2forders",
    "/api/coupon/validate/%ff",              # bozuk UTF-8 yüzde-dizisi → fail-closed
    "/api/coupon/validate;x=1/../orders",    # matrix-param + traversal
])
def test_bypass_attempts_denied(path):
    assert isinstance(_authz(path), Deny)


def test_double_slash_and_matching_forms():
    # Çift slash her iki formda da tek slash'a iner → gerçekten eşleşen yol Allow.
    assert isinstance(_authz("/api//coupon//validate"), Allow)
    d = _authz("/api/orders/..%2f..%2fcoupon/validate")
    assert isinstance(d, Deny)


def test_wire_and_decoded_must_both_match():
    # Wire: '/api/x%2fvalidate' deseni tutmaz; decoded '/api/x/validate' tutar → ikisi gerekir → Deny.
    scope = _scope(safe_write_paths=["/api/x/validate"])
    assert isinstance(_authz("/api/x%2fvalidate", scope=scope), Deny)
    assert isinstance(_authz("/api/x/validate", scope=scope), Allow)


# --------------------------- Scanner: kapsam uyarısı ---------------------------

def _ok_handler(request):
    return httpx.Response(200, json={"ok": True})


async def _run(scope, endpoint):
    scanner = Scanner(BASE, scope, BudgetConfig(max_total_requests=500, max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_ok_handler))
    A = store.create(Actor(name="user_A", role="user",
                           auth=AuthState(headers={"Authorization": "Bearer A"})))
    hyps = [Hypothesis(type=t, endpoint=endpoint, rationale="r", param="code", param_location="body")
            for t in ("injection", "timing")]
    await scanner.run_hypotheses([A], hyps)
    await store.aclose_all()
    return scanner


def _post_ep(path=SAFE):
    return Endpoint(method="POST", path_template=path)


@pytest.mark.asyncio
async def test_blocked_post_reported_as_coverage_warning():
    scanner = await _run(_scope(safe_write_paths=[]), _post_ep())
    lines = scanner.blocked_write_warnings()
    assert len(lines) == 1
    assert f"POST {SAFE} test edilemedi (injection, timing)" in lines[0]
    assert "safe_write_paths" in lines[0]


@pytest.mark.asyncio
async def test_safe_listed_post_runs_without_warning():
    scanner = await _run(_scope(), _post_ep())
    assert scanner.blocked_writes == []
    assert scanner.blocked_write_warnings() == []
    assert scanner.replayer.budget.remaining < 500   # istek gerçekten gitti


@pytest.mark.asyncio
async def test_path_out_of_scope_produces_no_warning():
    # destructive kapısı path kapısından ÖNCE çalışır; path reddinin uyarı üretmediğini görmek için açık.
    scanner = await _run(_scope(destructive_tests=True), _post_ep("/other/thing"))
    assert scanner.blocked_write_warnings() == []


@pytest.mark.asyncio
async def test_host_out_of_scope_produces_no_warning():
    scope = _scope(allowed_hosts=["elsewhere"])
    scanner = await _run(scope, _post_ep())
    assert scanner.blocked_write_warnings() == []


def test_blocked_write_warnings_truncated_to_ten():
    scanner = Scanner(BASE, _scope(), BudgetConfig())
    scanner.blocked_writes = [("POST", f"/api/e{i:02d}", "injection") for i in range(13)]
    lines = scanner.blocked_write_warnings()
    assert len(lines) == 11
    assert lines[-1] == "... ve 3 uç daha"
