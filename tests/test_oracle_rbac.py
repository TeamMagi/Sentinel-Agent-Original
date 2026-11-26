"""RbacMatrixOracle ve `run_rbac_scan` birim/entegrasyon testleri — ağsız (httpx.MockTransport).

A yolu (reference var): CONFIRMED / REJECTED / LIKELY / pozitif kontrol ve catch-all
INCONCLUSIVE. B yolu (reference yok): anon 401 ile CONFIRMED, anon 200 ile LIKELY, REJECTED.
Ayrıca id'siz aktör, ScopeError, triage metinleri, repro_curl redaction ve Scanner entegrasyonu.
"""
from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from pentestai.models import (
    Actor,
    AuthState,
    BudgetConfig,
    Endpoint,
    RbacPolicy,
    RbacRule,
    Scope,
)
from pentestai.net import Replayer, SessionStore
from pentestai.oracle.rbac import RbacMatrixOracle
from pentestai.policy import PolicyEngine
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
PROBE = "sentinel-nonexistent-7f3a"
REPORTS = {"reports": [{"id": 1, "total": 100}]}

EP = Endpoint(method="GET", path_template="/api/admin/reports")
EP_ID = Endpoint(method="GET", path_template="/api/users/{id}", id_param="id")


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET"])


def _token(request: httpx.Request) -> str:
    return request.headers.get("authorization", "").replace("Bearer ", "")


def _is_probe(request: httpx.Request) -> bool:
    return PROBE in request.url.path


def _actor(name: str, role: str, token: str, own: dict[str, str] | None = None) -> Actor:
    return Actor(name=name, role=role,
                 auth=AuthState(headers={"Authorization": f"Bearer {token}"}),
                 own_object_ids=own or {})


async def _run(
    handler: Callable[[httpx.Request], httpx.Response], *,
    endpoint: Endpoint = EP, source: str = "explicit",
    allowed: frozenset[str] = frozenset({"admin"}),
    with_reference: bool = True, with_anon: bool = False,
    subject_own: dict[str, str] | None = None,
    reference_own: dict[str, str] | None = None,
    resource_key: str = "id",
):
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    subject = store.create(_actor("user", "user", "TOKEN_USER", subject_own))
    reference = (store.create(_actor("admin", "admin", "TOKEN_ADMIN", reference_own))
                 if with_reference else None)
    anon = store.create(Actor(name="anonymous", role="anonymous")) if with_anon else None
    oracle = RbacMatrixOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        return await oracle.run(
            endpoint, subject, allowed_roles=allowed, source=source,  # type: ignore[arg-type]
            reference=reference, anon=anon, resource_key=resource_key)
    finally:
        await store.aclose_all()


# --- A) reference VAR ---

@pytest.mark.asyncio
async def test_reference_path_confirms_least_privilege():
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_probe(request):
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json=REPORTS)

    finding = await _run(handler)
    assert finding.verdict == "CONFIRMED"
    assert finding.confidence == "high"
    assert finding.type == "rbac_violation"
    assert finding.parameter == "(rbac:explicit)"
    assert "least-privilege" in (finding.triage_note or "")
    assert finding.evidence.positive_control is True
    assert finding.evidence.baseline_stable is True
    assert finding.evidence.negative_control is True
    assert finding.evidence.leaked_markers == ["user → GET /api/admin/reports: 200"]
    # Redaction: ham token yok, yalnız rol yer tutucusu var.
    assert "TOKEN_ADMIN" not in finding.evidence.repro_curl
    assert "<USER_TOKEN>" in finding.evidence.repro_curl


@pytest.mark.asyncio
async def test_reference_path_rejects_403():
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_probe(request):
            return httpx.Response(404, json={"error": "not found"})
        if _token(request) == "TOKEN_USER":
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(200, json=REPORTS)

    finding = await _run(handler)
    assert finding.verdict == "REJECTED"
    assert "doğru şekilde reddedildi (403)" in (finding.triage_note or "")


@pytest.mark.asyncio
async def test_reference_path_likely_when_structure_differs():
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_probe(request):
            return httpx.Response(404, json={"error": "not found"})
        if _token(request) == "TOKEN_USER":
            return httpx.Response(200, json={"data": {"id": 1}})
        return httpx.Response(200, json=REPORTS)

    finding = await _run(handler)
    assert finding.verdict == "LIKELY"
    assert finding.confidence == "medium"


@pytest.mark.asyncio
async def test_reference_500_is_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_probe(request):
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(500, json={"error": "boom"})

    finding = await _run(handler)
    assert finding.verdict == "INCONCLUSIVE"
    assert "pozitif kontrol" in (finding.triage_note or "")


@pytest.mark.asyncio
async def test_catch_all_spa_fallback_is_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:   # her yol aynı 200
        return httpx.Response(200, json=REPORTS)

    finding = await _run(handler)
    assert finding.verdict == "INCONCLUSIVE"
    assert "catch-all/SPA fallback" in (finding.triage_note or "")
    assert finding.evidence.negative_control is False


# --- B) reference YOK ---

@pytest.mark.asyncio
async def test_without_reference_confirms_when_anon_is_denied():
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_probe(request):
            return httpx.Response(404, json={"error": "not found"})
        if _token(request) == "TOKEN_USER":
            return httpx.Response(200, json=REPORTS)
        return httpx.Response(401, json={"error": "unauthorized"})

    finding = await _run(handler, source="default", allowed=frozenset(),
                         with_reference=False, with_anon=True)
    assert finding.verdict == "CONFIRMED"
    assert finding.confidence == "high"
    assert "deny-by-default" in (finding.triage_note or "")


@pytest.mark.asyncio
async def test_without_reference_likely_when_anon_also_accesses():
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_probe(request):
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json=REPORTS)

    finding = await _run(handler, source="default", allowed=frozenset(),
                         with_reference=False, with_anon=True)
    assert finding.verdict == "LIKELY"
    assert finding.confidence == "medium"
    assert "anon da erişiyor" in (finding.triage_note or "")


@pytest.mark.asyncio
async def test_without_reference_rejects_403():
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_probe(request):
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(403, json={"error": "forbidden"})

    finding = await _run(handler, source="default", allowed=frozenset(),
                         with_reference=False)
    assert finding.verdict == "REJECTED"


# --- id / kapsam ---

@pytest.mark.asyncio
async def test_id_endpoint_without_any_own_id_is_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:   # istek beklenmez
        raise AssertionError("id yokken istek atılmamalıydı")

    finding = await _run(handler, endpoint=EP_ID)
    assert finding.verdict == "INCONCLUSIVE"
    assert "id'li uç nokta için aktör id'si yok" in (finding.triage_note or "")


@pytest.mark.asyncio
async def test_scope_error_is_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:   # istek beklenmez
        raise AssertionError("kapsam dışı istek atılmamalıydı")

    finding = await _run(handler, endpoint=Endpoint(method="POST", path_template="/api/admin/reports"))
    assert finding.verdict == "INCONCLUSIVE"
    assert "kapsam dışı" in (finding.triage_note or "")


# --- Scanner entegrasyonu ---

@pytest.mark.asyncio
async def test_run_rbac_scan_confirms_least_privilege():
    def handler(request: httpx.Request) -> httpx.Response:
        if _is_probe(request):
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json=REPORTS)

    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    scanner.sessions.bind_transport(httpx.MockTransport(handler))
    admin = scanner.sessions.create(_actor("admin", "admin", "TOKEN_ADMIN"))
    user = scanner.sessions.create(_actor("user", "user", "TOKEN_USER"))
    policy = RbacPolicy(rules=[
        RbacRule(method="GET", path="/api/admin/reports", allow=["admin"])])
    try:
        findings = await scanner.run_rbac_scan([admin, user], [], policy)
    finally:
        await scanner.aclose()

    confirmed = [f for f in findings if f.verdict == "CONFIRMED"]
    assert len(confirmed) == 1
    finding = confirmed[0]
    assert finding.id == "F-RBAC001"
    assert finding.type == "rbac_violation"
    assert finding.victim == "admin"
    assert finding.attacker == "user"


@pytest.mark.asyncio
async def test_run_rbac_scan_skips_star_and_allowed_roles():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    scanner.sessions.bind_transport(httpx.MockTransport(handler))
    admin = scanner.sessions.create(_actor("admin", "admin", "TOKEN_ADMIN"))
    user = scanner.sessions.create(_actor("user", "user", "TOKEN_USER"))
    policy = RbacPolicy(rules=[
        RbacRule(method="GET", path="/api/public", allow=["*"]),
        RbacRule(method="GET", path="/api/shared", allow=["user", "admin"]),
    ])
    try:
        findings = await scanner.run_rbac_scan([admin, user], [], policy)
    finally:
        await scanner.aclose()

    assert findings == []
    assert calls == []


@pytest.mark.asyncio
async def test_run_rbac_scan_default_deny_skips_destructive_methods():
    """Güvenlik: varsayılan (deny) kuraldan gelen DELETE uç noktası HİÇ denenmez; açık kuraldaki denenir."""
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        return httpx.Response(403, json={"error": "forbidden"})

    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    scanner.sessions.bind_transport(httpx.MockTransport(handler))
    admin = scanner.sessions.create(_actor("admin", "admin", "TOKEN_ADMIN"))
    user = scanner.sessions.create(_actor("user", "user", "TOKEN_USER"))
    policy = RbacPolicy(default="deny", rules=[])
    inventory = [Endpoint(method="DELETE", path_template="/api/admin/reports"),
                 Endpoint(method="GET", path_template="/api/admin/reports")]
    try:
        findings = await scanner.run_rbac_scan([admin, user], inventory, policy)
    finally:
        await scanner.aclose()

    assert all(method != "DELETE" for method, _ in calls)
    assert findings and all(f.method == "GET" for f in findings)
