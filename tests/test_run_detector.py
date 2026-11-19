"""Dedektör ailesinin agentic döngüye bağlanması (Faz 8) — ağsız.

Doğrulananlar:
  • `RunDetector` executor'da doğru dedektöre dispatch edilir; çoklu bulgu Observation'da taşınır.
  • `WorldModel` çoklu bulguyu kaydeder; aynı nesne iki alanda olsa bile tek sayılır.
  • Dedektörün CONFIRMED bulgusu agentic loop'ta pivot tetikler (yeni endpoint keşfi).
  • Hedef-seviyesi dedektör döngü başında BİR kez seed edilir.
  • Deterministik seçici dedektör aksiyonunu yalnızca kayıtlıysa üretir; LLM şeması parse eder.
"""
import json

import httpx

from pentestai.detector.base import Detector
from pentestai.models import (
    Actor,
    AuthState,
    Endpoint,
    Evidence,
    Finding,
    NormalizedResponse,
    Observation,
    Scope,
)
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import IdorOracle
from pentestai.orchestrator.actions import RunDetector
from pentestai.orchestrator.agent import AgenticOrchestrator
from pentestai.orchestrator.executor import ActionExecutor
from pentestai.orchestrator.selectors import (
    DeterministicSelector,
    _parse_actions,
)
from pentestai.orchestrator.world_model import WorldModel
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
ORDERS = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
PROFILES = Endpoint(method="GET", path_template="/api/profiles/{id}", id_param="id")
USERS = Endpoint(method="GET", path_template="/api/users/{id}", id_param="id")

# Sahiplik kontrollü orders (IDOR negatif), sahipsiz profiles (IDOR pozitif).
_DB = {
    "orders": {
        "A-1": {"id": "A-1", "owner": "user_A", "message": "order"},
        "B-1": {"id": "B-1", "owner": "user_B", "message": "order"},
    },
    "profiles": {
        "P-A": {"id": "P-A", "email": "alice@test.local", "role": "user"},
        "P-B": {"id": "P-B", "email": "bob@test.local", "role": "user"},
    },
}


def _handler(request: httpx.Request) -> httpx.Response:
    actor = request.headers.get("authorization", "").replace("Bearer ", "")
    owner = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}.get(actor)
    oid = request.url.path.rsplit("/", 1)[-1]
    if "/api/orders/" in request.url.path:
        obj = _DB["orders"].get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if obj["owner"] != owner:
            return httpx.Response(403, json={"error": "forbidden"})   # güvenli
        return httpx.Response(200, json=obj)
    if "/api/profiles/" in request.url.path:
        obj = _DB["profiles"].get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json=obj)   # sahiplik kontrolü YOK → IDOR
    if "/api/users/" in request.url.path:
        obj = _DB["profiles"].get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        # Auth'suz da okunabilen public-by-design kaynak: IDOR DEĞİL (anonim kapı reddetmeli).
        return httpx.Response(200, json=obj)
    return httpx.Response(404, json={"error": "not found"})


def _setup(*, detectors=None, target_detectors=None, with_anon=False):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(_handler))
    replayer = Replayer(PolicyEngine(scope))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"orders": "A-1", "profiles": "P-A", "users": "P-A"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"orders": "B-1", "profiles": "P-B", "users": "P-B"})
    sessions = {"user_A": store.create(A), "user_B": store.create(B)}
    anon = store.create(Actor(name="anonymous", role="anonymous")) if with_anon else None
    executor = ActionExecutor(replayer, {"idor": IdorOracle(replayer, BASE)}, BASE,
                              detectors=detectors or {},
                              target_detectors=target_detectors or {},
                              anon_session=anon)
    return store, executor, sessions


def _finding(fid="F-DET", *, endpoint="/api/orders/{id}", profile_id="P-B"):
    return Finding(
        id=fid, type="open_redirect", endpoint=endpoint, method="GET", verdict="CONFIRMED",
        evidence=Evidence(attack_response=NormalizedResponse(
            status=200, json_body={"profileId": profile_id})),
    )


class _FakeDetector(Detector):
    """Ağ kullanmayan imza dedektörü: çağrıyı kaydeder, önceden verilen bulguları döner."""

    vuln_type = "open_redirect"

    def __init__(self, findings):
        super().__init__(replayer=None, base_url=BASE)
        self.findings = findings
        self.calls: list[tuple[str, str]] = []

    async def run(self, endpoint, session, *, finding_id="F-001"):
        self.calls.append((endpoint.path_template, session.actor.name))
        return list(self.findings)


async def test_run_detector_dispatch_and_multi_findings():
    fake = _FakeDetector([_finding("F-1"), _finding("F-2")])
    store, executor, sessions = _setup(detectors={"open_redirect": fake})
    obs = await executor.execute(
        RunDetector(detector="open_redirect", endpoint=ORDERS, actor_name="user_A"), sessions)
    assert [f.id for f in obs.findings] == ["F-1", "F-2"]
    assert obs.finding is None
    assert fake.calls == [("/api/orders/{id}", "user_A")]
    await store.aclose_all()


async def test_world_model_records_all_detector_findings_once():
    f1, f2 = _finding("F-1"), _finding("F-2")
    wm = WorldModel(BASE)
    wm.record(RunDetector(detector="open_redirect", endpoint=ORDERS, actor_name="user_A"),
              Observation(action_type="run_detector", findings=[f1, f2], finding=f1))
    assert wm.findings == [f1, f2]   # f1 iki alanda da olsa tek kez


async def test_unknown_detector_is_clean_observation():
    store, executor, sessions = _setup()
    obs = await executor.execute(
        RunDetector(detector="yok", endpoint=ORDERS, actor_name="user_A"), sessions)
    assert obs.findings == [] and "bilinmeyen dedektör" in obs.note
    await store.aclose_all()


async def test_agent_pivots_from_detector_confirmed_to_new_endpoint():
    fake = _FakeDetector([_finding()])
    store, executor, sessions = _setup(detectors={"open_redirect": fake})
    agent = AgenticOrchestrator(
        executor, [ORDERS], base_url=BASE, max_iterations=20, batch=4)
    state = await agent.run(sessions)

    confirmed = [f for f in state.findings if f.verdict == "CONFIRMED"]
    assert any(f.type == "idor" and f.endpoint == "/api/profiles/{id}" for f in confirmed), \
        "dedektör bulgusundaki profileId pivotu profiles IDOR'unu kanıtlamalıydı"
    assert any("run_detector open_redirect" in s.proposed_action for s in agent.trace.steps)
    assert any("pivot: CONFIRMED" in s.rationale and "/api/profiles" in s.proposed_action
               for s in agent.trace.steps)
    await store.aclose_all()


async def test_target_detector_is_seeded_exactly_once():
    calls = []

    async def seed(session):
        calls.append(session.actor.name)
        return [_finding("F-SEED")]

    store, executor, sessions = _setup(target_detectors={"fake": seed})
    agent = AgenticOrchestrator(
        executor, [ORDERS], base_url=BASE, max_iterations=20, batch=4)
    state = await agent.run(sessions)

    assert calls == ["user_A"]
    assert any("seed_target_detector fake" in s.proposed_action for s in agent.trace.steps)
    assert any(f.endpoint == "/api/profiles/{id}" and f.verdict == "CONFIRMED"
               for f in state.findings)
    await store.aclose_all()


async def test_agentic_idor_confirms_without_anon_gate():
    """Kontrol: anonim kap? yokken public endpoint'te IDOR (yanl??) CONFIRMED olur."""
    store, executor, sessions = _setup()
    agent = AgenticOrchestrator(executor, [USERS], base_url=BASE, max_iterations=10, batch=4)
    state = await agent.run(sessions)
    assert any(f.type == "idor" and f.endpoint == "/api/users/{id}"
               and f.verdict == "CONFIRMED" for f in state.findings)
    await store.aclose_all()


async def test_agentic_idor_rejects_public_by_design_with_anon_gate():
    """Anonim oturum verilince auth'suz okunabilen kaynak IDOR say?lmaz (VAmPI regresyonu)."""
    store, executor, sessions = _setup(with_anon=True)
    agent = AgenticOrchestrator(executor, [USERS], base_url=BASE, max_iterations=10, batch=4)
    state = await agent.run(sessions)
    idor = [f for f in state.findings
            if f.type == "idor" and f.endpoint == "/api/users/{id}"]
    assert idor and all(f.verdict != "CONFIRMED" for f in idor)
    await store.aclose_all()


async def test_deterministic_selector_emits_detector_only_when_registered():
    store, _, sessions = _setup()
    world = WorldModel(BASE)
    endpoints = [ORDERS]
    without = await DeterministicSelector().next_actions(world, endpoints, sessions)
    with_det = await DeterministicSelector(detector_names={"open_redirect"}).next_actions(
        world, endpoints, sessions)
    assert not any(isinstance(a, RunDetector) for a in without)
    assert any(isinstance(a, RunDetector) and a.detector == "open_redirect" for a in with_det)
    await store.aclose_all()


def test_llm_schema_parses_run_detector():
    raw = json.dumps([{"action": "run_detector", "detector": "cors", "method": "GET",
                       "path_template": "/api/x", "actor_name": "user_A",
                       "rationale": "CORS yansıması"}])
    actions = _parse_actions(raw)
    assert len(actions) == 1
    assert isinstance(actions[0], RunDetector)
    assert actions[0].detector == "cors" and actions[0].endpoint.path_template == "/api/x"
