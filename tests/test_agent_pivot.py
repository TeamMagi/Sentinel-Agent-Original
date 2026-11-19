"""Agentic loop'ta CONFIRMED → pivot (Teslimat B).

Klasik zincirleme: /api/orders/{id} IDOR CONFIRMED → cevaptaki 'profileId'den
/api/profiles/{id} türetilir (başlangıç recon'unda YOK) → orada da IDOR CONFIRMED.
Ağsız (httpx.MockTransport); LLM yok — pivot deterministik expander + selector ile çalışır.
"""
from collections import deque

import httpx
import pytest

from pentestai.models import (
    Actor,
    AuthState,
    Endpoint,
    Evidence,
    Finding,
    Hypothesis,
    NormalizedResponse,
    Scope,
)
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import (
    BflaOracle,
    BoplaOracle,
    IdorOracle,
    InjectionOracle,
    StateChangingOracle,
)
from pentestai.orchestrator.agent import AgenticOrchestrator
from pentestai.orchestrator.executor import ActionExecutor
from pentestai.orchestrator.selectors import DeterministicSelector
from pentestai.orchestrator.world_model import WorldModel
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
ORDERS_EP = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
PROFILES_EP = Endpoint(method="GET", path_template="/api/profiles/{id}", id_param="id")

ORDERS = {
    "A1": {"id": "A1", "email": "alice@test.local", "profileId": "P-A"},
    "B1": {"id": "B1", "email": "bob@test.local", "profileId": "P-B"},
}
PROFILES = {
    "P-A": {"id": "P-A", "email": "alice@test.local", "phone": "5550001111"},
    "P-B": {"id": "P-B", "email": "bob@test.local", "phone": "5550002222"},
}
def app_handler(request):
    path = request.url.path
    if path.startswith("/api/orders/"):
        oid = path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=ORDERS[oid]) if oid in ORDERS else httpx.Response(404, json={})
    if path.startswith("/api/profiles/"):
        pid = path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=PROFILES[pid]) if pid in PROFILES else httpx.Response(404, json={})
    return httpx.Response(404, json={})


def _oracles(replayer):
    return {
        "idor": IdorOracle(replayer, BASE), "bfla": BflaOracle(replayer, BASE),
        "excessive_data_exposure": BoplaOracle(replayer, BASE),
        "injection": InjectionOracle(replayer, BASE),
        "state_change_authz": StateChangingOracle(replayer, BASE),
    }


def _setup(*, budget=None):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(app_handler))
    replayer = Replayer(PolicyEngine(scope), budget=budget)
    executor = ActionExecutor(replayer, _oracles(replayer), BASE)
    A = Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
              own_object_ids={"orders": "A1", "profiles": "P-A"})
    B = Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"}),
              own_object_ids={"orders": "B1", "profiles": "P-B"})
    sessions = {"user_A": store.create(A), "user_B": store.create(B)}
    return store, executor, sessions


def _confirmed(json_body) -> Finding:
    return Finding(
        id="F-001", type="idor", endpoint="/api/orders/{id}", method="GET", parameter="id",
        verdict="CONFIRMED", confidence="high",
        evidence=Evidence(attack_response=NormalizedResponse(status=200, json_body=json_body)),
    )


@pytest.mark.asyncio
async def test_selector_converts_frontier_hypothesis_to_action():
    """DeterministicSelector `frontier` paramı (Open/Closed): ek endpoint olmadan pivot aksiyonu."""
    sessions = {
        "user_A": _session("user_A", "P-A"),
        "user_B": _session("user_B", "P-B"),
    }
    h = Hypothesis(type="idor", endpoint=PROFILES_EP, source="deterministic",
                   rationale="pivot: CONFIRMED cevaptaki 'profile' referansından türetildi")
    sel = DeterministicSelector(frontier=deque([h]))
    actions = await sel.next_actions(WorldModel(), [], sessions)
    pivots = [a for a in actions if getattr(a, "endpoint", None) == PROFILES_EP]
    assert pivots and all(a.rationale.startswith("pivot:") for a in pivots)


@pytest.mark.asyncio
async def test_agentic_loop_discovers_pivot_endpoint():
    """CONFIRMED bulgu → expander → sonraki turda pivot endpoint'i denenir ve CONFIRMED olur."""
    store, executor, sessions = _setup()
    agent = AgenticOrchestrator(executor, [ORDERS_EP], llm=None, base_url=BASE,
                                max_iterations=40)
    state = await agent.run(sessions)

    confirmed = {(f.type, f.endpoint) for f in state.findings if f.verdict == "CONFIRMED"}
    assert ("idor", "/api/orders/{id}") in confirmed
    assert ("idor", "/api/profiles/{id}") in confirmed      # yalnızca pivot ile bulundu
    assert any("/api/profiles/{id}" in s.proposed_action for s in agent.trace.steps)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_trace_steps_carry_ranker_priority():
    """Ranker kararı görünür: çalıştırılan aksiyonların trace adımı havuz sırasını taşır."""
    store, executor, sessions = _setup()
    agent = AgenticOrchestrator(executor, [ORDERS_EP], llm=None, base_url=BASE,
                                max_iterations=40)
    await agent.run(sessions)
    priorities = [s.priority for s in agent.trace.steps if s.priority]
    assert priorities                                    # en az bir adımda öncelik kaydı var
    assert all(p.startswith("sıra ") for p in priorities)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_non_confirmed_finding_does_not_expand():
    store, executor, sessions = _setup()
    agent = AgenticOrchestrator(executor, [ORDERS_EP], llm=None, base_url=BASE)
    finding = _confirmed({"profileId": "P-A"})
    finding.verdict = "LIKELY"
    agent._absorb_finding(finding)
    assert list(agent._frontier) == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_duplicate_pivot_hypotheses_are_deduped():
    store, executor, sessions = _setup()
    agent = AgenticOrchestrator(executor, [ORDERS_EP], llm=None, base_url=BASE)
    finding = _confirmed({"profileId": "P-A"})
    agent._absorb_finding(finding)
    first = list(agent._frontier)
    agent._absorb_finding(finding)
    assert list(agent._frontier) == first       # aynı pivot iki kez eklenmez
    assert {(h.type, h.endpoint.path_template) for h in first} == {
        ("idor", "/api/profiles/{id}"),
        ("excessive_data_exposure", "/api/profiles/{id}"),
    }
    await store.aclose_all()


# --- yardımcılar ---

def _session(name: str, own_id: str):
    from types import SimpleNamespace
    return SimpleNamespace(actor=SimpleNamespace(
        name=name, role="user", own_object_ids={"profiles": own_id}))
