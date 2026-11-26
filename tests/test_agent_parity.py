"""Faz 0 / Görev B — ajan modu (`--agent`) klasik taramayla parite. Ağsız (MockTransport).

Doğrulananlar: injection query/body param'ıyla (test_param) koşar ve sqli/nosqli bulguları
kaybolmaz; mass_assignment_create adaptörle bağlıdır; kuyrukta denenmemiş hipotez varken stall
çıkışı yoktur; max_iterations dolunca kısmi uyarı verilir; ajan yolunda `_record_tested`
çağrılır; planner'ın ürettiği her tip ajana bağlıdır (drift-guard).
"""
from __future__ import annotations

import json
from typing import Any, get_args

import httpx

from pentestai.models import (
    Actor,
    AuthState,
    BudgetConfig,
    Endpoint,
    Hypothesis,
    Scope,
)
from pentestai.net import SessionStore
from pentestai.orchestrator import AgenticOrchestrator
from pentestai.orchestrator.actions import RunOracle
from pentestai.orchestrator.selectors import AGENT_OUT_OF_SCOPE, DeterministicSelector
from pentestai.planner import HypothesisGenerator
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _scanner(*, destructive: bool = False) -> Scanner:
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"], destructive_tests=destructive)
    return Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))


def _sessions(handler) -> tuple[SessionStore, dict[str, Any]]:
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    a = store.create(Actor(name="user_A", role="user",
                           auth=AuthState(headers={"Authorization": "Bearer A"})))
    b = store.create(Actor(name="user_B", role="user",
                           auth=AuthState(headers={"Authorization": "Bearer B"})))
    return store, {"user_A": a, "user_B": b}


def _agent(scanner: Scanner, endpoints: list[Endpoint], **kw: Any) -> AgenticOrchestrator:
    return AgenticOrchestrator(scanner.executor, endpoints, planner=scanner.planner,
                               base_url=BASE, **kw)


# ---------------- B1: query/body param ile injection ----------------

async def test_agent_query_sqli_uses_param_and_keeps_sqli_finding() -> None:
    seen_params: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/products/search":
            q = request.url.params.get("q", "")
            seen_params.append(q)
            if "'" in q:
                return httpx.Response(500, text='SQLITE_ERROR: near "\'": syntax error')
            return httpx.Response(200, json={"data": []})
        return httpx.Response(404, json={})

    scanner = _scanner()
    store, sessions = _sessions(handler)
    ep = Endpoint(method="GET", path_template="/rest/products/search",
                  id_param="q", id_location="query")
    state = await _agent(scanner, [ep], max_iterations=30).run(sessions)
    await store.aclose_all()

    sqli = [f for f in state.findings if f.type == "sqli"]
    assert sqli and sqli[0].verdict == "CONFIRMED"          # xss tek başına değil
    assert sqli[0].parameter == "q"
    assert any("'" in v for v in seen_params)                # q query parametresi fuzz edildi
    # B4: ajan yolunda yüzey kaydı doldu
    assert "injection" in scanner.surface_tested.get(("GET", "/rest/products/search"), set())


async def test_agent_body_nosqli_confirmed_via_boolean_differential() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/api/coupon/validate":
            try:
                v = json.loads(request.content or b"{}").get("coupon_code")
            except ValueError:
                v = None
            if isinstance(v, dict):
                if "$ne" in v and v["$ne"] is not None:
                    return httpx.Response(200, json={"coupon_code": "TRIAL10", "discount": 10})
                return httpx.Response(500, json={})
            return httpx.Response(500, json={})
        return httpx.Response(404, json={})

    scanner = _scanner(destructive=True)
    store, sessions = _sessions(handler)
    ep = Endpoint(method="POST", path_template="/api/coupon/validate",
                  id_param="coupon_code", id_location="body")
    state = await _agent(scanner, [ep], max_iterations=30).run(sessions)
    await store.aclose_all()

    nosql = [f for f in state.findings if f.type == "nosqli"]
    assert nosql and nosql[0].verdict == "CONFIRMED"


# ---------------- B2: mass_assignment_create adaptörle ----------------

async def test_agent_runs_mass_assignment_create_via_adapter() -> None:
    users: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/users/v1/register":
            try:
                body = json.loads(request.content)
            except ValueError:
                return httpx.Response(400, json={})      # gövdesiz sonda istekleri (anon vb.)
            users.append({"username": body.get("username"), "admin": bool(body.get("admin", False))})
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/users/v1/_debug":
            return httpx.Response(200, json={"users": users})
        return httpx.Response(404)

    scanner = _scanner(destructive=True)
    store, sessions = _sessions(handler)
    ep = Endpoint(method="POST", path_template="/users/v1/register",
                  body_template={"username": "snt_{rand}", "password": "P{rand}!",
                                 "email": "snt_{rand}@example.com"},
                  readback_paths=["/users/v1/_debug"])
    state = await _agent(scanner, [ep], max_iterations=30).run(sessions, verify=False)
    await store.aclose_all()

    mass = [f for f in state.findings if f.type == "mass_assignment"
            and f.parameter == "(create)"]
    assert mass and mass[0].verdict == "CONFIRMED"


# ---------------- B2: drift-guard ----------------

def test_every_planner_type_is_wired_into_agent() -> None:
    """Hypothesis.type'ın her değeri ajan oracle/dedektör kayıt defterinde ya da gerekçeli
    kapsam-dışı listesinde olmalı. Yeni tip eklenip ajana bağlanmazsa bu test kırılır."""
    scanner = _scanner()
    known = set(scanner.executor.oracles) | set(scanner.executor.detectors)
    missing = [t for t in get_args(Hypothesis.model_fields["type"].annotation)
               if t not in known and t not in AGENT_OUT_OF_SCOPE]
    assert not missing, f"ajana bağlanmayan hipotez tipleri: {missing}"
    assert all(AGENT_OUT_OF_SCOPE.values())          # her istisnanın gerekçesi dolu


def test_out_of_scope_entries_are_real_types() -> None:
    types = set(get_args(Hypothesis.model_fields["type"].annotation))
    assert set(AGENT_OUT_OF_SCOPE) <= types


async def test_every_deterministic_hypothesis_yields_an_agent_action() -> None:
    """Planner'ın örnek uç kümesinde ürettiği her tip, ajan seçicisinde ≥1 aksiyona dönüşür."""
    scanner = _scanner(destructive=True)
    store, sessions = _sessions(lambda r: httpx.Response(404))
    for key in ("orders", "search"):
        sessions["user_A"].actor.own_object_ids[key] = "A-1"
        sessions["user_B"].actor.own_object_ids[key] = "B-1"
    sessions["anonymous"] = store.create(Actor(name="anonymous", role="anonymous"))
    names = [n for n in sessions if n != "anonymous"]
    endpoints = [
        Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"),
        Endpoint(method="PUT", path_template="/api/orders/{id}", id_param="id"),
        Endpoint(method="GET", path_template="/api/search", id_param="q", id_location="query"),
        Endpoint(method="POST", path_template="/users/v1/register",
                 body_template={"username": "u_{rand}"}, readback_paths=["/users/v1/_debug"]),
    ]
    hyps = HypothesisGenerator().deterministic(endpoints)
    selector = DeterministicSelector(
        scanner.planner, detector_names=set(scanner.executor.detectors),
        oracle_names=set(scanner.executor.oracles))
    produced = {h.type for h in hyps}
    covered = {h.type for h in hyps if selector._actions_for(h, sessions, names, [])}
    uncovered = produced - covered - set(AGENT_OUT_OF_SCOPE)
    await store.aclose_all()
    # bfla yalnız admin oturumu varken aksiyona döner → bu örnekte beklenen tek boşluk
    assert uncovered <= {"bfla"}, f"aksiyona dönüşmeyen tipler: {uncovered}"


# ---------------- B3: stall / max_iterations ----------------

class _FixedSelector:
    """Her turda aynı sabit aday listesini döner (claim edilenler elenir)."""

    def __init__(self, actions: list[RunOracle]):
        self.actions = actions

    async def next_actions(self, world, endpoints, sessions):   # noqa: ANN001
        return list(self.actions)


def _fresh_actions(n: int) -> list[RunOracle]:
    ep = Endpoint(method="GET", path_template="/api/x/{id}", id_param="id")
    return [RunOracle(oracle="injection", endpoint=ep, victim_name="user_A",
                      attacker_name="user_A", param=f"p{i}", param_location="query")
            for i in range(n)]


async def test_no_stall_exit_while_untested_actions_remain() -> None:
    scanner = _scanner()
    store, sessions = _sessions(lambda r: httpx.Response(404, json={}))
    agent = _agent(scanner, [], max_iterations=100, batch=1, stall_limit=2)
    agent.selector = _FixedSelector(_fresh_actions(8))
    await agent.run(sessions, verify=False)
    await store.aclose_all()
    assert len(agent.trace.steps) == 8          # bulgu yok, ama kuyruk bitene dek devam
    assert agent.partial is False


async def test_max_iterations_sets_partial_with_untested_count() -> None:
    scanner = _scanner()
    store, sessions = _sessions(lambda r: httpx.Response(404, json={}))
    agent = _agent(scanner, [], max_iterations=3, batch=1, stall_limit=2)
    agent.selector = _FixedSelector(_fresh_actions(8))
    await agent.run(sessions, verify=False)
    await store.aclose_all()
    assert agent.partial is True
    assert agent.untested_hypotheses == 5
    assert "max_iterations" in (agent.stop_reason or "") and "5 hipotez" in agent.stop_reason


# ---------------- B4: on_tested ----------------

async def test_executor_calls_on_tested_only_when_oracle_produced_findings() -> None:
    calls: list[tuple[str, str]] = []
    scanner = _scanner()
    scanner.executor.on_tested = None
    for strategy in scanner.executor._strategies.values():
        strategy.on_tested = lambda ep, t: calls.append((ep.path_template, t))
    store, sessions = _sessions(lambda r: httpx.Response(200, json={"ok": True}))
    action = _fresh_actions(1)[0]
    obs = await scanner.executor.execute(action, sessions)
    await store.aclose_all()
    assert obs.findings and calls == [("/api/x/{id}", "injection")]
    assert len(obs.findings) >= 2        # xss/sqli/nosqli/ssti/lfi birlikte korunur
