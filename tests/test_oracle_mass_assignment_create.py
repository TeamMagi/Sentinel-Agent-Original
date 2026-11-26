"""Oluşturma anı mass assignment oracle'ı — ağsız (httpx.MockTransport)."""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from pentestai.bench.twin_base import BASE
from pentestai.config import load_endpoints
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import CreateMassAssignmentOracle
from pentestai.oracle.mass_assignment_create import render_body_template
from pentestai.planner import HypothesisGenerator
from pentestai.policy import PolicyEngine

TEMPLATE: dict[str, Any] = {"username": "snt_{rand}", "password": "P{rand}!",
                            "email": "snt_{rand}@example.com"}


def _ep(template: Any = TEMPLATE, readback: Any = ("/users/v1/_debug",)) -> Endpoint:
    return Endpoint(method="POST", path_template="/users/v1/register",
                    body_template=dict(template) if template else None,
                    readback_paths=list(readback))


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)


def _handler(
    *, admin: Callable[[dict[str, Any]], Any] = lambda b: bool(b.get("admin", False)),
    register_status: Callable[[dict[str, Any]], int] = lambda b: 200,
    store: bool = True, keep_fields: tuple[str, ...] = (),
) -> Callable[[httpx.Request], httpx.Response]:
    users: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/users/v1/register":
            body = json.loads(request.content)
            status = register_status(body)
            if status < 300 and store:
                rec: dict[str, Any] = {"username": body["username"], "admin": admin(body)}
                for k in keep_fields:
                    if k in body:
                        rec[k] = body[k]
                users.append(rec)
            return httpx.Response(status, json={"status": "x"})
        if request.url.path == "/users/v1/_debug":
            return httpx.Response(200, json={"users": users})
        return httpx.Response(404)

    return handler


async def _run(handler: Callable[[httpx.Request], httpx.Response], ep: Endpoint | None = None):
    store = SessionStore(transport=httpx.MockTransport(handler))
    actor = store.create(Actor(name="user_A",
                               auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"})))
    oracle = CreateMassAssignmentOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        return await oracle.run(ep or _ep(), actor)
    finally:
        await store.aclose_all()


async def test_vulnerable_confirmed() -> None:
    f = await _run(_handler())
    assert f.verdict == "CONFIRMED"
    assert f.parameter == "(create)" and f.type == "mass_assignment"
    assert f.evidence.positive_control and f.evidence.negative_control
    assert any("admin" in m for m in f.evidence.leaked_markers)
    assert "2 test kaydı oluşturuldu" in (f.triage_note or "")
    assert "Bearer <USER_A_TOKEN>" in f.evidence.repro_curl   # placeholder; ham token yok
    assert "TOKEN_A\"" not in f.evidence.repro_curl


async def test_hardened_rejected() -> None:
    f = await _run(_handler(admin=lambda b: False))
    assert f.verdict == "REJECTED"


async def test_near_miss_default_admin_not_confirmed() -> None:
    f = await _run(_handler(admin=lambda b: True))
    assert f.verdict != "CONFIRMED"
    assert f.verdict == "INCONCLUSIVE"
    assert "zaten ayrıcalıklı" in (f.triage_note or "")


async def test_attack_post_400_rejected() -> None:
    f = await _run(_handler(register_status=lambda b: 400 if "admin" in b else 200))
    assert f.verdict == "REJECTED"
    assert "reddetti" in (f.triage_note or "")


async def test_control_post_500_inconclusive() -> None:
    f = await _run(_handler(register_status=lambda b: 500))
    assert f.verdict == "INCONCLUSIVE"
    assert not f.evidence.positive_control


async def test_record_not_in_readback_inconclusive() -> None:
    f = await _run(_handler(store=False))
    assert f.verdict == "INCONCLUSIVE"
    assert "bulunamadı" in (f.triage_note or "")


async def test_no_body_template_inconclusive_and_no_hypothesis() -> None:
    ep = _ep(template=None)
    f = await _run(_handler(), ep)
    assert f.verdict == "INCONCLUSIVE"
    assert "test edilemez" in (f.triage_note or "")
    hyps = HypothesisGenerator().deterministic([ep])
    assert all(h.type != "mass_assignment_create" for h in hyps)
    no_readback = _ep(readback=())
    hyps = HypothesisGenerator().deterministic([no_readback])
    assert all(h.type != "mass_assignment_create" for h in hyps)


def test_planner_emits_hypothesis_with_template() -> None:
    hyps = HypothesisGenerator().deterministic([_ep()])
    assert [h.type for h in hyps].count("mass_assignment_create") == 1


async def test_password_redacted_in_evidence() -> None:
    f = await _run(_handler())
    for req in (f.evidence.baseline_request, f.evidence.attack_request):
        assert req is not None and req.body is not None
        body = json.loads(req.body)
        assert body["password"] == "<REDACTED>"
        assert b"snt_" in req.body                      # redaksiyon yalnız hassas alanı etkiler
    assert f.evidence.repro_curl and "<REDACTED>" in f.evidence.repro_curl


async def test_existing_template_key_not_overwritten() -> None:
    seen: list[dict[str, Any]] = []
    inner = _handler(keep_fields=("role",))

    def spy(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/users/v1/register":
            seen.append(json.loads(request.content))
        return inner(request)

    tpl = {**TEMPLATE, "role": "user"}
    f = await _run(spy, _ep(template=tpl))
    assert all(b["role"] == "user" for b in seen)
    assert f.verdict == "CONFIRMED"            # admin hâlâ yansıyor; role değil
    assert not any("role" in m for m in f.evidence.leaked_markers)


def test_render_body_template_nested_and_list() -> None:
    tpl = {"a": "x_{rand}", "n": {"b": ["{rand}", {"c": "{rand}-{rand}"}], "i": 5}, "k_{rand}": 1}
    out = render_body_template(tpl, "T1")
    assert out == {"a": "x_T1", "n": {"b": ["T1", {"c": "T1-T1"}], "i": 5}, "k_{rand}": 1}
    assert tpl["a"] == "x_{rand}"                  # şablon değişmez


def test_load_endpoints_reads_body_and_readback(tmp_path: Path) -> None:
    p = tmp_path / "e.yaml"
    p.write_text(
        "endpoints:\n  - method: POST\n    path_template: /r\n"
        "    body: {username: 'u_{rand}'}\n    readback: ['/dbg']\n"
        "  - method: GET\n    path_template: /g\n", encoding="utf-8")
    (ep, _), (ep2, _) = load_endpoints(str(p))
    assert ep.body_template == {"username": "u_{rand}"} and ep.readback_paths == ["/dbg"]
    assert ep2.body_template is None and ep2.readback_paths == []


@pytest.mark.parametrize("yaml_text", [
    "endpoints:\n  - path_template: /r\n    body: [1, 2]\n",
    "endpoints:\n  - path_template: /r\n    readback: '/dbg'\n",
    "endpoints:\n  - path_template: /r\n    readback: [1, 2]\n",
])
def test_load_endpoints_bad_types_raise(tmp_path: Path, yaml_text: str) -> None:
    p = tmp_path / "e.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    with pytest.raises(ValueError):
        load_endpoints(str(p))
