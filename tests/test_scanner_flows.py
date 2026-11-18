"""Scanner.run_flows uçtan uca (ağsız): config-tabanlı akışlar gerçek oracle'ları koşar.

Amaç: config/flows.yaml ile tanımlanan iş mantığı akışının Scanner boru hattından tetiklenip
CONFIRMED üretmesi (aksi halde oracle "orphan" — canlı tarama bulmaz), ve destructive_tests
kapalıyken yazma yapan ailelerin ATLANMASI (bulgu yok)."""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.models.flows import BusinessLogicFlow, FlowConfig
from pentestai.net import SessionStore
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _negative_amount_app():
    """Satın alma bakiyeyi düşürmeli; negatif miktar bakiyeyi ARTIRIR (savunmasız)."""
    state = {"balance": 100}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"balance": state["balance"]})
        qty = json.loads(request.content or b"{}").get("quantity")
        if isinstance(qty, bool) or not isinstance(qty, int):
            return httpx.Response(400, json={"error": "sayı olmalı"})
        state["balance"] -= qty * 10          # negatif qty → bakiye artar (değişmez ihlali)
        return httpx.Response(200, json={"ok": True})

    return handler


def _flow() -> FlowConfig:
    ep = Endpoint(method="POST", path_template="/api/accounts/{id}/orders", id_param="id")
    return FlowConfig(business_logic=[BusinessLogicFlow(
        kind="negative_amount", endpoint=ep, state_path="/api/accounts/{id}",
        state_field="balance", amount_field="quantity", expected_direction="decrease",
        bad_value=-5, resource_key="account", actor="user_A")])


async def _run(scope: Scope):
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_negative_amount_app()))
    A = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer T"}),
                           own_object_ids={"account": "A-1"}))
    findings = await scanner.run_flows([A], _flow())
    await store.aclose_all()
    await scanner.aclose()
    return findings


@pytest.mark.asyncio
async def test_run_flows_negative_amount_confirmed():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "POST"], destructive_tests=True)
    findings = await _run(scope)
    confirmed = [f for f in findings if f.type == "negative_amount" and f.verdict == "CONFIRMED"]
    assert confirmed, "iş mantığı akışı CONFIRMED bekleniyordu (run_flows kablolu değil?)"
    assert all(f.victim and f.attacker for f in confirmed)   # R-B1 etiket


@pytest.mark.asyncio
async def test_run_flows_skips_without_destructive():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "POST"], destructive_tests=False)
    findings = await _run(scope)
    assert not findings, "destructive_tests kapalıyken yazma yapan akış atlanmalıydı"


@pytest.mark.asyncio
async def test_run_flows_bos_config_bos_sonuc():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "POST"], destructive_tests=True)
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_negative_amount_app()))
    A = store.create(Actor(name="user_A"))
    findings = await scanner.run_flows([A], FlowConfig())
    await store.aclose_all()
    await scanner.aclose()
    assert findings == []
