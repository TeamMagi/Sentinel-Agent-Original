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
VALID_RESET_TOKEN = "tok-abc12345"
BOGUS_RESET_TOKEN = "tok-bogus0000"
VALID_OTP = "445566"
BOGUS_OTP = "000000"


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


# --- Hesap ele geçirme: reset-token + OTP tekrar-kullanımı (config → request_builder) ---

def _account_takeover_app():
    """Reset token'ı ve OTP'yi süresiz kabul eden savunmasız hedef (tekrar-kullanım açık)."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        if request.url.path == "/api/reset-confirm":
            if body.get("token") != VALID_RESET_TOKEN:
                return httpx.Response(400, json={"error": "invalid token"})
            return httpx.Response(200, json={"success": True})
        if request.url.path == "/api/otp/verify":
            if body.get("otp") != VALID_OTP:
                return httpx.Response(400, json={"error": "invalid otp"})
            return httpx.Response(200, json={"success": True})
        return httpx.Response(404, json={"error": "not found"})

    return handler


def _account_takeover_flow() -> FlowConfig:
    """YAML'daki gibi dict'ten doğrula → discriminated union + builder alanları birlikte test edilir."""
    return FlowConfig.model_validate({
        "account_takeover": [
            {
                "kind": "password_reset_reuse",
                "endpoint": {"method": "POST", "path_template": "/api/reset-confirm"},
                "token_field": "token",
                "token": VALID_RESET_TOKEN,
                "bogus_token": BOGUS_RESET_TOKEN,
                "body_fields": {"newPassword": "NewP@ss1!"},
                "actor": "user_A",
            },
            {
                "kind": "otp_replay",
                "endpoint": {"method": "POST", "path_template": "/api/otp/verify"},
                "otp_field": "otp",
                "otp": VALID_OTP,
                "bogus_otp": BOGUS_OTP,
                "actor": "user_A",
            },
        ]
    })


async def _run_account_takeover(scope: Scope):
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_account_takeover_app()))
    A = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer T"})))
    findings = await scanner.run_flows([A], _account_takeover_flow())
    await store.aclose_all()
    await scanner.aclose()
    return findings


@pytest.mark.asyncio
async def test_run_flows_reset_token_ve_otp_replay_confirmed():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "POST"], destructive_tests=True)
    findings = await _run_account_takeover(scope)
    by_type = {f.type: f for f in findings}
    assert by_type["password_reset_abuse"].verdict == "CONFIRMED"
    assert by_type["mfa_bypass"].verdict == "CONFIRMED"      # OTP tekrar-kullanım bulgusu
    assert all(f.victim == "user_A" and f.attacker == "user_A" for f in findings)

    reset = by_type["password_reset_abuse"]
    assert VALID_RESET_TOKEN not in (reset.evidence.attack_request.body or b"").decode()
    assert VALID_RESET_TOKEN not in " ".join(reset.evidence.leaked_markers)
    otp = by_type["mfa_bypass"]
    assert VALID_OTP not in (otp.evidence.attack_request.body or b"").decode()
    assert VALID_OTP not in " ".join(otp.evidence.leaked_markers)


@pytest.mark.asyncio
async def test_run_flows_reset_otp_destructive_kapaliysa_atlanir():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "POST"], destructive_tests=False)
    findings = await _run_account_takeover(scope)
    assert not findings, "destructive_tests kapalıyken reset/OTP tekrar-kullanımı atlanmalıydı"


@pytest.mark.asyncio
async def test_run_flows_token_weakness_destructive_gerektirmez():
    """Zayıflık deseni ağ isteği yapmaz → destructive kapalıyken de koşar."""
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET"], destructive_tests=False)
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_account_takeover_app()))
    A = store.create(Actor(name="user_A"))
    flow = FlowConfig.model_validate({"account_takeover": [{
        "kind": "password_reset_weakness", "tokens": ["1234", "5678"], "min_samples": 2}]})
    findings = await scanner.run_flows([A], flow)
    await store.aclose_all()
    await scanner.aclose()
    assert [f.type for f in findings] == ["password_reset_abuse"]
    assert findings[0].verdict == "CONFIRMED"
