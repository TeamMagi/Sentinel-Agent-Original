"""İş mantığı oracle'ları: tüm yollar (CONFIRMED/LIKELY/REJECTED/INCONCLUSIVE), ağsız."""
from __future__ import annotations

import json

import httpx

from pentestai.bench.kolb.business_logic import (
    CouponReuseTwin,
    NegativeAmountTwin,
    WorkflowBypassTwin,
)
from pentestai.bench.twin_base import BASE
from pentestai.models import Actor, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle.business_logic import NegativeAmountOracle
from pentestai.policy import PolicyEngine


def _scope(destructive: bool = True) -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "POST"], destructive_tests=destructive)


async def _run(oracle_factory, twin, handler, *, destructive: bool = True):
    store = SessionStore(transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", own_object_ids={twin._KEY: twin._RID}))
    oracle = oracle_factory(Replayer(PolicyEngine(_scope(destructive))))
    try:
        return await oracle.run(twin._EP, session, session, resource_key=twin._KEY)
    finally:
        await store.aclose_all()


# --- negatif miktar ---

async def test_negative_confirmed_ve_kanit():
    t = NegativeAmountTwin()
    f = await _run(t._oracle, t, t._vuln())
    assert f.verdict == "CONFIRMED" and f.confidence == "high"
    assert "değişmez ihlali" in f.evidence.leaked_markers[0]
    assert f.evidence.positive_control and f.evidence.negative_control and f.evidence.baseline_stable
    assert f.evidence.restored is False and f.evidence.recovery_state
    assert "<ACTOR_TOKEN>" in f.evidence.repro_curl


async def test_negative_hardened_rejected():
    t = NegativeAmountTwin()
    f = await _run(t._oracle, t, t._hardened())
    assert f.verdict == "REJECTED"


async def test_negative_near_miss_dogru_yon_rejected():
    t = NegativeAmountTwin()
    f = await _run(t._oracle, t, t._near_miss())
    assert f.verdict == "REJECTED"


async def test_negative_kabul_ama_degismedi_likely():
    state = {"balance": 100}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"balance": state["balance"]})
        qty = json.loads(request.content).get("quantity")
        if not isinstance(qty, int):
            return httpx.Response(400, json={})
        if qty > 0:
            state["balance"] -= qty * 10
        return httpx.Response(200, json={"ok": True})     # negatif: kabul, etkisiz

    t = NegativeAmountTwin()
    f = await _run(t._oracle, t, handler)
    assert f.verdict == "LIKELY"


async def test_negative_destructive_kapali_inconclusive():
    t = NegativeAmountTwin()
    f = await _run(t._oracle, t, t._vuln(), destructive=False)
    assert f.verdict == "INCONCLUSIVE"
    assert "policy" in (f.triage_note or "")


async def test_negative_durum_okunamazsa_inconclusive():
    t = NegativeAmountTwin()
    f = await _run(t._oracle, t, lambda r: httpx.Response(500, json={}))
    assert f.verdict == "INCONCLUSIVE"


async def test_negative_pozitif_kontrol_yon_yanlissa_inconclusive():
    # beklenen yön "increase" verilirse meşru işlem (bakiye düşer) yönü doğrulamaz → verdict yok
    t = NegativeAmountTwin()

    def factory(rep):
        return NegativeAmountOracle(rep, BASE, state_path="/api/accounts/{id}", state_field="balance",
                                    amount_field="quantity", expected_direction="increase")

    f = await _run(factory, t, t._vuln())
    assert f.verdict == "INCONCLUSIVE" and not f.evidence.positive_control


async def test_negative_cop_deger_de_ters_oynatirsa_inconclusive():
    state = {"balance": 100}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"balance": state["balance"]})
        qty = json.loads(request.content).get("quantity")
        state["balance"] += 10 if not isinstance(qty, int) else -qty * 10   # çöp → bakiye artar
        return httpx.Response(200, json={})

    t = NegativeAmountTwin()
    f = await _run(t._oracle, t, handler)
    assert f.verdict == "INCONCLUSIVE" and not f.evidence.negative_control


# --- kupon ---

async def test_coupon_confirmed():
    t = CouponReuseTwin()
    f = await _run(t._oracle, t, t._vuln())
    assert f.verdict == "CONFIRMED"
    assert "ikinci" in f.evidence.leaked_markers[0]
    assert f.evidence.recovery_state


async def test_coupon_hardened_rejected():
    t = CouponReuseTwin()
    assert (await _run(t._oracle, t, t._hardened())).verdict == "REJECTED"


async def test_coupon_near_miss_rejected():
    t = CouponReuseTwin()
    f = await _run(t._oracle, t, t._near_miss())
    assert f.verdict == "REJECTED"
    assert "toplam değişmedi" in (f.triage_note or "")


async def test_coupon_gecersiz_kupon_da_indirirse_inconclusive():
    state = {"total": 100}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"total": state["total"]})
        state["total"] -= 10          # her kod geçerli sayılıyor
        return httpx.Response(200, json={})

    t = CouponReuseTwin()
    f = await _run(t._oracle, t, handler)
    assert f.verdict == "INCONCLUSIVE" and not f.evidence.negative_control


async def test_coupon_ilk_kullanim_etkisizse_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"total": 100})
        return httpx.Response(404, json={})

    t = CouponReuseTwin()
    f = await _run(t._oracle, t, handler)
    assert f.verdict == "INCONCLUSIVE" and not f.evidence.positive_control


async def test_coupon_destructive_kapali_inconclusive():
    t = CouponReuseTwin()
    f = await _run(t._oracle, t, t._vuln(), destructive=False)
    assert f.verdict == "INCONCLUSIVE"


async def test_coupon_ikinci_5xx_inconclusive():
    state = {"total": 100, "used": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"total": state["total"]})
        if json.loads(request.content).get("code") != "SAVE10":
            return httpx.Response(404, json={})
        if state["used"]:
            return httpx.Response(500, json={})
        state["used"] = True
        state["total"] -= 10
        return httpx.Response(200, json={})

    t = CouponReuseTwin()
    assert (await _run(t._oracle, t, handler)).verdict == "INCONCLUSIVE"


# --- iş akışı ---

async def test_workflow_confirmed():
    t = WorkflowBypassTwin()
    f = await _run(t._oracle, t, t._vuln())
    assert f.verdict == "CONFIRMED"
    assert "ön-koşul" in f.evidence.leaked_markers[0]


async def test_workflow_hardened_rejected():
    t = WorkflowBypassTwin()
    assert (await _run(t._oracle, t, t._hardened())).verdict == "REJECTED"


async def test_workflow_near_miss_rejected():
    t = WorkflowBypassTwin()
    f = await _run(t._oracle, t, t._near_miss())
    assert f.verdict == "REJECTED"


async def test_workflow_zaten_tamamlanmissa_inconclusive():
    t = WorkflowBypassTwin()
    f = await _run(t._oracle, t, lambda r: httpx.Response(200, json={"status": "completed"}))
    assert f.verdict == "INCONCLUSIVE"


async def test_workflow_bogus_kaynak_kabul_edilirse_inconclusive():
    # her id'ye 200 dönen sunucu: negatif kontrol geçmez → verdict yok
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "pending"})

    t = WorkflowBypassTwin()
    f = await _run(t._oracle, t, handler)
    assert f.verdict == "INCONCLUSIVE" and not f.evidence.negative_control


async def test_workflow_id_yoksa_inconclusive():
    t = WorkflowBypassTwin()
    store = SessionStore(transport=httpx.MockTransport(t._vuln()))
    session = store.create(Actor(name="user_A"))
    try:
        f = await t._oracle(Replayer(PolicyEngine(_scope()))).run(t._EP, session, session)
    finally:
        await store.aclose_all()
    assert f.verdict == "INCONCLUSIVE"


async def test_workflow_destructive_kapali_inconclusive():
    t = WorkflowBypassTwin()
    f = await _run(t._oracle, t, t._vuln(), destructive=False)
    assert f.verdict == "INCONCLUSIVE"


async def test_workflow_final_5xx_inconclusive():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/orders/O-1") and request.method == "POST":
            return httpx.Response(500, json={})
        if request.method == "POST":
            return httpx.Response(404, json={})
        return httpx.Response(200, json={"status": "pending"})

    t = WorkflowBypassTwin()
    assert (await _run(t._oracle, t, handler)).verdict == "INCONCLUSIVE"


async def test_hicbir_yanit_tek_basina_confirmed_degil():
    """Sunucu hep 'completed' iddia eder ama durum okuması pending → CONFIRMED asla."""
    t = WorkflowBypassTwin()
    f = await _run(t._oracle, t, t._near_miss())
    assert f.verdict != "CONFIRMED" and not f.evidence.leaked_markers
