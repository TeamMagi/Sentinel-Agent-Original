"""RaceConditionOracle — TIER_C.md C4: TOCTOU race condition kanıtı.

`httpx.MockTransport` ile iki sahte backend simüle edilir: check-then-set arasında `await
asyncio.sleep` (TOCTOU penceresi) bırakan SAVUNMASIZ bir "kupon kullan" uç noktası, ve
check-and-set'i atomik yapan (kilit) GÜVENLİ bir sürümü. Network'süz (CLAUDE.md §6).
"""
import asyncio
from decimal import Decimal

import httpx
import pytest

from pentestai.cli import _build_race_state
from pentestai.models import Actor, Endpoint, Scope
from pentestai.net.race import RaceHarness
from pentestai.net.session_store import SessionStore
from pentestai.oracle import base
from pentestai.oracle.race_condition import RaceConditionOracle, RaceStateProbe
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="POST", path_template="/coupons/{id}/redeem", id_param="id")
COUNTER_EP = Endpoint(method="POST", path_template="/counter/{id}/inc", id_param="id")


def _vulnerable_redeem_handler():
    """TOCTOU: check (oku) ile set (yaz) arasında `await` var — N eşzamanlı istek HEPSİ
    'kullanılmamış' okur, HEPSİ başarılı olur (gerçek dünyadaki klasik kupon-çoklu-kullanım açığı)."""
    used = {"flag": False}

    async def handler(request):
        if used["flag"]:
            return httpx.Response(409, json={"error": "already used"})
        await asyncio.sleep(0.02)   # DB round-trip'i simüle eder — TOCTOU penceresi
        used["flag"] = True
        return httpx.Response(200, json={"ok": True})

    return handler


def _safe_redeem_handler():
    """Atomik check-and-set (kilit) — yalnızca BİR istek başarılı olabilir."""
    used = {"flag": False}
    lock = asyncio.Lock()

    async def handler(request):
        async with lock:
            if used["flag"]:
                return httpx.Response(409, json={"error": "already used"})
            used["flag"] = True
            return httpx.Response(200, json={"ok": True})

    return handler


def _already_used_handler():
    async def handler(request):
        return httpx.Response(409, json={"error": "already used"})

    return handler


def _scope(*, destructive_tests: bool = True) -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                allowed_methods=["GET", "POST"], destructive_tests=destructive_tests)


def _setup(handler, *, destructive_tests: bool = True, concurrency: int = 8,
           own_object_ids=None):
    store = SessionStore(transport=httpx.MockTransport(handler))
    ids = own_object_ids if own_object_ids is not None else {"coupons": "C-1"}
    A = Actor(name="user_A", own_object_ids=ids)
    session = store.create(A)
    harness = RaceHarness(PolicyEngine(_scope(destructive_tests=destructive_tests)))
    oracle = RaceConditionOracle(harness, BASE, concurrency=concurrency)
    return oracle, store, session


@pytest.mark.asyncio
async def test_confirmed_when_toctou_window_allows_multiple_success():
    oracle, store, session = _setup(_vulnerable_redeem_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers
    assert "8/8" in f.evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_properly_serialized():
    oracle, store, session = _setup(_safe_redeem_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.REJECTED
    assert not f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_resource_already_invalid():
    oracle, store, session = _setup(_already_used_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_victim_id_missing():
    oracle, store, session = _setup(_vulnerable_redeem_handler())
    session.actor.own_object_ids.clear()
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_destructive_tests_disabled():
    oracle, store, session = _setup(_vulnerable_redeem_handler(), destructive_tests=False)
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


# --- FP düzeltmesi + limit/state/atomiklik testleri ---

def _idempotent_handler():
    """Her istek 200 döner (idempotent) — eşzamanlı 2xx tek başına kanıt OLMAMALI."""
    async def handler(request):
        return httpx.Response(200, json={"ok": True})

    return handler


def _limited_redeem_handler(max_uses: int):
    """Atomik sayaç: yalnızca `max_uses` başarılı kullanıma izin verir."""
    used = {"count": 0}

    async def handler(request):
        if request.method != "POST":
            return httpx.Response(404)
        if used["count"] >= max_uses:
            return httpx.Response(409, json={"error": "limit"})
        used["count"] += 1
        return httpx.Response(200, json={"ok": True})

    return handler


def _toctou_wallet_handler():
    """TOCTOU kupon: her başarılı kullanım /wallet/W-1 bakiyesini 10 düşürür."""
    state = {"used": False, "balance": 100}

    async def handler(request):
        if request.url.path == "/wallet/W-1":
            return httpx.Response(200, json={"data": {"balance": state["balance"]}})
        if request.url.path == "/coupons/C-1/redeem":
            if state["used"]:
                return httpx.Response(409, json={"error": "already used"})
            await asyncio.sleep(0.02)   # TOCTOU penceresi
            state["used"] = True
            state["balance"] -= 10
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    return handler


def _cosmetic_wallet_handler():
    """POST hep 200 ama bakiye yalnız İLK istekte düşer — kozmetik başarı."""
    state = {"redeemed": False, "balance": 100}

    async def handler(request):
        if request.url.path == "/wallet/W-1":
            return httpx.Response(200, json={"data": {"balance": state["balance"]}})
        if request.url.path == "/coupons/C-1/redeem":
            if not state["redeemed"]:
                state["redeemed"] = True
                state["balance"] -= 10
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    return handler


def _lost_update_counter_handler():
    """Atomik olmayan read-modify-write: oku → bekle → yaz (+1)."""
    state = {"value": 0}

    async def handler(request):
        if request.url.path == "/counter/K-1" and request.method == "GET":
            return httpx.Response(200, json={"value": state["value"]})
        if request.url.path == "/counter/K-1/inc" and request.method == "POST":
            current = state["value"]
            await asyncio.sleep(0.02)   # okuma ile yazma arasında pencere
            state["value"] = current + 1
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    return handler


def _atomic_counter_handler():
    """Kilitli read-modify-write: tüm artışlar kaybolmadan uygulanır."""
    state = {"value": 0}
    lock = asyncio.Lock()

    async def handler(request):
        if request.url.path == "/counter/K-1" and request.method == "GET":
            return httpx.Response(200, json={"value": state["value"]})
        if request.url.path == "/counter/K-1/inc" and request.method == "POST":
            async with lock:
                state["value"] += 1
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    return handler


def _unstable_state_handler():
    reads = {"n": 0}

    async def handler(request):
        if request.method == "GET":
            reads["n"] += 1
            return httpx.Response(200, json={"value": reads["n"]})
        return httpx.Response(200, json={"ok": True})

    return handler


def _unreadable_state_handler():
    async def handler(request):
        if request.method == "GET":
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json={"ok": True})

    return handler


@pytest.mark.asyncio
async def test_inconclusive_when_endpoint_idempotent():
    oracle, store, session = _setup(_idempotent_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1", limit=1)
    assert f.verdict == base.INCONCLUSIVE
    assert f.evidence.negative_control is False
    assert "idempotent" in (f.triage_note or "")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_limit_respected():
    oracle, store, session = _setup(_limited_redeem_handler(3))
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1", limit=3)
    assert f.verdict == base.REJECTED
    assert "limit (3) aşılmadı" in (f.triage_note or "")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_limit_overrun_with_state():
    probe = RaceStateProbe(path="/wallet/W-1", field="data.balance", unit=Decimal("-10"))
    oracle, store, session = _setup(_toctou_wallet_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1",
                         limit=1, state=probe)
    assert f.verdict == base.CONFIRMED
    assert f.evidence.baseline_stable is True
    assert f.evidence.recovery_state is not None
    assert f.evidence.recovery_state["before"] == "100"
    assert f.evidence.recovery_state["after"] == "20"
    assert f.evidence.restored is False
    assert "limit 1 aşıldı" in f.evidence.leaked_markers[1]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_cosmetic_success_with_state():
    probe = RaceStateProbe(path="/wallet/W-1", field="data.balance", unit=Decimal("-10"))
    oracle, store, session = _setup(_cosmetic_wallet_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1",
                         limit=1, state=probe)
    assert f.verdict == base.REJECTED
    assert "kozmetik başarı" in (f.triage_note or "")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_lost_update_unlimited():
    probe = RaceStateProbe(path="/counter/K-1", field="value", unit=Decimal("1"))
    oracle, store, session = _setup(_lost_update_counter_handler(),
                                    own_object_ids={"counters": "K-1"})
    f = await oracle.run(COUNTER_EP, session, resource_key="counters", finding_id="F-1",
                         limit=None, state=probe)
    assert f.verdict == base.CONFIRMED
    assert any("kayboldu" in m for m in f.evidence.leaked_markers)
    assert f.evidence.recovery_state is not None
    assert f.evidence.restored is False
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_atomic_increment_unlimited():
    probe = RaceStateProbe(path="/counter/K-1", field="value", unit=Decimal("1"))
    oracle, store, session = _setup(_atomic_counter_handler(),
                                    own_object_ids={"counters": "K-1"})
    f = await oracle.run(COUNTER_EP, session, resource_key="counters", finding_id="F-1",
                         limit=None, state=probe)
    assert f.verdict == base.REJECTED
    assert "atomik" in (f.triage_note or "")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_state_unstable():
    probe = RaceStateProbe(path="/wallet/W-1", field="value", unit=Decimal("-10"))
    oracle, store, session = _setup(_unstable_state_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1",
                         limit=1, state=probe)
    assert f.verdict == base.INCONCLUSIVE
    assert "kararsız" in (f.triage_note or "")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_state_unreadable():
    probe = RaceStateProbe(path="/wallet/W-1", field="value", unit=Decimal("-10"))
    oracle, store, session = _setup(_unreadable_state_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1",
                         limit=1, state=probe)
    assert f.verdict == base.INCONCLUSIVE
    assert "durum okunamadı" in (f.triage_note or "")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_unlimited_without_state():
    oracle, store, session = _setup(_idempotent_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1", limit=None)
    assert f.verdict == base.INCONCLUSIVE
    assert "durum probu" in (f.triage_note or "")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_invalid_limit_raises():
    oracle, store, session = _setup(_idempotent_handler())
    with pytest.raises(ValueError):
        await oracle.run(EP, session, resource_key="coupons", limit=0)
    await store.aclose_all()


def test_state_probe_zero_unit_raises():
    with pytest.raises(ValueError):
        RaceStateProbe(path="/wallet/W-1", field="balance", unit=Decimal("0"))


def test_build_race_state_none_when_all_missing():
    assert _build_race_state(None, None, None) is None


def test_build_race_state_partial_raises():
    with pytest.raises(SystemExit):
        _build_race_state("/wallet/W-1", "balance", None)


def test_build_race_state_zero_unit_raises():
    with pytest.raises(SystemExit):
        _build_race_state("/wallet/W-1", "balance", "0")


@pytest.mark.asyncio
async def test_state_response_body_not_stored_in_evidence():
    """Redaction (CLAUDE.md §5): ham durum yanıtı evidence'a yazılmaz; marker'da tam sayı işlem."""
    probe = RaceStateProbe(path="/wallet/W-1", field="data.balance", unit=Decimal("-10"))
    oracle, store, session = _setup(_toctou_wallet_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1",
                         limit=1, state=probe)
    assert f.verdict == base.CONFIRMED
    assert f.evidence.baseline_response is None
    assert "8 işlem" in f.evidence.leaked_markers[1]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_state_path_needs_missing_id():
    probe = RaceStateProbe(path="/wallet/{id}", field="data.balance", unit=Decimal("-10"))
    oracle, store, session = _setup(_toctou_wallet_handler())
    no_id_ep = Endpoint(method="POST", path_template="/coupons/redeem", id_param="id")
    session.actor.own_object_ids.clear()
    f = await oracle.run(no_id_ep, session, resource_key="coupons", finding_id="F-1",
                         limit=1, state=probe)
    assert f.verdict == base.INCONCLUSIVE
    assert "{id}" in (f.triage_note or "")
    await store.aclose_all()
