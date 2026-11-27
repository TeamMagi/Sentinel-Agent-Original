"""Hipotez önceliklendirme + bütçe payı + bütçe dökümü (ağsız, MockTransport).

Sorun: planner uç-öncelikli üretir; 2000 isteklik bütçe ilk birkaç ucun düşük değerli testlerine
(cors/crlf/open_redirect/path_traversal) gidip erişim-kontrolü testlerini hiç koşturmuyordu.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Hypothesis, Scope
from pentestai.net import BudgetTracker, SessionStore
from pentestai.planner import HypothesisGenerator
from pentestai.prioritize import LOW_VALUE_TYPES, HypothesisPrioritizer, tier_of
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def _h(type_: str, path: str = "/rest/x") -> Hypothesis:
    return Hypothesis(type=type_, endpoint=Endpoint(method="GET", path_template=path), rationale="r")


def test_access_control_runs_before_low_value_even_on_later_endpoints():
    # Uç-öncelikli planner çıktısı: 30 id'siz ucun düşük-değerli testleri, EN SONDA id'li uç.
    eps = [Endpoint(method="GET", path_template=f"/rest/p{i}") for i in range(30)]
    eps.append(Endpoint(method="GET", path_template="/rest/basket/{id}"))
    hyps = HypothesisGenerator().deterministic(eps)
    ordered = HypothesisPrioritizer().order(hyps)
    first_low = next(i for i, h in enumerate(ordered) if h.type in LOW_VALUE_TYPES)
    idor_idx = next(i for i, h in enumerate(ordered)
                    if h.type == "idor" and h.endpoint.path_template == "/rest/basket/{id}")
    jwt_idx = next(i for i, h in enumerate(ordered)
                   if h.type == "jwt_privilege_escalation"
                   and h.endpoint.path_template == "/rest/basket/{id}")
    assert idor_idx < first_low and jwt_idx < first_low
    # Sıralama hipotez kaybettirmez (kırpma kapalıyken).
    assert len(ordered) == len(hyps)


def test_tiers_are_monotonic():
    hyps = [_h(t) for t in ("cors", "idor", "injection", "ssrf", "open_redirect", "bfla")]
    tiers = [tier_of(h.type) for h in HypothesisPrioritizer().order(hyps)]
    assert tiers == sorted(tiers)


def test_round_robin_spreads_types_within_low_tier():
    hyps = [_h("cors", f"/a{i}") for i in range(3)] + [_h("crlf_injection", f"/b{i}") for i in range(3)]
    ordered = HypothesisPrioritizer().order(hyps)
    assert [h.type for h in ordered[:2]] == ["cors", "crlf_injection"]
    # Tip içi özgün sıra korunur.
    assert [h.endpoint.path_template for h in ordered if h.type == "cors"] == ["/a0", "/a1", "/a2"]


def test_low_value_cap_trims_only_low_tier():
    hyps = ([_h("cors", f"/a{i}") for i in range(8)]
            + [_h("idor", f"/o{i}/{{id}}") for i in range(8)]
            + [_h("injection", f"/i{i}/{{id}}") for i in range(8)])
    ordered = HypothesisPrioritizer(low_value_cap=3).order(hyps)
    assert sum(h.type == "cors" for h in ordered) == 3
    assert sum(h.type == "idor" for h in ordered) == 8        # yüksek değer ASLA kırpılmaz
    assert sum(h.type == "injection" for h in ordered) == 8


def test_id_endpoints_first_within_tier_and_input_not_mutated():
    hyps = [_h("unauthorized_access", "/plain"), _h("unauthorized_access", "/obj/{id}")]
    snapshot = list(hyps)
    ordered = HypothesisPrioritizer().order(hyps)
    assert ordered[0].endpoint.path_template == "/obj/{id}"
    assert hyps == snapshot


def test_unknown_type_is_not_dropped():
    assert tier_of("something_new") == 1


def test_derived_low_value_cap_scales_with_budget():
    assert HypothesisPrioritizer.derive_low_value_cap(2000) == 10
    assert HypothesisPrioritizer.derive_low_value_cap(10) == 5


def test_budget_tracker_breakdown_by_label():
    b = BudgetTracker(max_total_requests=100, max_wall_clock_sec=None)
    b.check_and_count()
    with b.label("faz/a"):
        b.check_and_count()
        b.check_and_count()
        with b.label("faz/b"):
            b.check_and_count()
        b.check_and_count()
    assert b.breakdown() == {"faz/a": 3, "diğer": 1, "faz/b": 1}
    assert b.total == 5


def _handler(request):
    return httpx.Response(200, json={"id": "1"})


@pytest.mark.asyncio
async def test_low_value_share_defers_low_tier_but_runs_access_control():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_methods=["GET", "HEAD"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_total_requests=400, max_rps_per_host=1000))
    scanner.low_value_budget_share = 0.05   # 20 istek
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"basket": "1"}))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"}),
                           own_object_ids={"basket": "2"}))
    scanner.anon = store.create(Actor(name="anonymous", role="anonymous"))
    eps = [Endpoint(method="GET", path_template=f"/rest/p{i}") for i in range(20)]
    eps.append(Endpoint(method="GET", path_template="/rest/basket/{id}"))
    hyps = scanner.prioritizer.order(HypothesisGenerator().deterministic(eps))
    await scanner.run_hypotheses([A, B], hyps)
    breakdown = scanner.replayer.budget.breakdown()
    assert breakdown.get("hipotez/idor", 0) > 0
    low_spent = sum(breakdown.get(f"hipotez/{t}", 0) for t in LOW_VALUE_TYPES)
    assert low_spent < 20 + 30            # pay + son hipotezin taşması
    assert scanner.deferred_low_value        # kalanlar ertelendi ve raporlanabilir
    await store.aclose_all()
