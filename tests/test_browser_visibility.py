"""T3 — görünürlük haritası, RBAC adayları ve own-id toplama (saf, ağsız)."""
from pentestai.models import OwnObjectIds
from pentestai.recon.browser import (
    CapturedCall,
    OwnIdHarvester,
    TrafficToEndpoints,
    VisibilityMap,
)

BASE = "http://localhost:3000"
CONVERTER = TrafficToEndpoints(["localhost"])


def _call(method: str, path: str, **kwargs: object) -> CapturedCall:
    return CapturedCall(method=method, url=BASE + path, **kwargs)  # type: ignore[arg-type]


def _map() -> VisibilityMap:
    matrix = VisibilityMap()
    matrix.add("admin", [
        _call("GET", "/api/admin/users", status=200, content_type="application/json"),
        _call("GET", "/api/orders", status=200, content_type="application/json"),
        _call("POST", "/api/admin/users/7", aborted=True),
    ], CONVERTER)
    matrix.add("user", [
        _call("GET", "/api/orders", status=200, content_type="application/json"),
    ], CONVERTER)
    return matrix


def test_admin_only_endpoint_is_candidate_with_visible_and_hidden_roles():
    candidates = _map().rbac_candidates()
    assert len(candidates) == 2   # GET /api/admin/users + abort edilen POST
    item = next(c for c in candidates if c.method == "GET")
    assert (item.method, item.path_template) == ("GET", "/api/admin/users")
    assert item.visible_to == ["admin"]
    assert item.hidden_from == ["user"]


def test_endpoint_seen_by_all_roles_is_not_a_candidate():
    matrix = _map()
    key = ("GET", "/api/orders")
    assert key in matrix.seen_by("admin")
    assert key in matrix.seen_by("user")
    assert key not in matrix.exclusive_to("admin")
    assert ("GET", "/api/admin/users") in matrix.exclusive_to("admin")
    assert {item.path_template for item in matrix.rbac_candidates()} == {
        "/api/admin/users", "/api/admin/users/{id}",
    }


def test_aborted_admin_post_counts_as_visible():
    matrix = _map()
    assert ("POST", "/api/admin/users/{id}") in matrix.seen_by("admin")
    assert ("POST", "/api/admin/users/{id}") in matrix.exclusive_to("admin")


def test_privileged_filter_drops_candidates_visible_to_unprivileged_roles():
    matrix = _map()
    assert len(matrix.rbac_candidates(privileged=["admin"])) == 2
    assert matrix.rbac_candidates(privileged=["user"]) == []

    mixed = VisibilityMap()
    mixed.add("admin", [_call("GET", "/api/reports", content_type="application/json")], CONVERTER)
    mixed.add("user", [_call("GET", "/api/reports", content_type="application/json")], CONVERTER)
    mixed.add("manager", [], CONVERTER)
    assert len(mixed.rbac_candidates()) == 1
    assert mixed.rbac_candidates(privileged=["admin"]) == []


def test_to_rbac_policy_default_allow_and_explicit_rule():
    policy = _map().to_rbac_policy()
    assert policy.default == "allow"
    assert len(policy.rules) == 2
    rule = next(r for r in policy.rules if r.method == "GET")
    assert (rule.method, rule.path, rule.allow) == ("GET", "/api/admin/users", ["admin"])
    # Kuralı olmayan uç: default=allow → None → RBAC taraması test etmez (FP güvenliği).
    assert policy.expected_roles("GET", "/api/orders") is None
    expected = policy.expected_roles("GET", "/api/admin/users")
    assert expected is not None
    assert expected[0] == frozenset({"admin"}) and expected[1] == "explicit"


def test_harvest_path_id_uses_endpoint_resource_key():
    calls = [_call("GET", "/api/orders/42", status=200, content_type="application/json")]
    assert OwnIdHarvester().harvest(calls, CONVERTER) == {"order": "42"}

    versioned = [_call("GET", "/api/v1/orders/42", status=200, content_type="application/json")]
    assert OwnIdHarvester().harvest(versioned, CONVERTER) == {"order": "42"}


def test_harvest_single_object_response_id_and_resource_id_field():
    calls = [
        _call("GET", "/api/orders", status=200, content_type="application/json",
              response_json={"id": 77, "name": "sipariş"}),
        _call("GET", "/api/baskets", status=200, content_type="application/json",
              response_json={"basketId": "b-1"}),
    ]
    harvested = OwnIdHarvester().harvest(calls, CONVERTER)
    assert harvested == {"order": "77", "basket": "b-1"}


def test_harvest_ignores_list_responses_and_first_seen_wins():
    calls = [
        _call("GET", "/api/orders", status=200, content_type="application/json",
              response_json=[{"id": "yabancı-1"}, {"id": "yabancı-2"}]),
        _call("GET", "/api/orders/5", status=200, content_type="application/json",
              response_json={"id": "başkası"}),
    ]
    harvested = OwnIdHarvester().harvest(calls, CONVERTER)
    assert harvested == {"order": "5"}


def test_harvest_skips_non_success_and_non_api_calls():
    calls = [
        _call("GET", "/api/orders", status=403, content_type="application/json",
              response_json={"id": "hata"}),
        _call("GET", "/api/baskets", status=200, content_type="text/html",
              response_json={"id": "html"}),
    ]
    assert OwnIdHarvester().harvest(calls, CONVERTER) == {}


def test_merge_into_config_priority_and_added_keys():
    actor_ids = OwnObjectIds({"orders": "config-id"})
    added = OwnIdHarvester.merge_into(actor_ids, {"order": "yeni-id", "basket": "b-1"})
    assert added == ["basket"]
    assert actor_ids["order"] == "config-id"
    assert actor_ids["basket"] == "b-1"


def test_drop_shared_removes_same_resource_id_from_both_actors():
    per_actor = {
        "admin": {"order": "1", "basket": "a"},
        "user": {"order": "1", "basket": "b"},
    }
    result = OwnIdHarvester.drop_shared(per_actor)
    assert result == {"admin": {"basket": "a"}, "user": {"basket": "b"}}
    assert per_actor["admin"]["order"] == "1"   # saflık: girdi değişmez
