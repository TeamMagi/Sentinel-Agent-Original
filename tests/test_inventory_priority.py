"""Faz 5 / T4 — öncelik planı testleri (saf, ağsız).

Sınıf sırası, aynı sınıf içinde kararlılık, delta filtreleme ve boş delta durumları
kanıtlanır. Hiçbir test verdict üretmez; yalnızca_change verisinden sıra kurulur.
"""
from pentestai.inventory.models import ChangeCategory, InventoryChange
from pentestai.inventory.priority import HIGH_RISK_HINTS, endpoint_key, is_high_risk, prioritize
from pentestai.models import Endpoint


def _endpoint(path: str, *, method: str = "GET", id_param: str | None = None) -> Endpoint:
    return Endpoint(
        method=method,
        path_template=path,
        id_param=id_param or "id",
    )


def _change(path: str, category: ChangeCategory, *, priority: int = 100,
            method: str = "GET") -> InventoryChange:
    return InventoryChange(
        category=category,
        key=f"{method.upper()} {path}",
        detail="test değişikliği",
        priority=priority,
    )


def _paths(endpoints: list[Endpoint]) -> list[str]:
    return [endpoint.path_template for endpoint in endpoints]


def test_full_mode_class_order_and_stable_within_class():
    # Liste SIRASI bilinçli olarak sınıf sırasıyla ters: kararlı sıralama beklenir.
    endpoints = [
        _endpoint("/plain"), _endpoint("/high/admin"), _endpoint("/stale"),
        _endpoint("/changed"), _endpoint("/new"), _endpoint("/returned"),
        _endpoint("/opened"), _endpoint("/plain2"),
    ]
    changes = [
        _change("/plain2", ChangeCategory.NEW),
        _change("/stale", ChangeCategory.STALE),
        _change("/changed", ChangeCategory.CHANGED),
        _change("/new", ChangeCategory.NEW),
        _change("/returned", ChangeCategory.RETURNED),
        _change("/opened", ChangeCategory.AUTH_CHANGED, priority=1),
        _change("/plain", ChangeCategory.AUTH_CHANGED, priority=4),  # erişim kapandı
    ]

    result = prioritize(endpoints, changes, "full")

    # NEW > RETURNED/açılan auth > CHANGED > yüksek risk > STALE > diğerleri.
    assert _paths(result) == [
        "/new", "/plain2", "/returned", "/opened", "/changed", "/high/admin", "/stale", "/plain",
    ]


def test_shape_change_with_priority_one_stays_in_changed_class():
    endpoints = [_endpoint("/stale"), _endpoint("/shape"), _endpoint("/opened")]
    changes = [
        _change("/shape", ChangeCategory.SHAPE_CHANGED, priority=1),  # hassas alan eklendi
        _change("/opened", ChangeCategory.AUTH_CHANGED, priority=1),
        _change("/stale", ChangeCategory.STALE),
    ]

    assert _paths(prioritize(endpoints, changes, "full")) == ["/opened", "/shape", "/stale"]


def test_high_risk_hints_are_case_insensitive_segment_substrings():
    endpoints = [
        _endpoint("/API/UserProfile"), _endpoint("/billing/orders"),
        _endpoint("/public/health"), _endpoint("/items/{id}", id_param="id"),
    ]

    assert is_high_risk(endpoints[0]) is True
    assert is_high_risk(endpoints[1]) is True
    assert is_high_risk(endpoints[2]) is False
    assert is_high_risk(endpoints[3]) is True   # id parametresi yeterli
    assert "reset" in HIGH_RISK_HINTS and "coupon" in HIGH_RISK_HINTS
    assert _paths(prioritize(endpoints, [], "full")) == [
        "/API/UserProfile", "/billing/orders", "/items/{id}", "/public/health",
    ]


def test_method_is_part_of_change_key():
    change = _change("/api/orders", ChangeCategory.NEW, method="POST")
    get_only = [_endpoint("/api/orders", method="GET")]
    post_only = [_endpoint("/api/orders", method="POST")]

    assert endpoint_key(post_only[0]) == "POST /api/orders"
    assert prioritize(get_only, [change], "delta") == []
    assert _paths(prioritize(post_only, [change], "delta")) == ["/api/orders"]


def test_delta_keeps_only_changed_categories_and_orders_by_class():
    endpoints = [
        _endpoint("/plain"), _endpoint("/stale"), _endpoint("/closed"),
        _endpoint("/new"), _endpoint("/missing"),
    ]
    changes = [
        _change("/plain", ChangeCategory.AUTH_CHANGED, priority=4),   # delta'da kalır, sınıf 5
        _change("/stale", ChangeCategory.STALE),
        _change("/new", ChangeCategory.NEW),
        _change("/missing", ChangeCategory.MISSING),                 # gözlemde olsa bile delta dışı
    ]

    assert _paths(prioritize(endpoints, changes, "delta")) == [
        "/new", "/stale", "/plain",
    ]


def test_empty_delta_returns_empty_list():
    endpoints = [_endpoint("/a"), _endpoint("/b")]

    assert prioritize(endpoints, [], "delta") == []
    assert prioritize(endpoints, [_change("/missing", ChangeCategory.MISSING)], "delta") == []
    assert _paths(prioritize(endpoints, [], "full")) == ["/a", "/b"]


def test_prioritize_does_not_mutate_input():
    endpoints = [_endpoint("/a"), _endpoint("/b")]
    original = list(endpoints)

    prioritize(endpoints, [_change("/b", ChangeCategory.NEW)], "delta")

    assert endpoints == original
