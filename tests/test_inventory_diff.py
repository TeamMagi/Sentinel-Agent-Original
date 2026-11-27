"""Envanter fark (diff) motoru testleri — her kategori, sınırlar ve kayıt koruma kuralları.

Tüm testler saftır: ağ yok, dosya yok; saat ``NOW`` olarak dışarıdan verilir.
"""
from datetime import UTC, datetime, timedelta

from pentestai.inventory.diff import InventoryDiff, summarize
from pentestai.inventory.models import (
    ChangeCategory,
    EndpointObservation,
    InventoryChange,
    InventoryRecord,
)

NOW = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
KEY = "GET /api/users/{id}"


def _record(
    *,
    method: str = "GET",
    path: str = "/api/users/{id}",
    key: str | None = None,
    params: list[str] | None = None,
    auth_profile: dict[str, int] | None = None,
    response_shape: str | None = "shape-a",
    response_fields: list[str] | None = None,
    sources: list[str] | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    last_tested_days: int | None = 1,
    last_results: dict[str, str] | None = None,
    missing_streak: int = 0,
    removed: bool = False,
) -> InventoryRecord:
    return InventoryRecord(
        key=key or f"{method} {path}",
        method=method,
        path_template=path,
        params=["id"] if params is None else params,
        auth_profile={"admin": 200, "anon": 401} if auth_profile is None else auth_profile,
        response_shape=response_shape,
        response_fields=["id:int", "email:str"] if response_fields is None else response_fields,
        sources=["openapi"] if sources is None else sources,
        first_seen=NOW - timedelta(days=30) if first_seen is None else first_seen,
        last_seen=NOW - timedelta(days=1) if last_seen is None else last_seen,
        last_tested=None if last_tested_days is None else NOW - timedelta(days=last_tested_days),
        last_results={"idor": "CONFIRMED"} if last_results is None else last_results,
        missing_streak=missing_streak,
        removed=removed,
    )


def _obs(
    *,
    method: str = "GET",
    path: str = "/api/users/{id}",
    params: list[str] | None = None,
    auth_profile: dict[str, int] | None = None,
    response_shape: str | None = "shape-a",
    response_fields: list[str] | None = None,
    sources: list[str] | None = None,
) -> EndpointObservation:
    return EndpointObservation(
        method=method,
        path_template=path,
        params=["id"] if params is None else params,
        sources=["crawler"] if sources is None else sources,
        auth_profile={"admin": 200, "anon": 401} if auth_profile is None else auth_profile,
        response_shape=response_shape,
        response_fields=["id:int", "email:str"] if response_fields is None else response_fields,
    )


def _categories(changes: list[InventoryChange]) -> list[ChangeCategory]:
    return [change.category for change in changes]


# --- 1. ilk koşum ------------------------------------------------------------
def test_first_run_from_empty_previous_is_silent():
    result = InventoryDiff().compare({}, [_obs()], NOW)

    assert result.first_run is True
    assert result.changes == []
    record = result.records[KEY]
    assert record.first_seen == NOW
    assert record.last_seen == NOW


def test_first_run_flag_overrides_non_empty_previous():
    previous = {KEY: _record()}

    result = InventoryDiff().compare(previous, [_obs()], NOW, first_run=True)

    assert result.first_run is True
    assert result.changes == []
    assert result.records[KEY].first_seen == NOW - timedelta(days=30)


def test_non_empty_previous_is_not_first_run():
    result = InventoryDiff().compare({KEY: _record()}, [_obs()], NOW)

    assert result.first_run is False
    assert result.changes == []


# --- 2. NEW ------------------------------------------------------------------
def test_new_endpoint_has_priority_zero():
    previous = {KEY: _record()}
    result = InventoryDiff().compare(previous, [_obs(path="/api/orders")], NOW)

    new_changes = [c for c in result.changes if c.category == ChangeCategory.NEW]
    assert len(new_changes) == 1
    assert new_changes[0].priority == 0
    assert new_changes[0].key == "GET /api/orders"
    assert "GET /api/orders" in new_changes[0].detail
    assert "GET /api/orders" in result.records


def test_new_method_on_existing_path_mentions_note():
    previous = {
        "GET /api/users": _record(path="/api/users", params=[]),
    }
    observation = _obs(method="POST", path="/api/users", params=[])

    result = InventoryDiff().compare(previous, [observation], NOW)

    new_changes = [c for c in result.changes if c.category == ChangeCategory.NEW]
    assert len(new_changes) == 1
    assert "mevcut yol, yeni method" in new_changes[0].detail
    assert "GET" in new_changes[0].detail


def test_new_endpoint_is_not_marked_stale():
    previous = {KEY: _record()}
    result = InventoryDiff().compare(previous, [_obs(path="/api/orders")], NOW)

    stale_keys = [c.key for c in result.changes if c.category == ChangeCategory.STALE]
    assert "GET /api/orders" not in stale_keys


# --- 3. RETURNED -------------------------------------------------------------
def test_returned_resets_removed_and_streak():
    previous = {KEY: _record(removed=True, missing_streak=3, last_tested_days=None)}

    result = InventoryDiff().compare(previous, [_obs()], NOW)

    assert _categories(result.changes) == [ChangeCategory.RETURNED]
    assert result.changes[0].priority == 1
    record = result.records[KEY]
    assert record.removed is False
    assert record.missing_streak == 0


def test_returned_record_does_not_also_go_stale():
    previous = {KEY: _record(missing_streak=1, last_tested_days=None)}

    result = InventoryDiff().compare(previous, [_obs()], NOW)

    assert _categories(result.changes) == [ChangeCategory.RETURNED]


# --- 4. AUTH_CHANGED ---------------------------------------------------------
def test_anon_401_to_200_is_access_opened_warning():
    previous = {KEY: _record(auth_profile={"admin": 200, "anon": 401})}
    observation = _obs(auth_profile={"admin": 200, "anon": 200})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.AUTH_CHANGED]
    change = result.changes[0]
    assert change.priority == 1
    assert "anonymous: 401 → 200" in change.detail
    assert "UYARI" in change.detail
    assert "kanıt değil" in change.detail
    # Eski "anon" anahtarı kayda "anonymous" olarak normalize edilir.
    assert result.records[KEY].auth_profile["anonymous"] == 200


def test_200_to_403_is_access_closed():
    previous = {KEY: _record(auth_profile={"admin": 200, "anon": 200})}
    observation = _obs(auth_profile={"admin": 200, "anon": 403})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.AUTH_CHANGED]
    assert result.changes[0].priority == 4
    assert "erişim kapandı" in result.changes[0].detail


def test_200_to_201_is_ignored():
    previous = {KEY: _record(auth_profile={"admin": 200, "anon": 200})}
    observation = _obs(auth_profile={"admin": 200, "anon": 201})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert result.changes == []
    assert result.records[KEY].auth_profile["anonymous"] == 201


def test_500_to_502_is_ignored():
    previous = {KEY: _record(auth_profile={"admin": 500, "anon": 500})}
    observation = _obs(auth_profile={"admin": 502, "anon": 502})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert result.changes == []


def test_role_present_on_one_side_only_is_ignored():
    previous = {KEY: _record(auth_profile={"admin": 200})}
    observation = _obs(auth_profile={"admin": 200, "anon": 401})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert result.changes == []
    assert result.records[KEY].auth_profile == {"admin": 200, "anonymous": 401}


def test_other_status_change_has_priority_three():
    previous = {KEY: _record(auth_profile={"admin": 200})}
    observation = _obs(auth_profile={"admin": 404})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.AUTH_CHANGED]
    assert result.changes[0].priority == 3


def test_404_to_200_is_not_access_opened():
    previous = {KEY: _record(auth_profile={"admin": 200, "anon": 404})}
    observation = _obs(auth_profile={"admin": 200, "anon": 200})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.AUTH_CHANGED]
    assert result.changes[0].priority == 3


def test_403_to_200_is_access_opened():
    previous = {KEY: _record(auth_profile={"admin": 403})}
    observation = _obs(auth_profile={"admin": 200})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.AUTH_CHANGED]
    assert result.changes[0].priority == 1


def test_400_to_200_is_other_status_not_access_opened():
    previous = {KEY: _record(auth_profile={"admin": 400})}
    observation = _obs(auth_profile={"admin": 200})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.AUTH_CHANGED]
    assert result.changes[0].priority == 3


def test_429_involving_changes_are_ignored_as_transient():
    for old, new in ((429, 200), (200, 429), (429, 401), (401, 429)):
        previous = {KEY: _record(auth_profile={"admin": old})}
        observation = _obs(auth_profile={"admin": new})

        result = InventoryDiff().compare(previous, [observation], NOW)

        assert result.changes == [], (old, new)


def test_5xx_involving_changes_are_ignored_as_transient():
    for old, new in ((500, 200), (200, 503), (401, 500), (502, 200)):
        previous = {KEY: _record(auth_profile={"admin": old})}
        observation = _obs(auth_profile={"admin": new})

        result = InventoryDiff().compare(previous, [observation], NOW)

        assert result.changes == [], (old, new)


def test_legacy_anon_key_is_compared_as_anonymous():
    # Eski sqlite kaydı "anon" taşır; yeni gözlem "anonymous" kullanır → aynı rol sayılır.
    previous = {KEY: _record(auth_profile={"admin": 200, "anon": 401})}
    observation = _obs(auth_profile={"admin": 200, "anonymous": 200})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.AUTH_CHANGED]
    assert result.changes[0].priority == 1
    assert "anonymous: 401 → 200" in result.changes[0].detail
    assert result.records[KEY].auth_profile == {"admin": 200, "anonymous": 200}


# --- 5. CHANGED (params) -----------------------------------------------------
def test_params_added_and_removed_are_listed():
    previous = {KEY: _record(params=["id", "legacy"])}
    observation = _obs(params=["id", "verbose"])

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.CHANGED]
    change = result.changes[0]
    assert change.priority == 2
    assert "verbose" in change.detail
    assert "legacy" in change.detail
    assert result.records[KEY].params == ["id", "verbose"]


# --- 6. SHAPE_CHANGED --------------------------------------------------------
def test_shape_change_lists_added_fields():
    previous = {KEY: _record(response_shape="shape-a", response_fields=["id:int"])}
    observation = _obs(response_shape="shape-b", response_fields=["id:int", "name:str"])

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.SHAPE_CHANGED]
    change = result.changes[0]
    assert change.priority == 2
    assert "name" in change.detail


def test_sensitive_added_field_raises_priority_to_one():
    previous = {KEY: _record(response_shape="shape-a", response_fields=["id:int"])}
    observation = _obs(
        response_shape="shape-b",
        response_fields=["id:int", "email:str", "ssn:str"],
    )

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert _categories(result.changes) == [ChangeCategory.SHAPE_CHANGED]
    change = result.changes[0]
    assert change.priority == 1
    assert "hassas alan eklendi: email, ssn" in change.detail


def test_shape_none_on_one_side_is_ignored():
    previous = {KEY: _record(response_shape="shape-a", response_fields=["id:int"])}
    observation = _obs(response_shape=None, response_fields=[])

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert result.changes == []
    record = result.records[KEY]
    assert record.response_shape == "shape-a"
    assert record.response_fields == ["id:int"]


def test_shape_detail_truncates_long_field_lists():
    previous = {KEY: _record(response_shape="shape-a", response_fields=["id:int"])}
    new_fields = ["id:int"] + [f"field{i}:str" for i in range(10)]
    observation = _obs(response_shape="shape-b", response_fields=new_fields)

    result = InventoryDiff().compare(previous, [observation], NOW)

    change = result.changes[0]
    assert "... ve 2 alan daha" in change.detail


# --- 7. MISSING --------------------------------------------------------------
def test_missing_streak_increments_and_retires_after_three():
    diff = InventoryDiff(missing_retire_after=3)
    records = {KEY: _record()}
    details: list[str] = []

    for expected_streak in (1, 2, 3):
        result = diff.compare(records, [], NOW)
        missing = [c for c in result.changes if c.category == ChangeCategory.MISSING]
        assert len(missing) == 1
        assert missing[0].priority == 5
        record = result.records[KEY]
        assert record.missing_streak == expected_streak
        details.append(missing[0].detail)
        records = result.records

    assert records[KEY].removed is True
    assert "1. taramadır görülmedi" in details[0]
    assert "kaldırıldı sayıldı" in details[2]


def test_already_removed_record_produces_no_missing_change():
    previous = {KEY: _record(removed=True, missing_streak=3)}

    result = InventoryDiff().compare(previous, [], NOW)

    assert result.changes == []
    assert result.records[KEY].removed is True


def test_missing_record_stays_in_records_for_history():
    previous = {KEY: _record()}

    result = InventoryDiff().compare(previous, [], NOW)

    assert KEY in result.records
    assert result.records[KEY].missing_streak == 1


def test_incomplete_run_does_not_produce_missing_or_touch_streak():
    previous = {KEY: _record(missing_streak=1)}

    result = InventoryDiff().compare(previous, [], NOW, complete=False)

    assert result.changes == []
    record = result.records[KEY]
    assert record.missing_streak == 1
    assert record.removed is False
    # Girdi kaydı da mutasyona uğramaz (saf motor).
    assert previous[KEY].missing_streak == 1


def test_incomplete_run_still_reports_observed_changes():
    previous = {KEY: _record()}
    observation = _obs(auth_profile={"admin": 200, "anon": 200})

    result = InventoryDiff().compare(previous, [observation], NOW, complete=False)

    assert _categories(result.changes) == [ChangeCategory.AUTH_CHANGED]
    assert result.records[KEY].missing_streak == 0


# --- 8. STALE ----------------------------------------------------------------
def test_stale_boundary_is_fourteen_days():
    at_13 = InventoryDiff().compare(
        {KEY: _record(last_tested_days=13)}, [_obs()], NOW
    )
    at_14 = InventoryDiff().compare(
        {KEY: _record(last_tested_days=14)}, [_obs()], NOW
    )

    assert at_13.changes == []
    assert _categories(at_14.changes) == [ChangeCategory.STALE]
    assert at_14.changes[0].priority == 6


def test_never_tested_record_is_stale():
    previous = {KEY: _record(last_tested_days=None)}

    result = InventoryDiff().compare(previous, [_obs()], NOW)

    assert _categories(result.changes) == [ChangeCategory.STALE]
    assert "hiç test edilmedi" in result.changes[0].detail


def test_stale_does_not_update_last_tested():
    previous = {KEY: _record(last_tested_days=None)}

    result = InventoryDiff().compare(previous, [_obs()], NOW)

    assert result.records[KEY].last_tested is None


# --- 9. birleşik kategoriler ve sıralama -------------------------------------
def test_endpoint_can_have_auth_and_shape_changes_together():
    previous = {
        KEY: _record(
            auth_profile={"admin": 200, "anon": 401},
            response_shape="shape-a",
            response_fields=["id:int"],
        )
    }
    observation = _obs(
        auth_profile={"admin": 200, "anon": 200},
        response_shape="shape-b",
        response_fields=["id:int", "email:str"],
    )

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert set(_categories(result.changes)) == {
        ChangeCategory.AUTH_CHANGED,
        ChangeCategory.SHAPE_CHANGED,
    }
    assert all(change.key == KEY for change in result.changes)


def test_changes_are_sorted_by_priority_then_key():
    previous = {
        "GET /aaa": _record(path="/aaa"),
        "GET /zzz": _record(path="/zzz", last_tested_days=None),
    }
    observations = [
        _obs(path="/aaa", params=["id", "verbose"]),
        _obs(method="POST", path="/new", params=[]),
        _obs(path="/zzz"),
    ]

    result = InventoryDiff().compare(previous, observations, NOW)

    assert _categories(result.changes) == [
        ChangeCategory.NEW,
        ChangeCategory.CHANGED,
        ChangeCategory.STALE,
    ]


def test_equal_priority_changes_are_sorted_by_key():
    previous = {"GET /seed": _record(path="/seed")}

    result = InventoryDiff().compare(previous, [_obs(path="/z"), _obs(path="/a")], NOW)

    new_keys = [c.key for c in result.changes if c.category == ChangeCategory.NEW]
    assert new_keys == ["GET /a", "GET /z"]


def test_duplicate_observations_are_merged_once():
    previous = {"GET /seed": _record(path="/seed")}
    observations = [
        _obs(path="/api/orders", sources=["crawler"]),
        _obs(path="/api/orders", sources=["openapi"]),
    ]

    result = InventoryDiff().compare(previous, observations, NOW)

    new_changes = [c for c in result.changes if c.category == ChangeCategory.NEW]
    assert len(new_changes) == 1
    assert result.records["GET /api/orders"].sources == ["crawler", "openapi"]


# --- 9. kayıt güncelleme kuralları -------------------------------------------
def test_sources_are_merged_sorted_and_unique():
    previous = {KEY: _record(sources=["openapi", "crawler"])}
    observation = _obs(sources=["crawler", "js"])

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert result.records[KEY].sources == ["crawler", "js", "openapi"]


def test_first_seen_last_results_and_last_tested_are_preserved():
    first_seen = NOW - timedelta(days=90)
    previous = {KEY: _record(first_seen=first_seen, last_tested_days=2)}

    result = InventoryDiff().compare(previous, [_obs()], NOW)

    record = result.records[KEY]
    assert record.first_seen == first_seen
    assert record.last_tested == NOW - timedelta(days=2)
    assert record.last_results == {"idor": "CONFIRMED"}
    assert record.last_seen == NOW


def test_previous_records_are_not_mutated():
    previous = {KEY: _record(sources=["openapi"], last_seen=NOW - timedelta(days=5))}

    InventoryDiff().compare(previous, [_obs(sources=["js"])], NOW)

    assert previous[KEY].sources == ["openapi"]
    assert previous[KEY].last_seen == NOW - timedelta(days=5)


def test_observation_without_role_keeps_previous_auth_value():
    previous = {KEY: _record(auth_profile={"admin": 200, "anon": 401})}
    observation = _obs(auth_profile={"admin": 200})

    result = InventoryDiff().compare(previous, [observation], NOW)

    assert result.changes == []
    assert result.records[KEY].auth_profile == {"admin": 200, "anonymous": 401}


# --- summarize ---------------------------------------------------------------
def test_summarize_counts_categories():
    changes = [
        InventoryChange(category=ChangeCategory.NEW, key="a", detail=""),
        InventoryChange(category=ChangeCategory.NEW, key="b", detail=""),
        InventoryChange(category=ChangeCategory.MISSING, key="c", detail=""),
    ]

    assert summarize(changes) == {"missing": 1, "new": 2}
    assert summarize([]) == {}
