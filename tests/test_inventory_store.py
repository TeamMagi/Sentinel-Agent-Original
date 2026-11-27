"""Envanter SQLite deposu testleri — kalıcılık, upsert, hedef izolasyonu, koşum geçmişi."""
from datetime import UTC, datetime

from pentestai.inventory.models import EndpointObservation, InventoryRecord
from pentestai.inventory.store import InventoryStore

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
TARGET = "http://target.local"


def _record(
    key: str = "GET /api/users/{id}",
    *,
    method: str = "GET",
    path: str = "/api/users/{id}",
    auth_profile: dict[str, int] | None = None,
    response_shape: str | None = "abc123",
    last_results: dict[str, str] | None = None,
) -> InventoryRecord:
    return InventoryRecord(
        key=key,
        method=method,
        path_template=path,
        params=["id"],
        auth_profile=auth_profile or {"admin": 200, "anon": 401},
        response_shape=response_shape,
        response_fields=["id:int", "email:str"],
        sources=["openapi"],
        first_seen=NOW,
        last_seen=NOW,
        last_tested=NOW,
        last_results=last_results or {"idor": "CONFIRMED"},
    )


def test_save_then_reopen_returns_same_records(tmp_path):
    path = tmp_path / "inventory.sqlite"
    record = _record()

    with InventoryStore(path) as store:
        store.save(TARGET, [record])

    with InventoryStore(path) as store:
        loaded = store.load(TARGET)

    assert set(loaded) == {record.key}
    assert loaded[record.key] == record
    assert loaded[record.key].first_seen.tzinfo is not None
    assert loaded[record.key].last_seen.utcoffset() == UTC.utcoffset(None)


def test_upsert_updates_existing_record(tmp_path):
    path = tmp_path / "inventory.sqlite"
    with InventoryStore(path) as store:
        store.save(TARGET, [_record()])
        store.save(TARGET, [_record(auth_profile={"admin": 200, "anon": 200})])
        loaded = store.load(TARGET)

    assert len(loaded) == 1
    assert loaded["GET /api/users/{id}"].auth_profile == {"admin": 200, "anon": 200}


def test_targets_are_isolated(tmp_path):
    path = tmp_path / "inventory.sqlite"
    first = _record()
    second = _record(key="POST /api/orders", method="POST", path="/api/orders")

    with InventoryStore(path) as store:
        store.save(TARGET, [first])
        store.save("http://other.local", [second])
        first_loaded = store.load(TARGET)
        second_loaded = store.load("http://other.local")

    assert set(first_loaded) == {first.key}
    assert set(second_loaded) == {second.key}


def test_record_run_and_last_run(tmp_path):
    path = tmp_path / "inventory.sqlite"
    started = datetime(2026, 5, 1, 12, 30, tzinfo=UTC)

    with InventoryStore(path) as store:
        assert store.last_run(TARGET) is None
        run_id = store.record_run(TARGET, started, "delta", {"new": 2, "missing": 1})
        latest = store.last_run(TARGET)

    assert run_id > 0
    assert latest is not None
    assert latest["id"] == run_id
    assert latest["mode"] == "delta"
    assert latest["summary"] == {"new": 2, "missing": 1}
    assert latest["started_at"] == started


def test_trailing_slash_is_normalized(tmp_path):
    path = tmp_path / "inventory.sqlite"
    record = _record()

    with InventoryStore(path) as store:
        store.save("http://target.local/", [record])
        loaded = store.load("http://target.local")
        store.record_run("http://target.local/", NOW, "full", {"new": 1})
        latest = store.last_run("http://target.local")

    assert set(loaded) == {record.key}
    assert latest is not None
    assert latest["target"] == "http://target.local"


def test_from_observation_round_trip(tmp_path):
    observation = EndpointObservation(
        method="get",
        path_template="/api/orders/{id}",
        params=["id"],
        sources=["har"],
        auth_profile={"user": 200},
        response_shape="deadbeefdeadbeef",
        response_fields=["id:int"],
    )
    record = InventoryRecord.from_observation(observation, NOW)
    assert record.key == "GET /api/orders/{id}"
    assert record.first_seen == NOW
    assert record.last_seen == NOW

    path = tmp_path / "nested" / "dir" / "inventory.sqlite"
    with InventoryStore(path) as store:
        store.save(TARGET, [record])
    with InventoryStore(path) as store:
        assert store.load(TARGET)[record.key] == record
