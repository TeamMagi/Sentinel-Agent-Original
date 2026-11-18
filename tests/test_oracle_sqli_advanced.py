"""SQLi gelişmiş oracle yolları: boolean-blind, UNION, second-order — kesin verdict'ler (ağsız)."""
from __future__ import annotations

import httpx
import pytest

from pentestai.bench.kolb import sqli_advanced as sa
from pentestai.oracle.base import CONFIRMED, INCONCLUSIVE, REJECTED

bool_t, union_t, so_t = sa.SqliBooleanBlindTwin(), sa.SqliUnionTwin(), sa.SqliSecondOrderTwin()


async def test_boolean_confirmed() -> None:
    f = await bool_t._one(bool_t._vuln)
    assert f.type == "sqli" and f.verdict == CONFIRMED and f.confidence == "high"
    assert f.evidence.negative_control and f.evidence.baseline_stable
    assert f.parameter.endswith("(boolean-blind)")


async def test_boolean_rejected_when_constant_page() -> None:
    assert (await bool_t._one(bool_t._near_miss)).verdict == REJECTED


async def test_boolean_inconclusive_when_both_payloads_differ() -> None:
    assert (await bool_t._one(bool_t._near_miss_invalid)).verdict == INCONCLUSIVE
    assert (await bool_t._one(bool_t._hardened)).verdict == INCONCLUSIVE


async def test_boolean_inconclusive_when_baseline_unstable() -> None:
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=[{"id": 1}])
        return httpx.Response(200, json=[])     # ikinci baseline farklı → kararsız

    assert (await bool_t._one(flaky)).verdict == INCONCLUSIVE


async def test_union_confirmed_returns_own_marker() -> None:
    f = await union_t._one(union_t._vuln)
    assert f.verdict == CONFIRMED and f.parameter.endswith("(union)")
    assert f.evidence.leaked_markers and f.evidence.leaked_markers[0].startswith("sxu")


async def test_union_rejected_when_marker_only_echoed() -> None:
    f = await union_t._one(union_t._near_miss)
    assert f.verdict == REJECTED
    assert f.evidence.negative_control is False


async def test_union_rejected_when_no_marker() -> None:
    assert (await union_t._one(union_t._hardened)).verdict == REJECTED


async def test_union_inconclusive_when_baseline_errors() -> None:
    f = await union_t._one(lambda r: httpx.Response(500, text="boom"))
    assert f.verdict == INCONCLUSIVE


async def test_second_order_confirmed_and_state_restored() -> None:
    f = await so_t._one(so_t._vuln)
    assert f.type == "sqli" and f.verdict == CONFIRMED and f.parameter.endswith("(second-order)")
    assert f.evidence.restored is True and f.evidence.negative_control


async def test_second_order_error_based_confirmed() -> None:
    # Yalnız tek tırnakta patlayan (UNION desteklemeyen) okuma: hata imzası ikinci aşamada gelir.
    app = so_t._app("vulnerable")

    def handler(request: httpx.Request) -> httpx.Response:
        return app(request)

    f = await so_t._one(lambda: handler)
    assert f.verdict == CONFIRMED and f.evidence.leaked_markers


@pytest.mark.parametrize("make", [so_t._near_miss,
                                  lambda: so_t._app("sanitize"),
                                  so_t._hardened], ids=["echo", "sanitize", "hardened"])
async def test_second_order_rejected_variants(make) -> None:
    assert (await so_t._one(make)).verdict == REJECTED


async def test_second_order_inconclusive_when_read_always_errors() -> None:
    assert (await so_t._one(lambda: so_t._app("persistent-error"))).verdict == INCONCLUSIVE


async def test_second_order_write_error_is_not_second_order() -> None:
    # Yazma cevabı da SQL hatası veriyor → birinci-derece; ikinci-el CONFIRMED verilmez.
    state = {"name": "anon"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            if "'" in request.content.decode():
                return httpx.Response(500, text="sqlite3.OperationalError: near \"'\"")
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(500, text="sqlite3.OperationalError: near \"'\"") \
            if state["name"] == "bad" else httpx.Response(200, json={"g": "hi"})

    f = await so_t._one(lambda: handler)
    assert f.verdict != CONFIRMED


def test_test_param_signature_unchanged() -> None:
    import inspect

    from pentestai.oracle import InjectionOracle
    assert list(inspect.signature(InjectionOracle.test_param).parameters) == [
        "self", "endpoint", "session", "param", "location", "finding_id"]
