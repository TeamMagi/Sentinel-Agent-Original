"""Timing twin'leri (ağsız, sahte saat): vuln=CONFIRMED, hardened/near-miss≠CONFIRMED."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb import timing as mod
from pentestai.oracle.base import CONFIRMED


@pytest.mark.parametrize("twin", mod.TWINS, ids=lambda t: t.name)
async def test_vulnerable_confirmed(twin) -> None:
    assert (await twin._one(twin._vuln)).verdict == CONFIRMED


@pytest.mark.parametrize("twin", mod.TWINS, ids=lambda t: t.name)
async def test_hardened_not_confirmed(twin) -> None:
    assert (await twin._one(twin._hardened)).verdict != CONFIRMED


@pytest.mark.parametrize("twin", mod.TWINS, ids=lambda t: t.name)
async def test_near_miss_not_confirmed(twin) -> None:
    assert (await twin.near_miss()).verdict != CONFIRMED


def test_cases_unique_and_consistent() -> None:
    cs = mod.cases()
    names = [c.name for c in cs]
    assert len(names) == len(set(names)) == 3 * len(mod.TWINS)
    assert {c.name.split(":")[0] for c in cs} == {t.name for t in mod.TWINS}


@pytest.mark.parametrize("case", mod.cases(), ids=lambda c: c.name)
async def test_cases_match_expectation(case) -> None:
    f = await case.run()
    assert f.type == case.vuln_type
    assert (f.verdict == CONFIRMED) == (case.expected == "CONFIRMED")
