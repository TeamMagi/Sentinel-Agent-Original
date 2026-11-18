"""Durum-bilgili twin'ler (csrf, race, file upload, hpp, smuggling) — ağsız."""
import pytest

from pentestai.bench.kolb.stateful import TWINS, cases
from pentestai.oracle import base

TWIN_IDS = [t.name for t in TWINS]


@pytest.mark.parametrize("twin", TWINS, ids=TWIN_IDS)
async def test_vulnerable_confirmed_hardened_not(twin):
    vuln, hardened = await twin.run()
    assert vuln.verdict == base.CONFIRMED
    assert hardened.verdict != base.CONFIRMED


@pytest.mark.parametrize("twin", TWINS, ids=TWIN_IDS)
async def test_near_miss_not_confirmed(twin):
    assert (await twin.near_miss()).verdict != base.CONFIRMED


async def test_cases_unique_and_consistent_with_twins():
    cs = cases()
    names = [c.name for c in cs]
    assert len(names) == len(set(names)) == 3 * len(TWINS)
    assert {c.vuln_type for c in cs} == {t.vuln_type for t in TWINS}
    for c in cs:
        f = await c.run()
        assert (f.verdict == base.CONFIRMED) == (c.expected == "CONFIRMED"), c.name

