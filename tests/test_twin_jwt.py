"""JWT twin'leri (ağsız): vulnerable=CONFIRMED, hardened/near-miss CONFIRMED değil."""
import pytest

from pentestai.bench.kolb import jwt as kolb_jwt
from pentestai.oracle import CONFIRMED

TWINS = kolb_jwt.TWINS


@pytest.mark.parametrize("twin", TWINS, ids=lambda t: t.name)
async def test_vulnerable_confirmed(twin):
    assert (await twin._one(twin._vuln)).verdict == CONFIRMED


@pytest.mark.parametrize("twin", TWINS, ids=lambda t: t.name)
async def test_hardened_not_confirmed(twin):
    assert (await twin._one(twin._hardened)).verdict != CONFIRMED


@pytest.mark.parametrize("twin", TWINS, ids=lambda t: t.name)
async def test_near_miss_not_confirmed(twin):
    assert (await twin._one(twin._near_miss)).verdict != CONFIRMED


def test_cases_unique_and_consistent():
    cs = kolb_jwt.cases()
    names = [c.name for c in cs]
    assert len(names) == len(set(names)) == 3 * len(TWINS)
    assert {c.name.split(":")[0] for c in cs} == {t.name for t in TWINS}
    assert {c.vuln_type for c in cs} == {t.vuln_type for t in TWINS}


@pytest.mark.parametrize("case", kolb_jwt.cases(), ids=lambda c: c.name)
async def test_cases_run_match_expectation(case):
    f = await case.run()
    assert (f.verdict == CONFIRMED) == (case.expected == "CONFIRMED")
