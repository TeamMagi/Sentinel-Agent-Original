"""XSS twin'leri (stored_xss, dom_xss): vuln=CONFIRMED, hardened/near-miss CONFIRMED değil. Ağsız."""
import pytest

from pentestai.bench.kolb import xss
from pentestai.oracle.base import CONFIRMED


@pytest.mark.asyncio
@pytest.mark.parametrize("twin", xss.TWINS, ids=lambda t: t.name)
async def test_twin_verdicts(twin):
    vuln, hardened = await twin.run()
    near = await twin.near_miss()
    assert vuln.verdict == CONFIRMED
    assert hardened.verdict != CONFIRMED
    assert near.verdict != CONFIRMED


@pytest.mark.asyncio
async def test_cases_run_as_labeled():
    for c in xss.cases():
        f = await c.run()
        assert f.type == c.vuln_type
        assert (f.verdict == CONFIRMED) == (c.expected == "CONFIRMED"), c.name


def test_cases_unique_and_consistent_with_twins():
    names = [c.name for c in xss.cases()]
    assert len(names) == len(set(names)) == 3 * len(xss.TWINS)
    for t in xss.TWINS:
        for suffix in ("vulnerable", "hardened", "near-miss"):
            assert f"{t.name}:{suffix}" in names
    assert {c.vuln_type for c in xss.cases()} == {t.vuln_type for t in xss.TWINS}
