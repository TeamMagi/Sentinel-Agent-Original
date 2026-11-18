"""Exposure twin'leri (exposure, info_leak, vulnerable_component, rate_limit, graphql_introspection) — ağsız."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb.exposure import TWINS, cases
from pentestai.oracle.base import CONFIRMED


@pytest.mark.parametrize("twin", TWINS, ids=lambda t: t.name)
async def test_twin_verdicts(twin):
    vuln = await twin._one(twin._vuln)
    hard = await twin._one(twin._hardened)
    near = await twin._one(twin._near_miss)
    assert vuln.verdict == CONFIRMED
    assert vuln.type == twin.vuln_type
    assert hard.verdict != CONFIRMED
    assert near.verdict != CONFIRMED


async def test_cases_consistent_and_pass():
    cs = cases()
    names = [c.name for c in cs]
    assert len(names) == len(set(names)) == 3 * len(TWINS)
    assert {c.vuln_type for c in cs} == {t.vuln_type for t in TWINS}
    for c in cs:
        f = await c.run()
        assert (f.verdict == CONFIRMED) == (c.expected == "CONFIRMED"), c.name
