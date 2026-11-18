"""Injection twin'leri (nosqli, ssti) — ağsız."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb.injection import TWINS, cases
from pentestai.oracle.base import CONFIRMED


@pytest.mark.parametrize("twin", TWINS, ids=lambda t: t.name)
async def test_twin_verdicts(twin):
    vuln = await twin._one(twin._vuln)
    hard = await twin._one(twin._hardened)
    near = await twin._one(twin._near_miss)
    assert vuln.verdict == CONFIRMED
    assert hard.verdict != CONFIRMED
    assert near.verdict != CONFIRMED


async def test_xss_near_misses_not_confirmed():
    from pentestai.bench.kolb.injection import ReflectedXssTwin
    t = ReflectedXssTwin()
    for h in [t._near_miss, *t.extra_near_misses().values()]:
        assert (await t._one(h)).verdict != CONFIRMED


async def test_cases_consistent_and_pass():
    cs = cases()
    names = [c.name for c in cs]
    # her twin 3 vaka; ReflectedXssTwin +2 ek near-miss (text/plain, tag-strip)
    assert len(names) == len(set(names)) == 3 * len(TWINS) + 2
    assert {"xss-reflected-param:vulnerable", "xss-reflected-param:hardened",
            "xss-reflected-param:near-miss", "xss-reflected-param:near-miss-plain",
            "xss-reflected-param:near-miss-strip"} <= set(names)
    assert {c.vuln_type for c in cs} == {t.vuln_type for t in TWINS}
    for c in cs:
        f = await c.run()
        assert (f.verdict == CONFIRMED) == (c.expected == "CONFIRMED"), c.name
