"""response_inspect twin'leri (open_redirect, cors, clickjacking) — ağsız."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb import response_inspect as mod
from pentestai.oracle.base import CONFIRMED


@pytest.mark.parametrize("twin", mod.TWINS, ids=lambda t: t.name)
async def test_twin_verdicts(twin):
    vuln, hardened = await twin.run()
    assert vuln.verdict == CONFIRMED
    assert hardened.verdict != CONFIRMED
    assert (await twin.near_miss()).verdict != CONFIRMED


def test_cases_unique_and_consistent():
    cs = mod.cases()
    names = [c.name for c in cs]
    assert len(names) == len(set(names)) == 3 * len(mod.TWINS)
    assert {c.name.split(":")[0] for c in cs} == {t.name for t in mod.TWINS}
    assert {c.vuln_type for c in cs} == {t.vuln_type for t in mod.TWINS}


@pytest.mark.parametrize("case", mod.cases(), ids=lambda c: c.name)
async def test_cases_run(case):
    f = await case.run()
    assert (f.verdict == CONFIRMED) == (case.expected == "CONFIRMED")
