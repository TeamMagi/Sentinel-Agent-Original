"""OOB twin'leri (ssrf, xxe, rfi) — ağsız."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb.oob import TWINS, _OobTwin, cases
from pentestai.oracle.base import CONFIRMED


@pytest.mark.parametrize("twin", TWINS, ids=lambda t: t.name)
async def test_twin_verdicts(twin):
    assert (await twin._one(twin._vuln)).verdict == CONFIRMED
    assert (await twin._one(twin._hardened)).verdict != CONFIRMED
    assert (await twin._one(twin._near_miss)).verdict != CONFIRMED
    if isinstance(twin, _OobTwin):   # loopback twin'in token bağlama (wrong-token) vakası yok
        assert (await twin._one(twin._wrong_token)).verdict != CONFIRMED


async def test_cases_consistent_and_pass():
    cs = cases()
    names = [c.name for c in cs]
    # _OobTwin başına 4 vaka (wrong-token dahil), loopback twin başına 3.
    expected = sum(4 if isinstance(t, _OobTwin) else 3 for t in TWINS)
    assert len(names) == len(set(names)) == expected
    assert {c.vuln_type for c in cs} == {t.vuln_type for t in TWINS}
    for c in cs:
        f = await c.run()
        assert (f.verdict == CONFIRMED) == (c.expected == "CONFIRMED"), c.name
